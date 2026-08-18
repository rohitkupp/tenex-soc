"""Triage — docs/01's `triage` stage contract, made real:

* Precondition: incidents exist (`correlate` already ran).
* Postcondition: `triage_verdicts` for top-N, citations verified.

Wires both LLM paths `app.agent.orchestrator` exposes, per docs/v2_migration change 14 ("two LLM
paths, explicitly separated — do not run one where the other belongs"):

* **Path B** — `triage_top_incidents_for_analysis`: four-stage Analyst -> verifier -> Judge ->
  verifier -> Presenter flow per incident, top `MAX_TRIAGE_INCIDENTS` by `fused_score`
  (`app.core.config.Settings.max_triage_incidents`, enforced inside that function's own query —
  this stage does not re-implement the cap, only relies on it). Recurrences inherit their parent's
  verdict at no API cost (also inside that function).
* **Path A** — `narrate_analysis`: one call, once per analysis, over the same deterministic
  overview/incident-list/timeline-phase inputs `POST /api/analyses/{id}/narrate` builds
  (`app.api.analyses._compute_log_overview`/`_narrator_overview_payload`,
  `app.api.incident_detail.analysis_timeline_phases` — reused directly rather than
  reimplemented, so the pipeline's own narration call is built from the exact same deterministic
  inputs a manual `/narrate` call would see). Runs regardless of whether anything was flagged
  (change 9/14: the executive summary is produced on every upload, not only a flagged one).

Both paths' cost lands in `analyses.llm_cost_usd`: Path B's `_accumulate_analysis_cost` (inside
`triage_incident`) already does this per verdict; this stage adds Path A's own single narration
cost on top, the same atomic `x = x + delta` pattern.

`needs_attention` (the fourth SSE counter) is computed here, once, from the same predicate
`app.api.incident_detail.list_incidents` already uses per incident — "verdict is None, or the
agent asked for review, or its citations failed verification" — over every incident in the
analysis, not only the triaged top-N (an incident that never got triaged at all still needs a
human to look at it).

## Test seam

`handle` (the worker entrypoint) always defaults to a real `LiveCaller` — `docs/v2_migration`
change 12 removed the demo-mode/no-key fallback, so a missing `ANTHROPIC_API_KEY` is a permanent
configuration error, not a mode to degrade into. `make_handler(caller=...)` is the injection point tests use to hand in a recorded/scripted
`LLMCaller` instead — CI never needs a live key.

## Non-retryable Anthropic failures must not spend the full backoff ladder

Observed in production: a triage stage that had exhausted its credit balance dead-lettered
"after 4 attempt(s)" — attempt 0 plus all three backoff retries (`app.pipeline.base_worker`) —
with cost climbing in even steps across every attempt, because `_run_triage` re-ran the *entire*
four-stage Analyst/verifier/Judge/verifier/Presenter chain (plus Path A's narration call) on each
retry. `anthropic.BadRequestError` (400 `invalid_request_error`) is not
`app.pipeline.errors.PermanentStageError`, so `base_worker` treated it exactly like a dropped DB
connection: retry with backoff, three more times, at full LLM spend each time. A 400 from a bad
request (or an exhausted credit balance, or an invalid/expired key, or a model ID this account
cannot access) cannot succeed on retry — the request is identical every time.

`_permanent_stage_error_for` below classifies the four Anthropic exception classes that are
genuinely non-retryable (see its own docstring for the exact list and why) and `_run_triage`
re-raises those as `PermanentStageError` so `base_worker` dead-letters on the first attempt
instead of the fourth. Every other failure — including the other Anthropic exception classes
(`RateLimitError`, `InternalServerError`, `OverloadedError`, `APIConnectionError`/
`APITimeoutError`) and anything unrelated to the LLM call (a DB hiccup, a bug) — is left alone
and keeps the existing retry-with-backoff policy. The error is never swallowed either way: a
reclassified failure still carries the original exception's message (via `PermanentStageError`'s
own text) into the `dead_letters` row and `analyses.error`, exactly as an unclassified failure's
message does today — only the attempt count changes.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Final

import anthropic
import redis.asyncio as redis
from sqlalchemy import func, select, update

from app.agent.client import LiveCaller, LLMCaller
from app.agent.context import log_citation_id
from app.agent.orchestrator import (
    narrate_analysis,
    narrative_columns,
    summarize_event_windows,
    triage_top_incidents_for_analysis,
)
from app.api.analyses import (
    _compute_domain_semantic_findings,
    _compute_log_overview,
    _compute_notable_destinations,
    _narrator_overview_payload,
)
from app.api.events import _window_aggregates
from app.api.incident_detail import analysis_timeline_phases
from app.core.config import get_settings
from app.core.db import get_engine, get_session_factory
from app.core.logging import get_logger
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.event import Event
from app.models.incident import Incident
from app.models.triage_verdict import TriageVerdict
from app.pipeline import state
from app.pipeline.contracts import NEXT_QUEUE, STAGE_PROGRESS, public_counters
from app.pipeline.errors import PermanentStageError
from app.pipeline.messages import StageMessage
from app.pipeline.progress import publish_progress
from app.pipeline.redis_client import get_redis

log = get_logger(__name__)

TriageHandler = Callable[[StageMessage], Awaitable[list[tuple[str, StageMessage]]]]

# Verified against the installed SDK's status-code -> exception-class mapping
# (`anthropic.Anthropic._make_status_error`, anthropic==0.122.0 — that mapping has drifted across
# SDK releases, so this was read from the vendored source in the container, not recalled from
# memory) and the claude-api skill's error-code reference. Each of these four is a permanent,
# request-shape/credential/model-identity failure: retrying the byte-identical request cannot
# change a still-exhausted credit balance, a still-invalid API key, or a model ID the account
# still cannot access.
_PERMANENT_ANTHROPIC_ERRORS: Final[tuple[type[anthropic.APIStatusError], ...]] = (
    anthropic.BadRequestError,  # 400 invalid_request_error
    anthropic.AuthenticationError,  # 401 authentication_error
    anthropic.PermissionDeniedError,  # 403 permission_error
    anthropic.NotFoundError,  # 404 not_found_error -- model ID not found/not accessible
)


def _permanent_stage_error_for(exc: Exception) -> PermanentStageError | None:
    """`None` for everything retryable (`anthropic.RateLimitError` — 429; `anthropic.
    InternalServerError` — the SDK's own catch-all for every 5xx it does not special-case,
    which per `_make_status_error` covers 500/502/503 alike, not just 500; `anthropic.
    OverloadedError` — 529; `anthropic.APIConnectionError`/`APITimeoutError` — network/timeout;
    and any exception that isn't one of the four classes named on `_PERMANENT_ANTHROPIC_ERRORS`
    at all, LLM-related or not) — the caller's bare `raise` then preserves `app.pipeline.
    base_worker`'s existing retry-with-backoff policy unchanged. See this module's own docstring,
    "Non-retryable Anthropic failures must not spend the full backoff ladder", for why the four
    classes below are the exception."""
    if isinstance(exc, _PERMANENT_ANTHROPIC_ERRORS):
        return PermanentStageError(
            f"triage stage hit a non-retryable Anthropic API error ({type(exc).__name__}, "
            f"HTTP {exc.status_code}, type={exc.type}): {exc}"
        )
    return None


def _needs_attention(
    incidents: list[Incident], verdict_by_incident: dict[uuid.UUID, TriageVerdict]
) -> int:
    """Mirrors `app.api.incident_detail.list_incidents`'s own per-incident predicate exactly, so
    the queue's filter/badge and this counter can never silently drift apart."""
    n = 0
    for incident in incidents:
        verdict = verdict_by_incident.get(incident.id)
        if (
            verdict is None
            or verdict.disposition == "needs_review"
            or verdict.citation_valid is False
        ):
            n += 1
    return n


def _publish_triage_progress(message: StageMessage, *, progress: float, text: str) -> None:
    """Push one SSE progress frame from inside the (synchronous) triage run.

    `publish_progress` is async and this is called from a worker thread, so it needs its own
    loop. Failures are swallowed: a dropped progress frame must never cost a triage run that has
    already spent real money on LLM calls.
    """
    try:
        with get_engine().begin() as conn:
            counters = state.get_counters(
                conn, analysis_id=message.analysis_id, tenant_id=message.tenant_id
            )
            state.mark_stage(
                conn,
                analysis_id=message.analysis_id,
                tenant_id=message.tenant_id,
                stage="triage",
                progress=progress,
            )

        # A *fresh* client, created inside the loop `asyncio.run` opens. `get_redis()` returns a
        # client bound to whichever loop first used it — the worker's — and reusing it here
        # raises "attached to a different loop" / "Event loop is closed", because this runs on a
        # worker thread with its own short-lived loop. Closed in `finally` so each progress frame
        # cleans up after itself rather than leaking a connection per incident.
        async def _send() -> None:
            # A genuinely new client, not `get_redis()` — that one is `lru_cache`d, so calling
            # it here would hand back the worker's own client and closing it below would tear
            # down the connection every other stage is using.
            client = redis.from_url(get_settings().redis_url, decode_responses=True)
            try:
                await publish_progress(
                    client,
                    analysis_id=message.analysis_id,
                    stage="triage",
                    progress=progress,
                    status="running",
                    message=text,
                    counters=public_counters(counters),
                )
            finally:
                await client.aclose()

        asyncio.run(_send())
    except Exception:
        log.warning("triage.progress_publish_failed", exc_info=True)


def _run_triage(message: StageMessage, *, caller: LLMCaller | None = None) -> dict[str, Any]:
    settings = get_settings()
    if caller is None and not settings.llm_enabled:
        raise PermanentStageError(
            "ANTHROPIC_API_KEY is not configured. Triage always makes real Claude API calls "
            "now (docs/v2_migration change 12 removed DEMO_MODE and the no-key fallback) — set "
            "ANTHROPIC_API_KEY before this analysis can reach the triage stage."
        )

    session = get_session_factory()()
    try:
        # Fractional progress *within* the triage stage. STAGE_PROGRESS is a completion ladder
        # — correlate lands at 0.75 and triage at 0.875 — so an incident-by-incident position is
        # interpolated between the two. The number is measured, not animated: it is the fraction
        # of incidents actually triaged, so a stalled run visibly stops advancing rather than
        # showing a bar that keeps moving while nothing happens.
        span_start = STAGE_PROGRESS["correlate"]
        span_end = STAGE_PROGRESS["triage"]

        def _report(done: int, total: int) -> None:
            fraction = (done / total) if total else 1.0
            _publish_triage_progress(
                message,
                progress=span_start + (span_end - span_start) * fraction,
                text=f"Triaging incidents — {done} of {total} complete",
            )

        verdicts = triage_top_incidents_for_analysis(
            session,
            message.tenant_id,
            message.analysis_id,
            caller=caller,
            on_progress=_report,
        )

        with tenant_scope(session, message.tenant_id):
            incident_rows = (
                session.execute(select(Incident).where(Incident.analysis_id == message.analysis_id))
                .scalars()
                .all()
            )
            verdict_by_incident: dict[uuid.UUID, TriageVerdict] = {}
            if incident_rows:
                verdict_rows = (
                    session.execute(
                        select(TriageVerdict)
                        .where(TriageVerdict.incident_id.in_([i.id for i in incident_rows]))
                        .order_by(TriageVerdict.incident_id, TriageVerdict.created_at.asc())
                    )
                    .scalars()
                    .all()
                )
                for v in verdict_rows:  # ascending -> last write per incident wins (newest)
                    verdict_by_incident[v.incident_id] = v

            analysis = session.execute(
                select(Analysis).where(Analysis.id == message.analysis_id)
            ).scalar_one_or_none()

        n_needs_attention = _needs_attention(incident_rows, verdict_by_incident)

        # ---- Path A: narrate_analysis, once per analysis, regardless of findings ----
        narration_cost = Decimal("0")
        narration_citation_valid = True
        if analysis is not None:
            incidents_payload = [
                {
                    "id": str(inc.id),
                    "title": inc.title,
                    "severity": inc.severity,
                    "fused_score": inc.fused_score,
                    "anomaly_confidence": inc.anomaly_confidence,
                    "disposition": (
                        verdict_by_incident[inc.id].disposition
                        if inc.id in verdict_by_incident
                        else None
                    ),
                }
                for inc in incident_rows
            ]
            phases, _total_phases, _truncated = analysis_timeline_phases(
                session, message.tenant_id, message.analysis_id
            )
            all_event_ids = {eid for phase in phases for eid in phase.event_ids}
            with tenant_scope(session, message.tenant_id):
                line_rows = (
                    session.execute(
                        select(Event.id, Event.raw_line_no).where(
                            Event.analysis_id == message.analysis_id,
                            Event.id.in_(all_event_ids),
                        )
                    ).all()
                    if all_event_ids
                    else []
                )
            line_by_event_id: dict[int, int] = dict(line_rows)
            timeline_payload = [
                {
                    "phase_index": i,
                    "tactic": phase.tactic,
                    "summary": phase.summary,
                    "log_ids": [
                        log_citation_id(line_by_event_id[eid])
                        for eid in phase.event_ids
                        if eid in line_by_event_id
                    ],
                }
                for i, phase in enumerate(phases)
            ]
            with tenant_scope(session, message.tenant_id):
                overview = _compute_log_overview(session, message.tenant_id, analysis)

            active_caller = caller or LiveCaller(
                api_key=settings.anthropic_api_key.get_secret_value()
            )
            narration = narrate_analysis(
                overview=_narrator_overview_payload(overview),
                incidents=incidents_payload,
                timeline_phases=timeline_payload,
                caller=active_caller,
                model=settings.anthropic_model,
            )
            narration_cost = narration.cost_usd
            narration_citation_valid = narration.citation_valid
            log.info(
                "triage.narration_complete",
                analysis_id=str(message.analysis_id),
                citation_valid=narration_citation_valid,
                cost_usd=str(narration_cost),
            )
            # ---- Timeline tab: windowed event summary, once per analysis ----
            # Produced here for the same reason as the narrative: the tab should render what the
            # run already paid for, not ask the analyst to buy it again on first visit. Windows
            # are cut deterministically in SQL; this call only writes prose over them.
            timeline_summary: dict[str, Any] | None = None
            try:
                windows = _window_aggregates(session, message.tenant_id, message.analysis_id)
                if windows:
                    tl = summarize_event_windows(
                        windows=windows, caller=active_caller, model=settings.anthropic_model
                    )
                    timeline_summary = {
                        "overview": tl.overview,
                        "windows": list(tl.windows),
                        "citation_valid": tl.citation_valid,
                        "invalid_citation_count": len(tl.invalid_citations),
                        "model": tl.model,
                        "generated_at": datetime.now(UTC).isoformat(),
                    }
                    narration_cost += tl.cost_usd
            except Exception:
                # A failed summary must not take down a run that has already triaged every
                # incident — the tab degrades to its "Summarise timeline" button.
                log.warning(
                    "triage.event_timeline_failed",
                    analysis_id=str(message.analysis_id),
                    exc_info=True,
                )

            # ---- change 8: semantic domain findings, once per analysis ----
            # This moved here from inside `GET /api/analyses/{id}/overview`, where it ran a live
            # LLM call on every request — seconds of latency and real tokens per page view.
            # Computed once, with the rest of this analysis's LLM work, and stored.
            semantic_findings = _compute_domain_semantic_findings(
                session,
                message.tenant_id,
                message.analysis_id,
                _compute_notable_destinations(session, message.tenant_id, message.analysis_id),
            )

            # Persist the prose, not just its price. This call has always run here; until the
            # `analyses.narrative` columns existed its output was discarded and the UI had to
            # offer a button that paid for it a second time.
            with tenant_scope(session, message.tenant_id):
                session.execute(
                    update(Analysis)
                    .where(Analysis.id == message.analysis_id)
                    .values(
                        llm_cost_usd=func.coalesce(Analysis.llm_cost_usd, 0) + narration_cost,
                        domain_semantic_findings=[
                            f.model_dump(mode="json") for f in semantic_findings
                        ],
                        domain_semantics_generated_at=datetime.now(UTC),
                        event_timeline_summary=timeline_summary,
                        **narrative_columns(narration),
                    )
                )
                session.commit()
    except Exception as exc:
        # Wraps both Path B (`triage_top_incidents_for_analysis`) and Path A (`narrate_analysis`)
        # -- either can raise straight out of `app.agent.client.LiveCaller.create` ->
        # `anthropic.Anthropic().messages.create`, and neither `app.agent.orchestrator` nor this
        # function's own body catches Anthropic exceptions anywhere upstream of here (verified:
        # orchestrator.py only catches `ToolError`/`ValidationError`, unrelated to the API call
        # itself), so this single point sees every one of them. See module docstring "Non-
        # retryable Anthropic failures must not spend the full backoff ladder".
        permanent = _permanent_stage_error_for(exc)
        if permanent is not None:
            raise permanent from exc
        raise
    finally:
        session.close()

    with get_engine().begin() as conn:
        state.mark_stage(
            conn,
            analysis_id=message.analysis_id,
            tenant_id=message.tenant_id,
            stage="triage",
            progress=STAGE_PROGRESS["triage"],
        )
        counters = state.increment_counter(
            conn,
            analysis_id=message.analysis_id,
            tenant_id=message.tenant_id,
            key="needs_attention",
            delta=n_needs_attention,
        )

    return {
        "n_triaged": len(verdicts),
        "n_incidents": len(incident_rows),
        "n_needs_attention": n_needs_attention,
        "narration_cost": narration_cost,
        "narration_citation_valid": narration_citation_valid,
        "max_triage_incidents": settings.max_triage_incidents,
        "counters": counters,
    }


def make_handler(*, caller: LLMCaller | None = None) -> TriageHandler:
    """`caller=None` (the worker entrypoint's default) means "use a real `LiveCaller`" — see
    `_run_triage`. Tests pass a scripted/fixture `LLMCaller` here instead."""

    async def handle(message: StageMessage) -> list[tuple[str, StageMessage]]:
        result = await asyncio.to_thread(_run_triage, message, caller=caller)

        await publish_progress(
            get_redis(),
            analysis_id=message.analysis_id,
            stage="triage",
            progress=STAGE_PROGRESS["triage"],
            status="running",
            message=(
                f"Triage complete: {result['n_triaged']}/{result['n_incidents']} incident(s) "
                f"investigated (cap {result['max_triage_incidents']}), "
                f"{result['n_needs_attention']} need analyst attention. Analysis narrative "
                f"generated (citations valid: {result['narration_citation_valid']}, "
                f"cost ${result['narration_cost']:.4f})."
            ),
            counters=public_counters(result["counters"]),
        )

        next_queue = NEXT_QUEUE["triage"]
        assert next_queue is not None
        now = datetime.now(UTC)
        return [
            (
                next_queue,
                message.model_copy(update={"stage": next_queue, "attempt": 0, "emitted_at": now}),
            )
        ]

    return handle


handle: TriageHandler = make_handler()
