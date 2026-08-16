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
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select, update

from app.agent.client import LiveCaller, LLMCaller
from app.agent.context import log_citation_id
from app.agent.orchestrator import narrate_analysis, triage_top_incidents_for_analysis
from app.api.analyses import _compute_log_overview, _narrator_overview_payload
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
        verdicts = triage_top_incidents_for_analysis(
            session, message.tenant_id, message.analysis_id, caller=caller
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
            if narration_cost:
                with tenant_scope(session, message.tenant_id):
                    session.execute(
                        update(Analysis)
                        .where(Analysis.id == message.analysis_id)
                        .values(
                            llm_cost_usd=func.coalesce(Analysis.llm_cost_usd, 0) + narration_cost
                        )
                    )
                    session.commit()
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
