"""GET /api/analyses, GET /api/analyses/{id}, DELETE /api/analyses/{id},
POST /api/analyses/{id}/retry — docs/09, as amended by docs/v2_migration change 27.

Every route requires an authenticated, tenant-scoped caller (docs/06); tenant scoping
itself is structural (`app.models.base`), not a filter a handler could forget.

`analyses` has no `created_at` column — docs/02-DATA-MODEL.md is matched exactly, see
`app.models.analysis`. "Newest first" is therefore ordered by the parent upload's
`created_at` (an upload and its analysis are created together, 1:1, in
`app.api.uploads`), with `analysis.id` as a tiebreaker for the keyset cursor.

`retry_analysis` is change 27's replacement for the deleted `POST /api/ops/dead-
letters/{id}/retry` (`app.api.ops`, removed along with the rest of `/ops` — "failures
surface on the analysis" instead of an ops console). Same republish mechanics as the
old route (find the dead-lettered `StageMessage` payload, republish it to its failing
queue with a fresh attempt budget, flip the analysis back to `running`), just addressed
by `analysis_id` — the id the analyst is already looking at — instead of a `dead_letter`
id from a console that no longer exists. `dead_letters` itself is unchanged and still
not tenant-scoped (see `app.models.dead_letter`'s docstring); this handler is safe
without a `tenant_id` filter on that table because it only ever looks up dead letters by
`analysis_id`, and the `analysis_id` itself was already resolved through a tenant-scoped
`Analysis` lookup above.
"""

from __future__ import annotations

import base64
import binascii
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, tuple_, update
from sqlalchemy.orm import Session
from starlette import status

from app.agent.client import LiveCaller
from app.agent.context import FIELD_TRUNCATE_LEN, log_citation_id
from app.agent.orchestrator import (
    MAX_SEMANTIC_DOMAINS_PER_CALL,
    assess_domain_semantics,
    narrate_analysis,
    narrative_columns,
)
from app.api.incident_detail import analysis_timeline_phases
from app.baseline.resolve import contact_counts_many, percentiles_for_many
from app.core.config import get_settings
from app.core.db import get_db, get_engine
from app.core.errors import ApiError
from app.core.logging import get_logger
from app.core.security import CurrentUser, require_user
from app.detection.evidence.constants import SIGNAL_BEACONING, SIGNAL_DGA
from app.graph.builder import REL_ACCESSED
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.dead_letter import DeadLetter
from app.models.entity import Entity
from app.models.entity_edge import EntityEdge
from app.models.event import Event
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.triage_verdict import TriageVerdict
from app.models.upload import Upload
from app.pipeline import state
from app.pipeline.messages import StageMessage
from app.privacy.redact import redact_text
from app.queue.publish import publish_stage_message
from app.queue.topology import declare_topology, get_connection, work_queue
from app.schemas.overview import (
    AnalysisNarrateResponse,
    AnalysisOverviewResponse,
    BaselineComparisonOut,
    DomainSemanticFinding,
    LogOverview,
    NotableDestination,
    NotableUser,
    PeriodicityOut,
    StoredNarrative,
)
from app.schemas.uploads import AnalysisListResponse, AnalysisOut, AnalysisRetryResponse

router = APIRouter()
log = get_logger(__name__)


def _not_found() -> ApiError:
    return ApiError(status_code=404, code="not_found", detail="Analysis not found.")


def _no_api_key() -> ApiError:
    # Mirrors `app.api.incidents._no_api_key` verbatim — same condition (`Settings.llm_enabled`),
    # same remediation. Kept as its own copy here rather than imported, matching this codebase's
    # established preference for a few duplicated lines over a cross-router import for something
    # this small (see e.g. `app.api.incident_detail._incident_scope_and_window`'s own docstring).
    return ApiError(
        status_code=503,
        code="anthropic_api_key_not_configured",
        detail=(
            "The Narrator requires ANTHROPIC_API_KEY to be configured. DEMO_MODE and the "
            "no-key fallback have been removed — set the key and retry."
        ),
    )


def _not_retryable(detail: str, *, status_code: int = 404) -> ApiError:
    return ApiError(status_code=status_code, code="not_retryable", detail=detail)


def _encode_cursor(created_at: datetime, analysis_id: uuid.UUID) -> str:
    raw = f"{created_at.isoformat()}|{analysis_id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        created_at_str, id_str = raw.split("|", 1)
        return datetime.fromisoformat(created_at_str), uuid.UUID(id_str)
    except (ValueError, binascii.Error) as exc:
        raise ApiError(status_code=400, code="invalid_cursor", detail="Invalid cursor.") from exc


@router.get("/analyses", response_model=AnalysisListResponse)
def list_analyses(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    cursor: str | None = None,
) -> AnalysisListResponse:
    with tenant_scope(db, current.tenant.id):
        stmt = (
            select(Analysis, Upload.created_at)
            .join(Upload, Analysis.upload_id == Upload.id)
            .order_by(Upload.created_at.desc(), Analysis.id.desc())
            .limit(limit + 1)
        )
        if cursor is not None:
            cursor_created_at, cursor_id = _decode_cursor(cursor)
            stmt = stmt.where(
                tuple_(Upload.created_at, Analysis.id) < (cursor_created_at, cursor_id)
            )
        rows = db.execute(stmt).all()

    has_more = len(rows) > limit
    page = rows[:limit]
    items = [AnalysisOut.model_validate(analysis) for analysis, _ in page]
    next_cursor = _encode_cursor(page[-1][1], page[-1][0].id) if has_more and page else None
    return AnalysisListResponse(items=items, next_cursor=next_cursor)


@router.get("/analyses/{analysis_id}", response_model=AnalysisOut)
def get_analysis(
    analysis_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> AnalysisOut:
    with tenant_scope(db, current.tenant.id):
        analysis = db.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        ).scalar_one_or_none()
    if analysis is None:
        raise _not_found()
    return AnalysisOut.model_validate(analysis)


@router.delete("/analyses/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_analysis(
    analysis_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> None:
    with tenant_scope(db, current.tenant.id):
        analysis = db.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        ).scalar_one_or_none()
        if analysis is None:
            raise _not_found()
        db.delete(analysis)


@router.post("/analyses/{analysis_id}/retry", response_model=AnalysisRetryResponse)
async def retry_analysis(
    analysis_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> AnalysisRetryResponse:
    with tenant_scope(db, current.tenant.id):
        analysis = db.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        ).scalar_one_or_none()
    if analysis is None:
        raise _not_found()
    if analysis.status != "failed":
        raise _not_retryable(
            f"analysis {analysis_id} is not failed (status={analysis.status!r}).",
            status_code=409,
        )

    # `dead_letters` carries no tenant_id (see module docstring) — scoped by
    # `analysis_id` alone, which is safe here because `analysis_id` was already
    # resolved through the tenant-scoped lookup above. `retried_at IS NULL` picks the
    # dead letter this failure hasn't already been retried from, in case an earlier
    # retry itself failed and dead-lettered again.
    dead_letter = db.execute(
        select(DeadLetter)
        .where(DeadLetter.analysis_id == analysis_id, DeadLetter.retried_at.is_(None))
        .order_by(DeadLetter.created_at.desc(), DeadLetter.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    if dead_letter is None:
        raise _not_retryable(f"no retryable dead letter found for analysis {analysis_id}.")

    try:
        message = StageMessage.model_validate(dead_letter.payload)
    except Exception as exc:
        raise _not_retryable(
            f"dead letter {dead_letter.id} has no retryable StageMessage payload: {exc}",
            status_code=400,
        ) from exc

    fresh_message = message.model_copy(update={"attempt": 0, "emitted_at": datetime.now(UTC)})
    target_queue = dead_letter.stage  # the logical queue name at time of failure

    connection = await get_connection()
    try:
        channel = await connection.channel()
        await declare_topology(channel)
        await publish_stage_message(channel, target_queue, fresh_message)
    finally:
        await connection.close()

    retried_at = datetime.now(UTC)
    dead_letter.retried_at = retried_at
    db.add(dead_letter)

    with get_engine().begin() as conn:
        state.reopen_for_retry(conn, analysis_id=analysis_id, tenant_id=current.tenant.id)

    log.info(
        "analyses.retried",
        analysis_id=str(analysis_id),
        dead_letter_id=dead_letter.id,
        queue=work_queue(target_queue),
    )

    return AnalysisRetryResponse(
        analysis_id=analysis_id, republished_to=work_queue(target_queue), retried_at=retried_at
    )


# =============================================================================================
# GET /analyses/{id}/overview + POST /analyses/{id}/narrate — docs/v2_migration changes 8, 9,
# 10, 14 Path A. See this module's own docstring split at the top... actually see
# `app.schemas.overview`'s module docstring for why these are two routes, not one.
# =============================================================================================

# change 9: a user-window counts as "anomalous" for the notable-users view at this confidence
# bar. `signals.confidence` is isotonic-calibrated on 0.0-1.0 (docs/04; see e.g.
# `app.detection.ml.detect.SIGNAL_CONFIDENCE_THRESHOLD`, which gates a signal firing at all —
# never 0-100 the way `incidents.anomaly_confidence` is, change 3's own rescaled field). 0.7 is
# this view's own bar for "worth calling out on the ten-second overview", not a threshold reused
# from elsewhere — there is no existing "notable window" concept in this codebase to match.
ANOMALOUS_WINDOW_CONFIDENCE_THRESHOLD = 0.7

# How many notable users/destinations change 9's overview surfaces, each. Unranked and uncapped
# would mean every entity a single low-confidence signal ever touched shows up on "what happened
# in ten seconds" — the opposite of the point (docs/09: "an analyst should understand the file in
# ten seconds"). Ranked by top anomaly score (falling back to raw volume when no signal exists)
# before the cut, so it drops the least notable entities first, never an arbitrary slice.
NOTABLE_ENTITIES_LIMIT = 20

# change 8's own selection rule: "a semantic pass over destinations flagged rare or first-seen."
# `NotableDestination.first_observed` (org-wide zero prior contact) is the unambiguous case; this
# extends "rare" to "contacted so few times org-wide it is practically first-seen" without
# inventing a second rarity concept — reads the same `app.baseline.resolve.contact_counts` source
# `_compute_notable_destinations.first_observed` already reads, just at a threshold above zero.
RARE_ORG_CONTACT_THRESHOLD = 2
# How many of a candidate domain's own log lines travel into the semantic-pass evidence bundle as
# citable ids — CLAUDE.md rule 1 applied to one domain's own event count, not just the whole file.
CANDIDATE_LOG_IDS_LIMIT = 10
# How many events immediately preceding a user's first visit to a candidate domain are surfaced as
# "preceding context" — change 8's own worked example ("github-update-security.com appearing
# immediately after a GitHub credential event"). Small on purpose: this is the one preceding event
# (or handful of them) that made the visit contextually notable, not a session replay.
PRECEDING_CONTEXT_EVENTS = 3


def _compute_log_overview(db: Session, tenant_id: uuid.UUID, analysis: Analysis) -> LogOverview:
    """change 9: "computed in SQL, on every upload, whether or not anything is flagged. Do not
    ask a model to count 83,241 rows." One aggregate query over `events`, no Python-side loop."""
    with tenant_scope(db, tenant_id):
        row = db.execute(
            select(
                func.count(Event.id),
                func.count(func.distinct(Event.principal)),
                func.count(func.distinct(Event.src_ip)),
                func.count(func.distinct(Event.domain)),
                func.count().filter(Event.action == "allowed"),
                func.count().filter(Event.action == "blocked"),
                func.coalesce(func.sum(Event.bytes_out), 0),
                func.coalesce(func.sum(Event.bytes_in), 0),
                func.min(Event.ts),
                func.max(Event.ts),
            ).where(Event.analysis_id == analysis.id)
        ).one()
    (
        events,
        users,
        src_ips,
        unique_domains,
        allowed,
        blocked,
        bytes_out,
        bytes_in,
        period_start,
        period_end,
    ) = row
    return LogOverview(
        period_start=period_start,
        period_end=period_end,
        events=events,
        users=users,
        src_ips=src_ips,
        unique_domains=unique_domains,
        allowed=allowed,
        blocked=blocked,
        bytes_out=int(bytes_out),
        bytes_in=int(bytes_in),
        parse_failure_rate=analysis.parse_failure_rate,
    )


def _rank_key(score: float | None, volume: int) -> tuple[float, int]:
    """Sort descending by top anomaly score, entities with no signal at all ranked below every
    scored entity (not at 0 — a real zero-confidence signal should still outrank "never flagged"),
    ties broken by raw volume. Returns a key `sorted(..., key=...)` can use directly (ascending
    sort over negated values == descending sort over the originals)."""
    return (-(score if score is not None else -1.0), -volume)


def _compute_notable_users(
    db: Session, tenant_id: uuid.UUID, analysis_id: uuid.UUID
) -> list[NotableUser]:
    """change 9: "notable users (anomalous windows, volume vs. baseline, first-seen domain
    count, top anomaly score)." Deterministic composition over `entities`, `signals`,
    `entity_edges`, and the baseline store (`app.baseline.resolve`) — no LLM involvement."""
    with tenant_scope(db, tenant_id):
        entities = (
            db.execute(select(Entity).where(Entity.analysis_id == analysis_id)).scalars().all()
        )
        edges = (
            db.execute(
                select(EntityEdge).where(
                    EntityEdge.analysis_id == analysis_id, EntityEdge.relation == REL_ACCESSED
                )
            )
            .scalars()
            .all()
        )
        top_score_rows = db.execute(
            select(Signal.entity_value, func.max(Signal.confidence))
            .where(Signal.analysis_id == analysis_id, Signal.entity_type == "user")
            .group_by(Signal.entity_value)
        ).all()
        anomalous_window_rows = db.execute(
            select(Signal.entity_value, func.count(func.distinct(Signal.window_start)))
            .where(
                Signal.analysis_id == analysis_id,
                Signal.entity_type == "user",
                Signal.confidence >= ANOMALOUS_WINDOW_CONFIDENCE_THRESHOLD,
                Signal.window_start.is_not(None),
            )
            .group_by(Signal.entity_value)
        ).all()

    users = [e for e in entities if e.type == "user"]
    if not users:
        return []

    # Plain loops, not `dict(rows)`/a dict comprehension: a SQLAlchemy `Row` isn't statically a
    # `tuple` for either's type-checking (ruff's C416 "use dict()" and mypy disagree with each
    # other here — `dict(rows)` satisfies the former and fails the latter), and a loop sidesteps
    # both cleanly, with no lint suppression needed.
    top_score_by_user: dict[str, float] = {}
    for value, score in top_score_rows:
        top_score_by_user[value] = score
    anomalous_windows_by_user: dict[str, int] = {}
    for value, n in anomalous_window_rows:
        anomalous_windows_by_user[value] = n

    by_id = {e.id: e for e in entities}
    domains_by_user: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        src, dst = by_id.get(edge.src_entity_id), by_id.get(edge.dst_entity_id)
        if src is not None and dst is not None and src.type == "user" and dst.type == "domain":
            domains_by_user[src.value].add(dst.value)

    ranked = sorted(
        users,
        key=lambda u: _rank_key(top_score_by_user.get(u.value), u.event_count),
    )[:NOTABLE_ENTITIES_LIMIT]

    # Two batched lookups for the whole ranked page, not two per user. The loop below was
    # previously one `percentile_for` *and* one `contact_counts` per (user, domain) pair —
    # ~600 sequential round trips for a 20-user page, which is what made this endpoint take
    # 14s against a managed Postgres in another region and blew the frontend's server-render
    # budget. Same values, same semantics (see `percentiles_for_many`), two queries.
    baselines = percentiles_for_many(
        db,
        tenant_id,
        "user",
        "n_events",
        {user.value: float(user.event_count) for user in ranked},
    )
    contacts = contact_counts_many(
        db,
        tenant_id,
        ((user.value, domain) for user in ranked for domain in domains_by_user.get(user.value, ())),
    )

    notable: list[NotableUser] = []
    for user in ranked:
        baseline = baselines[user.value]
        first_seen_count = sum(
            1
            for domain in domains_by_user.get(user.value, ())
            if contacts[(user.value, domain)].user.is_first_contact
        )
        notable.append(
            NotableUser(
                value=user.value,
                anomalous_windows=anomalous_windows_by_user.get(user.value, 0),
                volume_vs_baseline=BaselineComparisonOut(
                    metric=baseline.metric,
                    value=baseline.value,
                    baseline_status=baseline.baseline_status,
                    n_windows=baseline.n_windows,
                    percentile=baseline.percentile,
                    p50=baseline.p50,
                    p95=baseline.p95,
                    p99=baseline.p99,
                ),
                first_seen_domain_count=first_seen_count,
                top_anomaly_score=top_score_by_user.get(user.value),
            )
        )
    return notable


def _compute_notable_destinations(
    db: Session, tenant_id: uuid.UUID, analysis_id: uuid.UUID
) -> list[NotableDestination]:
    """change 9: "notable destinations (first-observed flag, distinct users, DGA score,
    connection count, periodicity)." `dga_score`/`periodicity` are read straight off the
    `signal.dga`/`signal.beaconing` rows already produced for this domain — this view never
    recomputes an extractor, it only reads what was already calibrated and persisted."""
    with tenant_scope(db, tenant_id):
        entities = (
            db.execute(select(Entity).where(Entity.analysis_id == analysis_id)).scalars().all()
        )
        edges = (
            db.execute(
                select(EntityEdge).where(
                    EntityEdge.analysis_id == analysis_id, EntityEdge.relation == REL_ACCESSED
                )
            )
            .scalars()
            .all()
        )
        top_score_rows = db.execute(
            select(Signal.entity_value, func.max(Signal.confidence))
            .where(Signal.analysis_id == analysis_id, Signal.entity_type == "domain")
            .group_by(Signal.entity_value)
        ).all()
        dga_rows = db.execute(
            select(Signal.entity_value, Signal.explanation).where(
                Signal.analysis_id == analysis_id,
                Signal.entity_type == "domain",
                Signal.detector_key == SIGNAL_DGA,
            )
        ).all()
        beacon_rows = db.execute(
            select(Signal.entity_value, Signal.explanation).where(
                Signal.analysis_id == analysis_id,
                Signal.entity_type == "domain",
                Signal.detector_key == SIGNAL_BEACONING,
            )
        ).all()

    domains = [e for e in entities if e.type == "domain"]
    if not domains:
        return []

    top_score_by_domain: dict[str, float] = {}
    for value, score in top_score_rows:
        top_score_by_domain[value] = score

    # `signal.dga`/`signal.beaconing` explanations are detector-authored JSONB
    # (`app.detection.evidence.{dga,beaconing}`'s own payload shape) — read defensively, same
    # "tolerant on purpose" policy `app.api.incident_detail._technique_ids` documents for the
    # same reason (one malformed row should cost that row, not the whole overview).
    dga_score_by_domain: dict[str, float] = {}
    for value, explanation in dga_rows:
        score = explanation.get("score") if isinstance(explanation, dict) else None
        if isinstance(score, int | float):
            dga_score_by_domain[value] = float(score)

    periodicity_by_domain: dict[str, PeriodicityOut] = {}
    for value, explanation in beacon_rows:
        if not isinstance(explanation, dict):
            continue
        period = explanation.get("dominant_period_s")
        strength = explanation.get("fft_peak_power_ratio")
        if isinstance(period, int | float) and isinstance(strength, int | float):
            periodicity_by_domain[value] = PeriodicityOut(
                dominant_period_s=float(period), spectral_strength=float(strength)
            )

    by_id = {e.id: e for e in entities}
    users_by_domain: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        src, dst = by_id.get(edge.src_entity_id), by_id.get(edge.dst_entity_id)
        if src is not None and dst is not None and src.type == "user" and dst.type == "domain":
            users_by_domain[dst.value].add(src.value)

    ranked = sorted(
        domains,
        key=lambda d: _rank_key(top_score_by_domain.get(d.value), d.event_count),
    )[:NOTABLE_ENTITIES_LIMIT]

    # Only `.org` is used below — `contact_counts` also resolves user/department scope, neither
    # meaningful for a domain-centric (not user-centric) view, so an empty `user` is passed
    # deliberately rather than picking one of this domain's visitors arbitrarily. Batched for
    # the same reason as `_compute_notable_users` above: one query, not one per domain.
    org_contacts = contact_counts_many(db, tenant_id, (("", d.value) for d in ranked))

    notable: list[NotableDestination] = []
    for domain in ranked:
        org_contact = org_contacts[("", domain.value)].org
        notable.append(
            NotableDestination(
                value=domain.value,
                first_observed=org_contact.is_first_contact,
                distinct_users=len(users_by_domain.get(domain.value, ())),
                dga_score=dga_score_by_domain.get(domain.value),
                connection_count=domain.event_count,
                periodicity=periodicity_by_domain.get(domain.value),
            )
        )
    return notable


# =============================================================================================
# change 8 — LLM semantic domain analysis. This section is the deterministic half only: which
# domains are candidates, and what citable evidence bundle each one carries. The LLM call and its
# verifier are `app.agent.orchestrator.assess_domain_semantics` — out of this module's ownership
# boundary, the same split `_narrator_overview_payload`/`narrate_analysis_route` already draws for
# change 14 Path A.
# =============================================================================================


def _domain_semantic_candidate_selection(
    db: Session, tenant_id: uuid.UUID, destinations: list[NotableDestination]
) -> list[NotableDestination]:
    """Which of this analysis's `notable_destinations` (already ranked/capped to
    `NOTABLE_ENTITIES_LIMIT`) are "rare or first-seen" enough to earn a second, semantic look.
    Ranked first-seen-first, then by ascending org contact count, and capped at
    `MAX_SEMANTIC_DOMAINS_PER_CALL` *here* — before any of the per-candidate row lookups below run
    — so the domains most worth the extra queries are the ones that survive the cut."""
    org_contacts = contact_counts_many(
        db, tenant_id, (("", d.value) for d in destinations if not d.first_observed)
    )
    ranked: list[tuple[int, NotableDestination]] = []
    for d in destinations:
        if d.first_observed:
            ranked.append((0, d))
            continue
        org_count = org_contacts[("", d.value)].org.contact_count
        if 0 < org_count <= RARE_ORG_CONTACT_THRESHOLD:
            ranked.append((org_count, d))
    ranked.sort(key=lambda pair: pair[0])
    return [d for _, d in ranked[:MAX_SEMANTIC_DOMAINS_PER_CALL]]


def _first_event_for_domain(
    db: Session, tenant_id: uuid.UUID, analysis_id: uuid.UUID, domain: str
) -> Event | None:
    with tenant_scope(db, tenant_id):
        return db.execute(
            select(Event)
            .where(Event.analysis_id == analysis_id, Event.domain == domain)
            .order_by(Event.ts.asc())
            .limit(1)
        ).scalar_one_or_none()


def _preceding_events_payload(
    db: Session,
    tenant_id: uuid.UUID,
    analysis_id: uuid.UUID,
    principal: str,
    before_ts: datetime,
) -> list[dict[str, Any]]:
    """Every event immediately before `before_ts`, for the same `principal` only — this is what
    lets the semantic pass see "a GitHub credential event, then this domain" without needing to
    know *who* made either request. Deliberately never includes `principal`/`src_ip`/`dst_ip` in
    what it returns (CLAUDE.md rule 4, "pseudonymize before any external call") — the strongest
    form of that rule is not sending the identifier at all, not minting a pseudonym for something
    this pass has no use for. `url_path` is truncated + redacted the same way `app.agent.context.
    AgentContext.sanitize_free_text` treats every other free-text field that reaches a prompt."""
    with tenant_scope(db, tenant_id):
        rows = db.execute(
            select(Event.domain, Event.url_path, Event.action, Event.ts)
            .where(
                Event.analysis_id == analysis_id,
                Event.principal == principal,
                Event.ts < before_ts,
            )
            .order_by(Event.ts.desc())
            .limit(PRECEDING_CONTEXT_EVENTS)
        ).all()
    payload: list[dict[str, Any]] = []
    for domain, url_path, action, ts in rows:
        truncated = (url_path or "")[:FIELD_TRUNCATE_LEN]
        payload.append(
            {
                "domain": domain,
                "url_path": redact_text(truncated).text or None,
                "action": action,
                "seconds_before": max(0.0, (before_ts - ts).total_seconds()),
            }
        )
    return payload


def _log_ids_for_domain(
    db: Session, tenant_id: uuid.UUID, analysis_id: uuid.UUID, domain: str, limit: int
) -> list[str]:
    with tenant_scope(db, tenant_id):
        raw_line_nos = (
            db.execute(
                select(Event.raw_line_no)
                .where(Event.analysis_id == analysis_id, Event.domain == domain)
                .order_by(Event.ts.asc())
                .limit(limit)
            )
            .scalars()
            .all()
        )
    return [log_citation_id(n) for n in raw_line_nos]


def _compute_domain_semantic_candidates(
    db: Session,
    tenant_id: uuid.UUID,
    analysis_id: uuid.UUID,
    destinations: list[NotableDestination],
) -> list[dict[str, Any]]:
    """change 8's deterministic evidence bundle, one entry per selected candidate domain
    (`_domain_semantic_candidate_selection`): rarity at org scope, the domain's own already-
    computed DGA score (read straight off `NotableDestination.dga_score` — never recomputed,
    never touched by this pass, `app.detection.evidence.dga` stays the single owner of that
    number), a bounded set of citable `LOG-n` ids, and, when the first visit's own event carries a
    `principal`, the events that immediately preceded it. Every field here is either already
    computed elsewhere in this module or a small, targeted, `analysis_id`-scoped query — the same
    "reduce before the next stage" discipline CLAUDE.md rule 1 applies everywhere else in this
    pipeline, applied to a handful of domains rather than the whole file.
    """
    selected = _domain_semantic_candidate_selection(db, tenant_id, destinations)
    rarities = contact_counts_many(db, tenant_id, (("", d.value) for d in selected))
    candidates: list[dict[str, Any]] = []
    for i, dest in enumerate(selected, start=1):
        rarity = rarities[("", dest.value)].org
        first_event = _first_event_for_domain(db, tenant_id, analysis_id, dest.value)
        preceding: list[dict[str, Any]] = []
        if first_event is not None and first_event.principal:
            preceding = _preceding_events_payload(
                db, tenant_id, analysis_id, first_event.principal, first_event.ts
            )
        candidates.append(
            {
                "domain": dest.value,
                "evidence_id": f"DOMAIN-{i}",
                "rarity": {
                    "org_contact_count": rarity.contact_count,
                    "org_first_contact": rarity.is_first_contact,
                },
                "dga_score": dest.dga_score,
                "connection_count": dest.connection_count,
                "distinct_users": dest.distinct_users,
                "log_ids": _log_ids_for_domain(
                    db, tenant_id, analysis_id, dest.value, CANDIDATE_LOG_IDS_LIMIT
                ),
                "preceding_context": preceding,
            }
        )
    return candidates


def _compute_domain_semantic_findings(
    db: Session,
    tenant_id: uuid.UUID,
    analysis_id: uuid.UUID,
    destinations: list[NotableDestination],
) -> list[DomainSemanticFinding]:
    """Populates change 8's field on `AnalysisOverviewResponse` — see that schema's own docstring
    for why it defaulted to `[]` before this function existed. Gated on `Settings.llm_enabled`
    (an unconfigured key degrades to `[]`, exactly like an analysis with no rare/first-seen
    destinations at all — never a 503, unlike `POST /narrate`: this is a `GET` route documented
    as safe to call on every page load) and wrapped in a broad try/except (a timeout, a refusal,
    or a schema-validation failure from the LLM call degrades to `[]` the same way `app.agent.
    context._prior_analyst_decisions_block` degrades a failed memory lookup — a missing semantic
    finding is a correct, reportable answer; a 500 on the whole overview page is not).

    **Called once per analysis, from the `triage` stage — never from a request handler.** This
    spends real tokens and takes seconds. It used to run inline inside `GET /overview`, which
    meant the analysis page paid for an LLM round trip on every load, every reload and every tab
    switch, and blocked for 14-17s doing it — comfortably past the frontend's server-render
    budget, which is what produced the "server-side exception" the analyst saw. The migration
    that added `analyses.domain_semantic_findings` removed the "nowhere to persist it" reason
    this note previously gave for accepting that.
    """
    settings = get_settings()
    if not settings.llm_enabled:
        return []

    candidates = _compute_domain_semantic_candidates(db, tenant_id, analysis_id, destinations)
    if not candidates:
        return []

    caller = LiveCaller(api_key=settings.anthropic_api_key.get_secret_value())
    try:
        result = assess_domain_semantics(
            candidates=candidates, caller=caller, model=settings.anthropic_model
        )
    except Exception:
        log.warning(
            "analyses.domain_semantic_failed",
            analysis_id=str(analysis_id),
            n_candidates=len(candidates),
            exc_info=True,
        )
        return []

    log.info(
        "analyses.domain_semantic_complete",
        analysis_id=str(analysis_id),
        n_candidates=len(candidates),
        n_findings=len(result.findings),
        citation_valid=result.citation_valid,
        cost_usd=str(result.cost_usd),
    )
    return [
        DomainSemanticFinding(
            domain=f.domain,
            assessment=f.assessment,
            rationale=f.rationale,
            evidence_id=f.evidence_id,
        )
        for f in result.findings
    ]


@router.get("/analyses/{analysis_id}/overview", response_model=AnalysisOverviewResponse)
def get_analysis_overview(
    analysis_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> AnalysisOverviewResponse:
    """change 9's deterministic log overview, always produced — works for an analysis that is
    still `running` (partial counts) or has zero incidents (an empty `notable_users`/
    `notable_destinations` is a correct answer, not an error). `executive_summary` is not part of
    this response; see `POST /analyses/{id}/narrate` and this module's own docstring for why the
    LLM half of change 10 Level 1 is a separate, explicit call.

    `domain_semantic_findings` (change 8) is populated by `_compute_domain_semantic_findings`,
    over the same `notable_destinations` this response already computed — an empty list remains a
    correct, common answer (no rare/first-seen destination, no configured API key, or nothing the
    pass flagged), not evidence the pass isn't wired.
    """
    with tenant_scope(db, current.tenant.id):
        analysis = db.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        ).scalar_one_or_none()
        if analysis is None:
            raise _not_found()
        anomaly_count = db.execute(
            select(func.count(Incident.id)).where(Incident.analysis_id == analysis_id)
        ).scalar_one()

    notable_destinations = _compute_notable_destinations(db, current.tenant.id, analysis_id)

    return AnalysisOverviewResponse(
        overview=_compute_log_overview(db, current.tenant.id, analysis),
        anomaly_count=anomaly_count,
        notable_users=_compute_notable_users(db, current.tenant.id, analysis_id),
        notable_destinations=notable_destinations,
        # Read, not compute. This used to call `_compute_domain_semantic_findings` inline, which
        # makes a live Anthropic request — so a GET documented as "safe to call on every page
        # load" blocked for 14-17s and spent tokens on every load, reload and tab switch. The
        # pipeline computes these once (`app.pipeline.stages.triage`) and stores them.
        domain_semantic_findings=[
            DomainSemanticFinding.model_validate(f)
            for f in (analysis.domain_semantic_findings or [])
        ],
        narrative=_stored_narrative(analysis),
    )


def _stored_narrative(analysis: Analysis) -> StoredNarrative | None:
    """The narrative `triage` already generated, read off the row. A column read, never a
    generation — this route must stay free of LLM spend so the page can render the summary on
    every load instead of asking the analyst to pay for one the pipeline already bought."""
    if not analysis.narrative:
        return None
    return StoredNarrative(
        executive_summary=analysis.narrative,
        citation_valid=analysis.narrative_citation_valid,
        invalid_citation_count=len(analysis.narrative_invalid_citations or []),
        model=analysis.narrative_model,
        cost_usd=analysis.narrative_cost_usd,
        generated_at=analysis.narrative_generated_at,
    )


def _narrator_overview_payload(overview: LogOverview) -> dict[str, Any]:
    """change 9's own JSON shape (`{"period": [start, end], "events": ..., ...}`) for the
    Narrator prompt specifically — `AnalysisOverviewResponse.overview` uses `period_start`/
    `period_end` (see that schema's docstring for why), but the migration doc's own worked
    example for what the Narrator reads is a `period` pair; matching it here costs nothing and
    keeps the prompt recognizable against the doc."""
    return {
        "period": [
            overview.period_start.isoformat() if overview.period_start else None,
            overview.period_end.isoformat() if overview.period_end else None,
        ],
        "events": overview.events,
        "users": overview.users,
        "src_ips": overview.src_ips,
        "unique_domains": overview.unique_domains,
        "allowed": overview.allowed,
        "blocked": overview.blocked,
        "bytes_out": overview.bytes_out,
        "bytes_in": overview.bytes_in,
        "parse_failure_rate": overview.parse_failure_rate,
    }


@router.post("/analyses/{analysis_id}/narrate", response_model=AnalysisNarrateResponse)
def narrate_analysis_route(
    analysis_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> AnalysisNarrateResponse:
    """change 14 Path A, wired to HTTP for the first time — `app.agent.orchestrator.
    narrate_analysis` itself is unit-tested but was never called from an API surface before this
    (that function's own docstring: wiring it in "is out of app/agent's ownership"). No
    persistence, no idempotency — see this module's own docstring for why, and
    `app.api.incidents.trigger_incident_triage` for the pattern this deliberately cannot fully
    match yet.

    Inputs are exactly change 14's three deterministic, pre-computed pieces:
    `_compute_log_overview` (this file), the analysis's incidents (`incidents` table), and
    `analysis_timeline_phases` (`app.api.incident_detail`, the same truncated, confidence-ranked
    phase list `GET /analyses/{id}/timeline` serves) — the Narrator selects nothing, orders
    nothing, and counts nothing; it only writes prose over numbers this handler already computed.
    """
    settings = get_settings()
    with tenant_scope(db, current.tenant.id):
        analysis = db.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        ).scalar_one_or_none()
        if analysis is None:
            raise _not_found()

        incident_rows = (
            db.execute(select(Incident).where(Incident.analysis_id == analysis_id)).scalars().all()
        )
        verdicts_by_incident: dict[uuid.UUID, TriageVerdict] = {}
        if incident_rows:
            verdict_rows = (
                db.execute(
                    select(TriageVerdict)
                    .where(TriageVerdict.incident_id.in_([i.id for i in incident_rows]))
                    .order_by(TriageVerdict.incident_id, TriageVerdict.created_at.asc())
                )
                .scalars()
                .all()
            )
            for v in verdict_rows:  # ascending order -> last write per incident wins (newest)
                verdicts_by_incident[v.incident_id] = v

    incidents_payload: list[dict[str, Any]] = [
        {
            "id": str(inc.id),
            "title": inc.title,
            "severity": inc.severity,
            "fused_score": inc.fused_score,
            "anomaly_confidence": inc.anomaly_confidence,
            "disposition": verdicts_by_incident[inc.id].disposition
            if inc.id in verdicts_by_incident
            else None,
        }
        for inc in incident_rows
    ]

    phases, _total_phases, _truncated = analysis_timeline_phases(db, current.tenant.id, analysis_id)
    all_event_ids = {eid for phase in phases for eid in phase.event_ids}
    with tenant_scope(db, current.tenant.id):
        line_rows = (
            db.execute(
                select(Event.id, Event.raw_line_no).where(
                    Event.analysis_id == analysis_id, Event.id.in_(all_event_ids)
                )
            ).all()
            if all_event_ids
            else []
        )
    line_by_event_id: dict[int, int] = {}
    for event_id, line_no in line_rows:
        line_by_event_id[event_id] = line_no
    timeline_payload: list[dict[str, Any]] = [
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

    overview = _compute_log_overview(db, current.tenant.id, analysis)

    if not settings.llm_enabled:
        raise _no_api_key()
    caller = LiveCaller(api_key=settings.anthropic_api_key.get_secret_value())

    result = narrate_analysis(
        overview=_narrator_overview_payload(overview),
        incidents=incidents_payload,
        timeline_phases=timeline_payload,
        caller=caller,
        model=settings.anthropic_model,
    )
    log.info(
        "analyses.narrated",
        analysis_id=str(analysis_id),
        citation_valid=result.citation_valid,
        cost_usd=str(result.cost_usd),
    )
    # An explicit regeneration replaces the stored copy — otherwise the analyst would read a
    # narrative from the pipeline run while the one they just paid to refresh lived only in the
    # browser tab, and a reload would silently revert it.
    with tenant_scope(db, current.tenant.id):
        db.execute(
            update(Analysis)
            .where(Analysis.id == analysis_id)
            .values(
                llm_cost_usd=func.coalesce(Analysis.llm_cost_usd, 0) + result.cost_usd,
                **narrative_columns(result),
            )
        )
        db.commit()
    return AnalysisNarrateResponse(
        executive_summary=result.executive_summary,
        phase_narratives=list(result.phase_narratives),
        citation_valid=result.citation_valid,
        invalid_citations=list(result.invalid_citations),
        model=result.model,
        tokens_in=result.tokens_in,
        tokens_out=result.tokens_out,
        cost_usd=result.cost_usd,
        latency_ms=result.latency_ms,
    )
