"""The incident *read* surface — docs/09-API-CONTRACT.md.

    GET /api/analyses/{analysis_id}/incidents   the queue
    GET /api/analyses/{analysis_id}/timeline    analysis-wide summarized timeline (below)
    GET /api/incidents/{incident_id}            full case file (minus timeline/plan, below)
    GET /api/incidents/{incident_id}/graph      `{nodes: [], edges: []}`
    GET /api/incidents/{incident_id}/timeline   docs/05's deterministic phase list

Why this is not in `app.api.incidents`: that module's docstring scopes itself to the *verdict*
slice and explicitly says the composite detail endpoint "spans four milestones' data ... and is
not this module's to build whole". This is that composite. Both routers mount at `/api`, so the
split is invisible over the wire — `/api/incidents/{id}` and `/api/incidents/{id}/verdict` are
neighbours in `/api/docs` regardless of which file defines them.

**Why `/api/analyses/{id}/timeline` lives here and not in `app.api.events`.** It is
`app.graph.timeline.build_timeline` fed every signal in an analysis instead of one incident's
(docs/05's "Timeline" section) — the exact same function, called the exact same way, as
`get_incident_timeline` two functions below. Splitting the two callers across modules would mean
either duplicating the phase-assembly logic or importing across `app.api.events`/
`app.api.incident_detail` for no reason; keeping them together means one docstring explains the
ordering/truncation contract for both.

**Tenant isolation.** `Incident` and `Signal` carry `TenantScopedMixin`, so `tenant_scope`
filters them structurally (`app.models.base`). `Entity` and `EntityEdge` do not — docs/02 scopes
them transitively through `analysis_id`, and every query below reaches them only via an
`analysis_id` read off an incident (or, for the two analysis-scoped routes, an `Analysis` row
itself) that `tenant_scope` already proved belongs to the caller. A cross-tenant id 404s; it
never leaks a row.

**Ordering.** The queue is `fused_score DESC, id DESC` — the order an analyst works the queue in,
and a strict total order (`id` is unique), so the keyset cursor below can never skip or repeat a
row. Same rule as `app.api.events`: keyset, never `OFFSET`.
"""

from __future__ import annotations

import base64
import binascii
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, cast, or_, select
from sqlalchemy.dialects.postgresql import REAL
from sqlalchemy.orm import Session

from app.agent.context import (
    CITATION_TEMPORAL_SLACK,
    AgentContextError,
    build_agent_context,
    compute_evidence_payloads,
)
from app.core.db import get_db
from app.core.errors import ApiError
from app.core.security import CurrentUser, require_user
from app.detection.evidence.payload import EvidencePayload
from app.graph.timeline import TimelinePhase, build_timeline
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.entity import Entity
from app.models.entity_edge import EntityEdge
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.triage_verdict import TriageVerdict
from app.schemas.agent import TriageVerdictResponse
from app.schemas.evidence import (
    AnalysisEvidenceResponse,
    IncidentEvidenceResponse,
    evidence_payload_out,
    highlight_line_violations,
)
from app.schemas.incident import (
    AnalysisTimelineResponse,
    EntityOut,
    GraphEdge,
    GraphNode,
    IncidentDetail,
    IncidentGraph,
    IncidentListItem,
    IncidentsListResponse,
    SignalOut,
    TimelinePhaseOut,
    TimelineResponse,
)

router = APIRouter()

# `GET /api/analyses/{id}/evidence` (change 16, "including evidence that never formed an
# incident") has no natural upper bound either — same CLAUDE.md rule 1 reasoning as
# `MAX_ANALYSIS_TIMELINE_PHASES` above, applied to a browse table instead of an LLM prompt: an
# unbounded page is not "browsable". `total`/`truncated` on the response tell the analyst how
# much was cut, same contract as the analysis timeline.
MAX_ANALYSIS_EVIDENCE_ITEMS = 500

# Cap for `GET /api/analyses/{id}/timeline` — an analysis-wide timeline has no natural upper
# bound the way one incident's does (docs/05 correlates "hundreds of signals" down to "a dozen
# readable incidents", but the *analysis* can still carry every signal that never made it into
# one), and CLAUDE.md rule 1 ("the LLM never sees raw log volume... a few hundred events into a
# prompt, stop") is a UI-facing instance of the same principle here: an unbounded phase list is
# not "summarized". Kept by confidence, not truncated arbitrarily — see
# `get_analysis_timeline`'s docstring for how the cut interacts with chronological ordering.
# The Signals tab pages through this client-side (100 at a time, load-more), so the server cap
# is the *total* it can ever reveal, not a page size. At 100 the two were identical and the
# load-more button never appeared, because the client had already been given everything.
MAX_ANALYSIS_TIMELINE_PHASES = 1000

# The graph endpoint returns the incident's seed entities plus their 1-hop neighbourhood
# (docs/05). On a busy analysis a single hub entity — a shared proxy egress IP, a CDN domain —
# can have thousands of neighbours, which would produce a payload no one can read and a layout
# no one can interpret. Neighbours are taken in descending edge weight, so the cap keeps the
# strongest relationships rather than an arbitrary slice, and any edge whose other endpoint fell
# outside the cap is dropped rather than left dangling.
MAX_GRAPH_NEIGHBOURS = 60


def _not_found(detail: str) -> ApiError:
    return ApiError(status_code=404, code="not_found", detail=detail)


def _require_incident(db: Session, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> Incident:
    with tenant_scope(db, tenant_id):
        incident = db.execute(
            select(Incident).where(Incident.id == incident_id)
        ).scalar_one_or_none()
    if incident is None:
        raise _not_found("Incident not found.")
    return incident


def _encode_cursor(fused_score: float, incident_id: uuid.UUID) -> str:
    return base64.urlsafe_b64encode(f"{fused_score!r}|{incident_id}".encode()).decode()


def _decode_cursor(cursor: str) -> tuple[float, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        score_str, id_str = raw.split("|", 1)
        return float(score_str), uuid.UUID(id_str)
    except (ValueError, binascii.Error) as exc:
        raise ApiError(status_code=400, code="invalid_cursor", detail="Invalid cursor.") from exc


def _latest_verdicts(db: Session, incident_ids: list[uuid.UUID]) -> dict[uuid.UUID, TriageVerdict]:
    """Newest verdict per incident, one query for the whole page.

    `TriageVerdict` is not tenant-scoped (docs/02: isolation is transitive through `incident_id`,
    `app.models.triage_verdict`'s own docstring). Every id passed in here has already been read
    out of a `tenant_scope`d query, so this cannot widen the caller's view.
    """
    if not incident_ids:
        return {}
    rows = (
        db.execute(
            select(TriageVerdict)
            .where(TriageVerdict.incident_id.in_(incident_ids))
            .order_by(TriageVerdict.incident_id, TriageVerdict.created_at.asc())
        )
        .scalars()
        .all()
    )
    # Ascending order means the last write per incident wins — the newest verdict.
    return {v.incident_id: v for v in rows}


def _technique_ids(verdict: TriageVerdict | None) -> list[str]:
    """docs/07's `mitre_techniques[]` is `[{id, name, rationale}]`; the queue row wants bare ids.

    Tolerant on purpose: a verdict row is LLM-authored JSONB, and one malformed entry should
    cost that entry, not the whole queue page.
    """
    if verdict is None:
        return []
    out: list[str] = []
    for item in verdict.mitre_techniques or []:
        if isinstance(item, dict):
            tid = item.get("id")
            if isinstance(tid, str) and tid:
                out.append(tid)
        elif isinstance(item, str) and item:
            out.append(item)
    return out


@router.get("/analyses/{analysis_id}/incidents", response_model=IncidentsListResponse)
def list_incidents(
    analysis_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
    severity: str | None = None,
    status: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: str | None = None,
) -> IncidentsListResponse:
    with tenant_scope(db, current.tenant.id):
        analysis = db.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        ).scalar_one_or_none()
        if analysis is None:
            raise _not_found("Analysis not found.")

        stmt = select(Incident).where(Incident.analysis_id == analysis_id)
        if severity is not None:
            stmt = stmt.where(Incident.severity == severity)
        if status is not None:
            stmt = stmt.where(Incident.status == status)
        stmt = stmt.order_by(Incident.fused_score.desc(), Incident.id.desc())
        if cursor is not None:
            cursor_score, cursor_id = _decode_cursor(cursor)
            # `cast(..., REAL)` is load-bearing. `incidents.fused_score` is `REAL` (float4,
            # docs/02) but a Python float binds as float8, and Postgres resolves float4 < float8
            # by *widening the column*: 0.7 stored as float4 reads back as 0.699999988079071 in
            # float8, which is strictly less than the 0.7 in the cursor. Every row on the page
            # would then satisfy the predicate again and pagination would never terminate.
            # Casting the parameter down to REAL keeps the comparison inside the column's own
            # type domain, where the cursor value is exactly the value it came from.
            #
            # Written as an explicit disjunction rather than a row-value comparison because a
            # `tuple_(...) < (python, tuple)` right-hand side binds each element as a literal
            # parameter, and a `Cast` is a SQL expression, not something psycopg can adapt.
            cursor_param = cast(cursor_score, REAL)
            stmt = stmt.where(
                or_(
                    Incident.fused_score < cursor_param,
                    and_(Incident.fused_score == cursor_param, Incident.id < cursor_id),
                )
            )
        rows = db.execute(stmt.limit(limit + 1)).scalars().all()

        has_more = len(rows) > limit
        page = list(rows[:limit])
        verdicts = _latest_verdicts(db, [i.id for i in page])

    items: list[IncidentListItem] = []
    for inc in page:
        verdict = verdicts.get(inc.id)
        disposition = verdict.disposition if verdict is not None else None
        citation_valid = verdict.citation_valid if verdict is not None else None
        evidence_confidence = verdict.evidence_confidence if verdict is not None else None
        evidence_confidence_band = verdict.evidence_confidence_band if verdict is not None else None
        items.append(
            IncidentListItem(
                id=inc.id,
                title=inc.title,
                severity=inc.severity,
                fused_score=inc.fused_score,
                anomaly_confidence=inc.anomaly_confidence,
                disposition=disposition,
                citation_valid=citation_valid,
                evidence_confidence=evidence_confidence,
                evidence_confidence_band=evidence_confidence_band,
                mitre_techniques=_technique_ids(verdict),
                tags=list(inc.tags),
                entity_count=len(inc.entity_ids),
                signal_count=len(inc.signal_ids),
                created_at=inc.created_at,
                # Everything an analyst must personally look at: never triaged, the agent
                # itself asked for review, or a verdict whose citations failed verification
                # (docs/07). Computed here so the queue's filter and its badge cannot drift
                # apart the way they would if each client derived it.
                needs_attention=(
                    verdict is None or disposition == "needs_review" or citation_valid is False
                ),
            )
        )
    next_cursor = _encode_cursor(page[-1].fused_score, page[-1].id) if has_more and page else None
    return IncidentsListResponse(items=items, next_cursor=next_cursor)


def _timeline_phase_out(phase: TimelinePhase) -> TimelinePhaseOut:
    """Shared by both timeline routes — one field-for-field copy from the dataclass
    `build_timeline` returns to the Pydantic shape the wire actually sends."""
    return TimelinePhaseOut(
        ts=phase.ts,
        tactic=phase.tactic,
        tactic_is_placeholder=phase.tactic_is_placeholder,
        event_ids=phase.event_ids,
        summary=phase.summary,
        detector_key=phase.detector_key,
        detector_layer=phase.detector_layer,
        entity_type=phase.entity_type,
        entity_value=phase.entity_value,
        confidence=phase.confidence,
        calibrated=phase.calibrated,
        mitre_technique=phase.mitre_technique,
    )


def analysis_timeline_phases(
    db: Session, tenant_id: uuid.UUID, analysis_id: uuid.UUID
) -> tuple[list[TimelinePhase], int, bool]:
    """Every signal in the analysis, correlated into phases (`build_timeline`) and truncated to
    `MAX_ANALYSIS_TIMELINE_PHASES` by confidence — the computation `get_analysis_timeline` below
    serves over HTTP, factored out so `app.api.analyses`' change-14 Path A narrator route can feed
    the Narrator the exact same, already-deterministically-selected phase list a client reading
    `GET /api/analyses/{id}/timeline` would see (change 14: "*selection* of which phases matter is
    deterministic and happens upstream ... never [in the Narrator]"). Returns `(phases,
    total_phases, truncated)` — see `get_analysis_timeline`'s docstring for the truncation rule
    and why `total_phases` is the pre-cut count.

    Does not itself check the analysis exists — callers already resolve `analysis_id` through a
    tenant-scoped `Analysis` lookup of their own (this function would otherwise 404 on the wrong
    exception type for at least one of its two callers' response contracts).
    """
    with tenant_scope(db, tenant_id):
        signals = (
            db.execute(select(Signal).where(Signal.analysis_id == analysis_id)).scalars().all()
        )

    all_phases = build_timeline(list(signals))
    total_phases = len(all_phases)
    truncated = total_phases > MAX_ANALYSIS_TIMELINE_PHASES
    if truncated:
        keep_indices = _select_phase_indices(all_phases, MAX_ANALYSIS_TIMELINE_PHASES)
        phases = [p for i, p in enumerate(all_phases) if i in keep_indices]
    else:
        phases = all_phases
    return phases, total_phases, truncated


def _select_phase_indices(phases: list[TimelinePhase], limit: int) -> set[int]:
    """Which `limit` phases survive truncation — highest confidence first, but round-robin
    across `detector_key` so no single detector can own the whole page.

    A pure `sorted(by -confidence)[:limit]` is what this used to be, and on real data it
    degenerates completely. Confidence is `clamp01(raw_score)` for any detector without a
    fitted isotonic calibrator, so an uncalibrated detector whose raw scores exceed 1.0 pins
    every one of its signals to *exactly* 1.0. On a measured analysis here, 189 signals tied at
    1.0 against this 100-phase cap — two detectors between them filled the entire timeline and
    every row rendered "confidence 100%". An analyst learns nothing from a page where every
    entry is identical, and the strongest evidence from every *other* detector is what got cut
    to make room for the ties.

    Round-robin attacks that directly: take each detector's best remaining phase in turn, so a
    detector holding 143 saturated signals contributes its first before it contributes its
    second. Detectors are visited in descending order of their own top confidence, so the
    strongest evidence still leads; within a detector, phases stay ranked by confidence with
    chronological position as the tiebreak. Fully deterministic, and it selects exactly what
    the old rule did whenever no detector holds more than its round-robin share.
    """
    by_detector: dict[str, list[tuple[float, int]]] = defaultdict(list)
    for i, phase in enumerate(phases):
        by_detector[phase.detector_key].append((phase.confidence, i))
    if not by_detector:
        return set()
    for ranked in by_detector.values():
        ranked.sort(key=lambda pair: (-pair[0], pair[1]))

    # Strongest detector first, by its own best phase; the detector key breaks ties so the
    # order is stable across runs rather than dependent on dict insertion order.
    order = sorted(by_detector, key=lambda key: (-by_detector[key][0][0], key))

    keep: set[int] = set()
    for round_index in range(max(len(r) for r in by_detector.values())):
        for detector_key in order:
            ranked = by_detector[detector_key]
            if round_index >= len(ranked):
                continue
            keep.add(ranked[round_index][1])
            if len(keep) == limit:
                return keep
    return keep


@router.get("/analyses/{analysis_id}/timeline", response_model=AnalysisTimelineResponse)
def get_analysis_timeline(
    analysis_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> AnalysisTimelineResponse:
    """The take-home brief's "summarized timeline of events" — analysis-wide, not nested in one
    incident's case file. Reuses `build_timeline` (docs/05: "Never let the model order events")
    fed every signal in the analysis rather than one incident's `signal_ids`.

    **Truncation.** Capped at `MAX_ANALYSIS_TIMELINE_PHASES`, kept *by confidence* — "keep the
    strongest, then re-sort chronologically for output" (docs/09). Concretely: `build_timeline`
    already returns every phase in deterministic chronological order (window_start, falling back
    to the lowest evidence event id — see that module's docstring for why that fallback is
    correct and not arbitrary); when a cut is needed, this ranks phases by confidence (ties
    broken by their position in that chronological list, for determinism) to pick the survivors,
    then filters the *original* chronological list down to that surviving set instead of
    re-deriving order from `ts` from scratch. That sidesteps having a second, easy-to-drift
    reimplementation of `build_timeline`'s None/fallback ordering rule here, and produces exactly
    the same output a from-scratch chronological re-sort of the survivors would.

    `total_phases` is the count *before* the cut, so the UI can render "showing the 100
    highest-confidence phases of N" instead of a vaguer "some were hidden" — added after this
    endpoint's first pass shipped without it and the frontend had no way to say how much was cut.
    """
    with tenant_scope(db, current.tenant.id):
        analysis = db.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        ).scalar_one_or_none()
        if analysis is None:
            raise _not_found("Analysis not found.")

    phases, total_phases, truncated = analysis_timeline_phases(db, current.tenant.id, analysis_id)
    return AnalysisTimelineResponse(
        phases=[_timeline_phase_out(p) for p in phases],
        truncated=truncated,
        total_phases=total_phases,
    )


def _verdict_for_incident(
    db: Session, tenant_id: uuid.UUID, incident: Incident
) -> TriageVerdict | None:
    """This incident's own latest verdict. Shared by `get_incident` and `get_incident_evidence`
    so the two can never disagree about which verdict "this incident's verdict" means.

    Previously fell back to a recurrence parent's verdict when this incident had none. Recurrence
    detection is gone (it was the duplicate-checking service), so an incident with no verdict now
    simply has none — every incident is triaged on its own evidence or not at all.
    """
    return _latest_verdicts(db, [incident.id]).get(incident.id)


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident(
    incident_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> IncidentDetail:
    incident = _require_incident(db, current.tenant.id, incident_id)
    with tenant_scope(db, current.tenant.id):
        signals = (
            db.execute(
                select(Signal)
                .where(Signal.id.in_(incident.signal_ids))
                .order_by(Signal.confidence.desc(), Signal.id.asc())
            )
            .scalars()
            .all()
        )
        entities = (
            db.execute(
                select(Entity)
                .where(
                    Entity.analysis_id == incident.analysis_id,
                    Entity.id.in_(incident.entity_ids),
                )
                .order_by(Entity.risk_score.desc(), Entity.id.asc())
            )
            .scalars()
            .all()
        )

    verdict = _verdict_for_incident(db, current.tenant.id, incident)

    return IncidentDetail(
        id=incident.id,
        analysis_id=incident.analysis_id,
        title=incident.title,
        severity=incident.severity,
        fused_score=incident.fused_score,
        anomaly_confidence=incident.anomaly_confidence,
        status=incident.status,
        entity_ids=list(incident.entity_ids),
        signal_ids=list(incident.signal_ids),
        tags=list(incident.tags),
        summary=incident.summary,
        created_at=incident.created_at,
        entities=[EntityOut.model_validate(e) for e in entities],
        signals=[SignalOut.model_validate(s) for s in signals],
        verdict=TriageVerdictResponse.model_validate(verdict) if verdict is not None else None,
    )


@router.get("/incidents/{incident_id}/timeline", response_model=TimelineResponse)
def get_incident_timeline(
    incident_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> TimelineResponse:
    """Ordering is a database fact, not a model output — docs/05: "Never let the model order
    events." `app.graph.timeline.build_timeline` is the same function the agent's context builder
    uses, called here on the same rows, so the timeline an analyst reads is byte-identical to the
    one the agent reasoned over."""
    incident = _require_incident(db, current.tenant.id, incident_id)
    with tenant_scope(db, current.tenant.id):
        signals = (
            db.execute(select(Signal).where(Signal.id.in_(incident.signal_ids))).scalars().all()
        )
    phases = build_timeline(list(signals))
    return TimelineResponse(phases=[_timeline_phase_out(p) for p in phases])


@router.get("/incidents/{incident_id}/graph", response_model=IncidentGraph)
def get_incident_graph(
    incident_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> IncidentGraph:
    """Seed entities plus their 1-hop neighbourhood, capped at `MAX_GRAPH_NEIGHBOURS` by edge
    weight. Edges are returned only between nodes that are actually present, so the client never
    has to handle a dangling endpoint."""
    incident = _require_incident(db, current.tenant.id, incident_id)
    seed_ids = set(incident.entity_ids)
    if not seed_ids:
        return IncidentGraph(nodes=[], edges=[])

    with tenant_scope(db, current.tenant.id):
        # Entity/EntityEdge are scoped transitively through analysis_id (docs/02); the incident
        # above was already proven to belong to this tenant, so its analysis_id is the boundary.
        incident_edges = (
            db.execute(
                select(EntityEdge)
                .where(
                    EntityEdge.analysis_id == incident.analysis_id,
                    or_(
                        EntityEdge.src_entity_id.in_(seed_ids),
                        EntityEdge.dst_entity_id.in_(seed_ids),
                    ),
                )
                .order_by(EntityEdge.weight.desc(), EntityEdge.id.asc())
            )
            .scalars()
            .all()
        )

        neighbour_ids: list[int] = []
        seen: set[int] = set()
        for edge in incident_edges:
            for eid in (edge.src_entity_id, edge.dst_entity_id):
                if eid not in seed_ids and eid not in seen:
                    seen.add(eid)
                    neighbour_ids.append(eid)
        neighbour_ids = neighbour_ids[:MAX_GRAPH_NEIGHBOURS]

        node_ids = seed_ids | set(neighbour_ids)
        entities = (
            db.execute(
                select(Entity).where(
                    Entity.analysis_id == incident.analysis_id, Entity.id.in_(node_ids)
                )
            )
            .scalars()
            .all()
        )

    key_by_id: dict[int, str] = {e.id: f"{e.type}:{e.value}" for e in entities}
    nodes = [
        GraphNode(
            id=key_by_id[e.id],
            type=e.type,
            value=e.value,
            risk_score=e.risk_score,
            event_count=e.event_count,
            is_seed=e.id in seed_ids,
        )
        for e in entities
    ]
    edges: list[GraphEdge] = []
    emitted: set[tuple[str, str, str]] = set()
    for edge in incident_edges:
        src = key_by_id.get(edge.src_entity_id)
        dst = key_by_id.get(edge.dst_entity_id)
        if src is None or dst is None:
            continue  # endpoint fell outside the cap — drop the edge, never dangle it
        dedup_key = (src, dst, edge.relation)
        if dedup_key in emitted:
            continue
        emitted.add(dedup_key)
        edges.append(
            GraphEdge(
                source=src,
                target=dst,
                relation=edge.relation,
                weight=edge.weight,
                event_count=edge.event_count,
            )
        )
    return IncidentGraph(nodes=nodes, edges=edges)


# ------------------------------------------------------------------ GET /incidents/{id}/evidence
#                                                                     GET /analyses/{id}/evidence
#                                                             docs/v2_migration changes 2, 11, 16


@router.get("/incidents/{incident_id}/evidence", response_model=IncidentEvidenceResponse)
def get_incident_evidence(
    incident_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> IncidentEvidenceResponse:
    """change 16's primary evidence view: every `EvidencePayload` that contributed to this
    incident (`app.agent.context.build_agent_context`'s own entity+window filtering — the exact
    scope a triage run would have seen, so the evidence an analyst reviews here is byte-identical
    to what the agent reasoned over). change 11's `highlight_lines` and `highlight_line_
    violations` are derived from the same set, in this handler, never from the verdict's prose —
    see `app.schemas.evidence`'s own module docstring for the full trace path and why this is a
    route of its own rather than a field on `IncidentDetail`.
    """
    incident = _require_incident(db, current.tenant.id, incident_id)
    try:
        ctx = build_agent_context(db, current.tenant.id, incident.id)
    except AgentContextError as exc:
        raise _not_found(str(exc)) from exc

    highlight_lines = sorted(
        {line_no for p in ctx.evidence_payloads for line_no in p.contributing_line_numbers}
    )
    verdict = _verdict_for_incident(db, current.tenant.id, incident)
    violations = highlight_line_violations(
        verdict.narrative if verdict is not None else None, highlight_lines
    )
    items = [evidence_payload_out(p, incident_ids=[incident.id]) for p in ctx.evidence_payloads]
    return IncidentEvidenceResponse(
        items=items, highlight_lines=highlight_lines, highlight_line_violations=violations
    )


def _incident_scope_and_window(
    db: Session, incident: Incident
) -> tuple[frozenset[tuple[str, str]], datetime, datetime]:
    """This incident's own (entity_type, entity_value) scope and time window, for matching
    `EvidencePayload`s against it — the same rule `app.agent.context._entity_scope`/`_incident_
    window` compute, duplicated here rather than imported. Those two helpers are private to
    `app.agent.context` (leading underscore, absent from its `__all__`), and that module's own
    `_incident_window` docstring makes the same call for a sibling case ("computed directly here
    instead of importing `app.graph.timeline` ... duplicating ~10 lines of aggregation is cheaper
    than a cross-milestone coupling") — the same tradeoff applies to reaching into another
    package's private helpers.
    """
    scope: set[tuple[str, str]] = set()
    if incident.entity_ids:
        rows = db.execute(
            select(Entity.type, Entity.value).where(Entity.id.in_(incident.entity_ids))
        ).all()
        scope.update((t, v) for t, v in rows)

    starts: list[datetime] = []
    ends: list[datetime] = []
    if incident.signal_ids:
        window_rows = db.execute(
            select(Signal.window_start, Signal.window_end).where(Signal.id.in_(incident.signal_ids))
        ).all()
        for s_start, s_end in window_rows:
            if s_start is not None:
                starts.append(s_start)
            if s_end is not None:
                ends.append(s_end)
        if not scope:
            entity_rows = db.execute(
                select(Signal.entity_type, Signal.entity_value).where(
                    Signal.id.in_(incident.signal_ids)
                )
            ).all()
            scope.update((t, v) for t, v in entity_rows)

    window_start, window_end = (
        (min(starts), max(ends)) if starts and ends else (incident.created_at, incident.created_at)
    )
    return frozenset(scope), window_start, window_end


def _evidence_matches_incident(
    payload: EvidencePayload,
    *,
    entity_scope: frozenset[tuple[str, str]],
    window_start: datetime,
    window_end: datetime,
) -> bool:
    """Same membership rule as `app.agent.context._filter_evidence_for_incident`: the payload's
    own entity is one of the incident's entities, and its window overlaps the incident's window
    padded by `CITATION_TEMPORAL_SLACK` on each side."""
    pair = (payload.entity.get("type", ""), payload.entity.get("value", ""))
    if pair not in entity_scope:
        return False
    lo = window_start - CITATION_TEMPORAL_SLACK
    hi = window_end + CITATION_TEMPORAL_SLACK
    p_start, p_end = payload.window
    return p_start <= hi and lo <= p_end


def _max_percentile(payload: EvidencePayload) -> float | None:
    """The highest numeric `*percentile` value in this payload's `historical` dict (change 2's
    `historical_from_percentile` always names its keys `{prefix}_percentile` or bare
    `percentile`) — used only for `min_percentile` filtering below. `None` when every percentile
    entry is cold-start (`baseline_status: "insufficient_history"` → `percentile: None`) or the
    extractor carries no percentile at all (dga's probability is already the answer, per change
    2's own table)."""
    values = [
        v
        for k, v in payload.historical.items()
        if k.endswith("percentile") and isinstance(v, int | float)
    ]
    return max(values) if values else None


@router.get("/analyses/{analysis_id}/evidence", response_model=AnalysisEvidenceResponse)
def get_analysis_evidence(
    analysis_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
    extractor: str | None = None,
    entity_type: str | None = None,
    entity_value: str | None = None,
    min_percentile: Annotated[float | None, Query(ge=0, le=100)] = None,
    line_no: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[
        int, Query(ge=1, le=MAX_ANALYSIS_EVIDENCE_ITEMS)
    ] = MAX_ANALYSIS_EVIDENCE_ITEMS,
) -> AnalysisEvidenceResponse:
    """change 16's secondary evidence view: every `EvidencePayload` produced for the analysis —
    "including evidence that never formed an incident. That residue is exactly what an analyst
    wants when they suspect the pipeline missed something." Filterable by `extractor`,
    `entity_type`/`entity_value`, and `min_percentile`; sorted by `evidence_id` (change 2's own
    deterministic assignment order — extractor, then entity, then window) so the same query
    returns the same page every time.
    """
    with tenant_scope(db, current.tenant.id):
        analysis = db.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        ).scalar_one_or_none()
        if analysis is None:
            raise _not_found("Analysis not found.")

    all_evidence = compute_evidence_payloads(
        db, analysis_id=analysis_id, tenant_id=current.tenant.id
    )

    def _meets_min_percentile(payload: EvidencePayload) -> bool:
        if min_percentile is None:
            return True
        value = _max_percentile(payload)
        # `value == 0.0` is a real, meets-the-bar percentile, not "no percentile" — must not
        # fall through to the cold-start/absent case (a bare `value or ...` would do exactly
        # that, since `0.0` is falsy in Python).
        return value is not None and value >= min_percentile

    filtered = [
        p
        for p in all_evidence
        # `line_no` keys evidence to one raw log line — the Events tab's expanded row asks
        # "which evidence cites the line this event came from" (events carry `raw_line_no`,
        # payloads carry `contributing_line_numbers`; this is the same join the LOG-n citation
        # chips already make in the other direction).
        if (line_no is None or line_no in p.contributing_line_numbers)
        and (extractor is None or p.extractor == extractor)
        and (entity_type is None or p.entity.get("type") == entity_type)
        and (entity_value is None or p.entity.get("value") == entity_value)
        and _meets_min_percentile(p)
    ]
    total = len(filtered)
    truncated = total > limit
    page = filtered[:limit]

    with tenant_scope(db, current.tenant.id):
        incidents = (
            db.execute(select(Incident).where(Incident.analysis_id == analysis_id)).scalars().all()
        )
        incident_scopes = [
            (incident.id, *_incident_scope_and_window(db, incident)) for incident in incidents
        ]

    items = [
        evidence_payload_out(
            p,
            incident_ids=[
                incident_id
                for incident_id, scope, w_start, w_end in incident_scopes
                if _evidence_matches_incident(
                    p, entity_scope=scope, window_start=w_start, window_end=w_end
                )
            ],
        )
        for p in page
    ]
    return AnalysisEvidenceResponse(items=items, total=total, truncated=truncated)
