"""The incident *read* surface — docs/09-API-CONTRACT.md.

    GET /api/analyses/{analysis_id}/incidents   the queue
    GET /api/incidents/{incident_id}            full case file (minus timeline/plan, below)
    GET /api/incidents/{incident_id}/graph      `{nodes: [], edges: []}`
    GET /api/incidents/{incident_id}/timeline   docs/05's deterministic phase list

Why this is not in `app.api.incidents`: that module's docstring scopes itself to the *verdict*
slice and explicitly says the composite detail endpoint "spans four milestones' data ... and is
not this module's to build whole". This is that composite. Both routers mount at `/api`, so the
split is invisible over the wire — `/api/incidents/{id}` and `/api/incidents/{id}/verdict` are
neighbours in `/api/docs` regardless of which file defines them.

**Tenant isolation.** `Incident` and `Signal` carry `TenantScopedMixin`, so `tenant_scope`
filters them structurally (`app.models.base`). `Entity` and `EntityEdge` do not — docs/02 scopes
them transitively through `analysis_id`, and every query below reaches them only via an
`analysis_id` read off an incident that `tenant_scope` already proved belongs to the caller. A
cross-tenant id 404s; it never leaks a row.

**Ordering.** The queue is `fused_score DESC, id DESC` — the order an analyst works the queue in,
and a strict total order (`id` is unique), so the keyset cursor below can never skip or repeat a
row. Same rule as `app.api.events`: keyset, never `OFFSET`.
"""

from __future__ import annotations

import base64
import binascii
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, cast, or_, select
from sqlalchemy.dialects.postgresql import REAL
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.errors import ApiError
from app.core.security import CurrentUser, require_user
from app.graph.timeline import build_timeline
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.entity import Entity
from app.models.entity_edge import EntityEdge
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.triage_verdict import TriageVerdict
from app.schemas.agent import TriageVerdictResponse
from app.schemas.incident import (
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
        items.append(
            IncidentListItem(
                id=inc.id,
                title=inc.title,
                severity=inc.severity,
                fused_score=inc.fused_score,
                disposition=disposition,
                citation_valid=citation_valid,
                mitre_techniques=_technique_ids(verdict),
                entity_count=len(inc.entity_ids),
                signal_count=len(inc.signal_ids),
                recurrence_of=inc.recurrence_of,
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
        verdict = _latest_verdicts(db, [incident.id]).get(incident.id)

    # A recurrence inherits its parent's verdict (docs/05) — surface the parent's rather than
    # showing an empty case file for an incident the analyst has, in substance, already seen.
    if verdict is None and incident.recurrence_of is not None:
        with tenant_scope(db, current.tenant.id):
            parent = db.execute(
                select(Incident).where(Incident.id == incident.recurrence_of)
            ).scalar_one_or_none()
            if parent is not None:
                verdict = _latest_verdicts(db, [parent.id]).get(parent.id)

    return IncidentDetail(
        id=incident.id,
        analysis_id=incident.analysis_id,
        title=incident.title,
        severity=incident.severity,
        fused_score=incident.fused_score,
        status=incident.status,
        entity_ids=list(incident.entity_ids),
        signal_ids=list(incident.signal_ids),
        recurrence_of=incident.recurrence_of,
        recurrence_similarity=incident.recurrence_similarity,
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
    return TimelineResponse(
        phases=[
            TimelinePhaseOut(
                ts=p.ts,
                tactic=p.tactic,
                tactic_is_placeholder=p.tactic_is_placeholder,
                event_ids=p.event_ids,
                summary=p.summary,
                detector_key=p.detector_key,
                entity_type=p.entity_type,
                entity_value=p.entity_value,
            )
            for p in phases
        ]
    )


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
