"""Entity graph construction (docs/05-CORRELATION.md "Graph construction").

`networkx.MultiGraph`, built per analysis. This module owns two independent halves:

1. A **pure** graph-construction function, `build_entity_graph`, that turns a plain sequence of
   `GraphEvent` rows into an in-memory `networkx.MultiGraph` plus a pruning report. It knows
   nothing about Postgres and is what `tests/test_graph_builder.py` exercises directly.
2. A thin Postgres adapter (`fetch_graph_events` / `persist_entity_graph`) that reads
   `events` and writes `entities`/`entity_edges` (docs/02) for a real analysis. Kept separate so
   the construction logic never needs a live database to test.

## Nodes and edges (docs/05, verbatim)

Nodes: `user`, `src_ip`, `domain`, `dst_ip`, `asn`, `country` — proxy-only, no `session` type
(the old multi-source design's node type; ZScaler-only has no session log to key one on).

Edges, derived from co-occurrence **within a single event**:
`user --accessed--> domain`, `user --from--> src_ip`, `src_ip --resolves_to--> asn`,
`domain --hosted_at--> dst_ip`, `src_ip --located_in--> country`. `country`/`asn` come from
IP geolocation on `src_ip` (MaxMind GeoLite2 via `app.enrichment`), not an identity event — see
docs/05 for why (Okta is gone).

Edge `weight` is `log1p(event_count)` ("log-scaled" per docs/05); `event_count` (the raw count)
is kept alongside it so a consumer can recover the untransformed number. Singleton edges — an
edge supported by fewer than `prune_below_event_count` events — are dropped from the graph and
recorded in `GraphBuildResult.pruned_edges` rather than silently discarded, per docs/05's
"record what was pruned." Nodes are never pruned, only edges: an entity that appears in the
analysis keeps its node (and its `entities` row) even if every edge touching it happened to fall
below the prune threshold — the entity itself is still real evidence.
"""

from __future__ import annotations

import math
import uuid
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final

import networkx as nx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.entity import Entity
from app.models.entity_edge import EntityEdge
from app.models.event import Event

__all__ = [
    "DEFAULT_PRUNE_BELOW_EVENT_COUNT",
    "ENTITY_ASN",
    "ENTITY_COUNTRY",
    "ENTITY_DOMAIN",
    "ENTITY_DST_IP",
    "ENTITY_SRC_IP",
    "ENTITY_USER",
    "REL_ACCESSED",
    "REL_FROM",
    "REL_HOSTED_AT",
    "REL_LOCATED_IN",
    "REL_RESOLVES_TO",
    "EntityKey",
    "GraphBuildResult",
    "GraphEvent",
    "PrunedEdge",
    "build_entity_graph",
    "fetch_graph_events",
    "persist_entity_graph",
]

log = get_logger(__name__)

# ---------------------------------------------------------------------------- node/relation vocab

ENTITY_USER: Final[str] = "user"
ENTITY_SRC_IP: Final[str] = "src_ip"
ENTITY_DOMAIN: Final[str] = "domain"
ENTITY_DST_IP: Final[str] = "dst_ip"
ENTITY_ASN: Final[str] = "asn"
ENTITY_COUNTRY: Final[str] = "country"

REL_ACCESSED: Final[str] = "accessed"  # user -> domain
REL_FROM: Final[str] = "from"  # user -> src_ip
REL_RESOLVES_TO: Final[str] = "resolves_to"  # src_ip -> asn
REL_HOSTED_AT: Final[str] = "hosted_at"  # domain -> dst_ip
REL_LOCATED_IN: Final[str] = "located_in"  # src_ip -> country

# An edge backed by fewer than this many co-occurring events is a "singleton" and gets pruned
# (docs/05: "Prune singleton edges below a configurable threshold to keep the graph tractable").
# 2 is the natural reading of "singleton": an edge seen exactly once carries almost no
# correlation signal (could be one stray request) and the induced-subgraph/Louvain step below
# is O(edges) sensitive to a long tail of these across a large analysis.
DEFAULT_PRUNE_BELOW_EVENT_COUNT: Final[int] = 2

# `(entity_type, entity_value)` — the node key used throughout `app.graph`, matching
# `signals.entity_type`/`entity_value` and `entities.type`/`value` (docs/02) exactly, so a
# signal's entity reference is always directly a graph node key with no translation.
EntityKey = tuple[str, str]


# ---------------------------------------------------------------------------- input row


@dataclass(frozen=True, slots=True)
class GraphEvent:
    """One event's worth of graph-relevant fields — deliberately narrower than
    `app.models.event.Event` or `app.detection.ml.events.MLEvent`: this module only ever reads
    the six columns below. Carries `dst_ip` (which `MLEvent` does not — see that module's own
    docstring on why `app/detection/ml` is out of scope to extend) and `asn`/`country` off
    `events.enrichment` (docs/02), the same enrichment payload `app.enrichment.enrich_event`
    produces at ingestion time.
    """

    event_id: int
    ts: datetime
    principal: str | None
    src_ip: str | None
    dst_ip: str | None
    domain: str | None  # registrable domain, already resolved by the caller
    asn: int | None
    country: str | None


# ---------------------------------------------------------------------------- construction


@dataclass(frozen=True, slots=True)
class PrunedEdge:
    src: EntityKey
    dst: EntityKey
    relation: str
    event_count: int


@dataclass(slots=True)
class _NodeAccum:
    event_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def observe(self, ts: datetime) -> None:
        self.event_count += 1
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts


@dataclass(slots=True)
class GraphBuildResult:
    graph: nx.MultiGraph
    prune_below_event_count: int
    pruned_edges: list[PrunedEdge] = field(default_factory=list)

    @property
    def n_nodes(self) -> int:
        return int(self.graph.number_of_nodes())

    @property
    def n_edges(self) -> int:
        return int(self.graph.number_of_edges())


def _emit(
    edge_counts: dict[tuple[EntityKey, EntityKey, str], int],
    src: EntityKey | None,
    dst: EntityKey | None,
    relation: str,
) -> None:
    if src is None or dst is None:
        return
    edge_counts[(src, dst, relation)] += 1


def build_entity_graph(
    events: Sequence[GraphEvent],
    *,
    prune_below_event_count: int = DEFAULT_PRUNE_BELOW_EVENT_COUNT,
) -> GraphBuildResult:
    """Build the per-analysis entity `MultiGraph` from a flat event sequence (docs/05).

    Pure function — no I/O. `events` need not be time-ordered; `first_seen`/`last_seen` per node
    are computed here regardless of input order.
    """
    node_accum: dict[EntityKey, _NodeAccum] = defaultdict(_NodeAccum)
    edge_counts: dict[tuple[EntityKey, EntityKey, str], int] = defaultdict(int)

    for e in events:
        user_key: EntityKey | None = (ENTITY_USER, e.principal) if e.principal else None
        src_ip_key: EntityKey | None = (ENTITY_SRC_IP, e.src_ip) if e.src_ip else None
        domain_key: EntityKey | None = (ENTITY_DOMAIN, e.domain) if e.domain else None
        dst_ip_key: EntityKey | None = (ENTITY_DST_IP, e.dst_ip) if e.dst_ip else None
        asn_key: EntityKey | None = (ENTITY_ASN, str(e.asn)) if e.asn is not None else None
        country_key: EntityKey | None = (ENTITY_COUNTRY, e.country) if e.country else None

        for key in (user_key, src_ip_key, domain_key, dst_ip_key, asn_key, country_key):
            if key is not None:
                node_accum[key].observe(e.ts)

        _emit(edge_counts, user_key, domain_key, REL_ACCESSED)
        _emit(edge_counts, user_key, src_ip_key, REL_FROM)
        _emit(edge_counts, src_ip_key, asn_key, REL_RESOLVES_TO)
        _emit(edge_counts, domain_key, dst_ip_key, REL_HOSTED_AT)
        _emit(edge_counts, src_ip_key, country_key, REL_LOCATED_IN)

    graph: nx.MultiGraph = nx.MultiGraph()
    for (etype, evalue), accum in node_accum.items():
        graph.add_node(
            (etype, evalue),
            type=etype,
            value=evalue,
            event_count=accum.event_count,
            first_seen=accum.first_seen,
            last_seen=accum.last_seen,
        )

    pruned: list[PrunedEdge] = []
    for (src, dst, relation), count in edge_counts.items():
        if count < prune_below_event_count:
            pruned.append(PrunedEdge(src=src, dst=dst, relation=relation, event_count=count))
            continue
        graph.add_edge(
            src, dst, key=relation, relation=relation, weight=math.log1p(count), event_count=count
        )

    log.info(
        "graph.built",
        n_nodes=graph.number_of_nodes(),
        n_edges=graph.number_of_edges(),
        n_pruned=len(pruned),
        prune_below_event_count=prune_below_event_count,
    )
    return GraphBuildResult(
        graph=graph, prune_below_event_count=prune_below_event_count, pruned_edges=pruned
    )


# ---------------------------------------------------------------------------- Postgres adapter


def fetch_graph_events(session: Session, analysis_id: uuid.UUID) -> list[GraphEvent]:
    """All events for one analysis, projected to `GraphEvent` rows. `session` must already be
    tenant-bound (`app.models.base.tenant_scope`/`tenant_session`) — same convention as
    `app.detection.signal.events_dao.fetch_event_rows`.

    `domain` prefers the enriched registrable domain (`enrichment->'domain'->>'registrable_domain'`,
    the same field `app.detection.ml.events` builds its graph-adjacent features from) and falls
    back to the raw hostname when enrichment did not run or found nothing — a domain node should
    still exist even for an unenriched event, just keyed on the literal hostname it saw.
    `asn`/`country` come from `enrichment->'src_ip'` (docs/05: "`country` comes from IP
    geolocation on `src_ip`"), `None` when absent.
    """
    stmt = select(
        Event.id,
        Event.ts,
        Event.principal,
        Event.src_ip,
        Event.dst_ip,
        Event.domain,
        Event.enrichment,
    ).where(Event.analysis_id == analysis_id)

    rows: list[GraphEvent] = []
    for event_id, ts, principal, src_ip, dst_ip, domain, enrichment in session.execute(stmt):
        src_enrichment = (enrichment or {}).get("src_ip") or {}
        domain_enrichment = (enrichment or {}).get("domain") or {}
        registrable = domain_enrichment.get("registrable_domain") or domain
        rows.append(
            GraphEvent(
                event_id=event_id,
                ts=ts,
                principal=principal,
                src_ip=str(src_ip) if src_ip is not None else None,
                dst_ip=str(dst_ip) if dst_ip is not None else None,
                domain=registrable,
                asn=src_enrichment.get("asn"),
                country=src_enrichment.get("country"),
            )
        )
    return rows


def persist_entity_graph(
    session: Session, *, analysis_id: uuid.UUID, result: GraphBuildResult
) -> dict[EntityKey, int]:
    """Write every surviving node/edge in `result.graph` to `entities`/`entity_edges` (docs/02),
    returning `{(type, value): entities.id}` for callers (incident formation, seed marking) that
    need to go from a graph node key to its persisted row id.

    Idempotent per `(analysis_id, type, value)` — `entities`' own unique constraint — so re-running
    against an analysis that already has rows updates them in place rather than duplicating.
    """
    existing = {
        (row.type, row.value): row
        for row in session.execute(
            select(Entity).where(Entity.analysis_id == analysis_id)
        ).scalars()
    }

    key_to_id: dict[EntityKey, int] = {}
    for key, data in result.graph.nodes(data=True):
        etype, evalue = key
        row = existing.get(key)
        if row is None:
            row = Entity(
                analysis_id=analysis_id,
                type=etype,
                value=evalue,
                first_seen=data.get("first_seen"),
                last_seen=data.get("last_seen"),
                event_count=data.get("event_count", 0),
            )
            session.add(row)
            session.flush()
            existing[key] = row
        else:
            row.first_seen = data.get("first_seen")
            row.last_seen = data.get("last_seen")
            row.event_count = data.get("event_count", 0)
        key_to_id[key] = row.id

    # Edges are not upserted individually (no natural unique key to match against short of
    # `(analysis_id, src, dst, relation)`, which docs/02's `entity_edges` does not declare as a
    # constraint) — a re-run against the same analysis_id replaces them wholesale, which is
    # simpler and correct since this function always receives the *complete* current graph, not
    # an incremental delta.
    session.execute(delete(EntityEdge).where(EntityEdge.analysis_id == analysis_id))
    for u, v, data in result.graph.edges(data=True):
        session.add(
            EntityEdge(
                analysis_id=analysis_id,
                src_entity_id=key_to_id[u],
                dst_entity_id=key_to_id[v],
                relation=data["relation"],
                weight=data["weight"],
                event_count=data["event_count"],
            )
        )
    session.flush()
    log.info(
        "graph.persisted",
        analysis_id=str(analysis_id),
        n_entities=len(key_to_id),
        n_edges=result.n_edges,
    )
    return key_to_id
