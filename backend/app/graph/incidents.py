"""Incident formation (docs/05 "Incident formation"), verbatim:

1. Mark every entity carrying at least one signal as a **seed**.
2. Expand each seed to its 1-hop neighborhood.
3. Induce a subgraph over the union of seeds and their neighborhoods.
4. Run **Louvain community detection** on the induced subgraph.
5. Each community containing >= 1 seed becomes one incident.
6. Merge communities sharing >= 50% of their seed entities.

Rationale (docs/05): "alerting per signal produces alert fatigue; alerting per community produces
stories." This module turns a flat signal list plus the entity graph (`app.graph.builder`) into
that smaller set of communities.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

import networkx as nx
from community import best_partition  # python-louvain

from app.core.logging import get_logger
from app.graph.builder import EntityKey

__all__ = [
    "DEFAULT_SEED_MERGE_THRESHOLD",
    "IncidentCandidate",
    "SignalRef",
    "form_incidents",
]

log = get_logger(__name__)

# docs/05: "Merge communities sharing >= 50% of their seed entities." Read as: the overlap is at
# least half of the *smaller* of the two communities' own seed sets -- symmetric, and the natural
# reading of "sharing X% of their seeds" when the two sets can have different sizes (a strict
# Jaccard union-based ratio would require *more* absolute overlap to clear the same 50% bar
# whenever the sets differ in size, which is not what "sharing half of their seeds" suggests).
DEFAULT_SEED_MERGE_THRESHOLD = 0.5

# Louvain's own stochastic tie-breaking (`python-louvain`'s docs note the algorithm's node
# visitation order affects the exact partition on graphs with ties) -- fixed so the same graph
# always yields the same communities, load-bearing for the eval harness's `incident_recall`/
# `fragmentation` metrics and for deterministic titling.
LOUVAIN_RANDOM_STATE = 42


@dataclass(frozen=True, slots=True)
class SignalRef:
    """The subset of `signals` (docs/02) incident formation and fusion need. Detector-layer-
    agnostic — L1/L2/L3/L5 signals are all the same shape by the time they reach this module."""

    signal_id: int
    detector_key: str
    detector_layer: str
    confidence: float
    entity_type: str
    entity_value: str
    mitre_technique: str | None
    evidence_event_ids: tuple[int, ...]
    window_start: object = None
    window_end: object = None


@dataclass(slots=True)
class IncidentCandidate:
    """One post-merge incident: a set of entities (the union of every merged community's nodes)
    and the signals whose entity falls inside it. `seed_entity_keys` is kept separately from
    `entity_keys` because `community_signal_density` (docs/04 §L5) is defined against it."""

    entity_keys: frozenset[EntityKey]
    seed_entity_keys: frozenset[EntityKey]
    signals: list[SignalRef] = field(default_factory=list)
    source_community_ids: frozenset[int] = frozenset()

    @property
    def community_size(self) -> int:
        return len(self.entity_keys)

    @property
    def community_signal_density(self) -> float:
        """Fraction of this incident's entities that are seeds (carry >= 1 signal directly) --
        docs/04 §L5's `community_signal_density`: how concentrated the evidence is within the
        community, not diluted across a large 1-hop halo of uninvolved entities."""
        if not self.entity_keys:
            return 0.0
        return len(self.seed_entity_keys) / len(self.entity_keys)

    @property
    def n_distinct_detector_layers(self) -> int:
        return len({s.detector_layer for s in self.signals})


def _mark_seeds(
    graph: nx.MultiGraph, signals: Sequence[SignalRef]
) -> dict[EntityKey, list[SignalRef]]:
    seeds: dict[EntityKey, list[SignalRef]] = {}
    skipped = 0
    for s in signals:
        key: EntityKey = (s.entity_type, s.entity_value)
        if key not in graph.nodes:
            skipped += 1
            continue
        seeds.setdefault(key, []).append(s)
    if skipped:
        log.warning("incidents.signals_without_graph_node", n_skipped=skipped)
    return seeds


def _one_hop_expand(graph: nx.MultiGraph, seed_keys: Sequence[EntityKey]) -> set[EntityKey]:
    expanded: set[EntityKey] = set(seed_keys)
    for key in seed_keys:
        if key in graph:
            expanded.update(graph.neighbors(key))
    return expanded


def _to_simple_weighted(graph: nx.MultiGraph) -> nx.Graph:
    """Collapse a `MultiGraph`'s parallel edges (distinct relations between the same pair, e.g. a
    user could in principle both `accessed` and be `from` the same node key in pathological data)
    into one simple `Graph` with summed weight -- what `best_partition` (Louvain) needs; it does
    not accept a `MultiGraph`."""
    simple = nx.Graph()
    simple.add_nodes_from(graph.nodes(data=True))
    for u, v, data in graph.edges(data=True):
        if simple.has_edge(u, v):
            simple[u][v]["weight"] += data["weight"]
        else:
            simple.add_edge(u, v, weight=data["weight"])
    return simple


def _merge_by_seed_overlap(
    communities: list[tuple[frozenset[EntityKey], frozenset[EntityKey], frozenset[int]]],
    *,
    threshold: float,
) -> list[tuple[frozenset[EntityKey], frozenset[EntityKey], frozenset[int]]]:
    """Union-find merge of `(entities, seeds, community_ids)` triples whose seed sets overlap by
    >= `threshold` of the smaller set -- transitive (A merges with B, B merges with C -> A, B, C
    all end up in one incident even if A and C alone don't clear the bar directly)."""
    n = len(communities)
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[ri] = rj

    for i in range(n):
        for j in range(i + 1, n):
            seeds_i, seeds_j = communities[i][1], communities[j][1]
            if not seeds_i or not seeds_j:
                continue
            overlap = len(seeds_i & seeds_j)
            smaller = min(len(seeds_i), len(seeds_j))
            if smaller and overlap / smaller >= threshold:
                union(i, j)

    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)

    merged: list[tuple[frozenset[EntityKey], frozenset[EntityKey], frozenset[int]]] = []
    for members in groups.values():
        entities: set[EntityKey] = set()
        seeds: set[EntityKey] = set()
        comm_ids: set[int] = set()
        for idx in members:
            entities |= communities[idx][0]
            seeds |= communities[idx][1]
            comm_ids |= communities[idx][2]
        merged.append((frozenset(entities), frozenset(seeds), frozenset(comm_ids)))
    return merged


def form_incidents(
    graph: nx.MultiGraph,
    signals: Sequence[SignalRef],
    *,
    seed_merge_threshold: float = DEFAULT_SEED_MERGE_THRESHOLD,
) -> list[IncidentCandidate]:
    """docs/05 "Incident formation", steps 1-6, in order. Returns one `IncidentCandidate` per
    final (post-merge) incident; an analysis with no signals produces no incidents (there are no
    seeds to expand from)."""
    seeds_by_entity = _mark_seeds(graph, signals)
    if not seeds_by_entity:
        return []

    seed_keys = list(seeds_by_entity)
    induced_nodes = _one_hop_expand(graph, seed_keys)
    induced = graph.subgraph(induced_nodes)
    simple = _to_simple_weighted(nx.MultiGraph(induced))

    partition: dict[EntityKey, int] = best_partition(
        simple, weight="weight", random_state=LOUVAIN_RANDOM_STATE
    )

    by_community: dict[int, set[EntityKey]] = {}
    for node, community_id in partition.items():
        by_community.setdefault(community_id, set()).add(node)

    candidate_communities: list[
        tuple[frozenset[EntityKey], frozenset[EntityKey], frozenset[int]]
    ] = []
    for community_id, nodes in by_community.items():
        community_seeds = nodes & seeds_by_entity.keys()
        if not community_seeds:
            continue  # docs/05 step 5: only communities with >= 1 seed become incidents
        candidate_communities.append(
            (frozenset(nodes), frozenset(community_seeds), frozenset({community_id}))
        )

    merged = _merge_by_seed_overlap(candidate_communities, threshold=seed_merge_threshold)

    incidents: list[IncidentCandidate] = []
    for entities, merged_seeds, comm_ids in merged:
        incident_signals: list[SignalRef] = []
        for seed_key in merged_seeds:
            incident_signals.extend(seeds_by_entity[seed_key])
        incidents.append(
            IncidentCandidate(
                entity_keys=entities,
                seed_entity_keys=merged_seeds,
                signals=incident_signals,
                source_community_ids=comm_ids,
            )
        )

    log.info(
        "incidents.formed",
        n_seed_entities=len(seeds_by_entity),
        n_communities_pre_merge=len(candidate_communities),
        n_incidents=len(incidents),
    )
    return incidents
