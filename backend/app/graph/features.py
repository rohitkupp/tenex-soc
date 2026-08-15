"""L5 graph anomaly features (docs/04 §L5) and infrastructure clustering (docs/05).

| Feature | Signal |
|---|---|
| `degree`, `weighted_degree` | hub entities |
| `fan_out` | one principal -> many rare domains |
| `shared_infra_overlap` | distinct principals converging on the same rare dst |
| `betweenness` | bridging otherwise separate clusters (lateral movement) |
| `clustering_coefficient` | tight suspicious cluster |
| `community_size`, `community_signal_density` | incident-worthiness |

"Score via robust z-score against the graph's own distribution" (docs/04) — every per-node
feature below is scored with `app.detection.features.robust_z`, the **canonical** shared
implementation (CLAUDE.md: "reusing robust_z from app/detection/features.py — do not fork it").
`community_size`/`community_signal_density` are computed directly on the incident
(`app.graph.incidents.IncidentCandidate`), not z-scored the same way — they feed the graph bonus
formula (`app.detection.fusion.apply_graph_bonus`) directly, per docs/05.

## Infrastructure clustering (docs/05 "Infrastructure clustering")

"Restrict the induced subgraph ... to `domain`/`dst_ip` nodes below a rarity threshold, and look
for nodes with >= 3 distinct `user` edges within the analysis window." That fixed count (3) is
docs/05's own literal construction rule for *which nodes are candidates*; this module also
z-scores `shared_infra_overlap` against the graph's population (docs/04's general L5 scoring
rule) so a candidate additionally has to be a real population-level outlier, not merely clear the
absolute floor, before it is promoted to a `graph.*` signal.

## Graph-layer signals

A node feature that clears its z-score threshold becomes a `graph.<feature>` signal —
`detector_layer="graph"`, matching `signals.detector_layer`'s documented enum
(`rule|signal|ml|graph`, docs/02) — so cross-layer corroboration
(`n_distinct_detector_layers`, `app.detection.fusion.apply_graph_bonus`) can include graph
evidence exactly like docs/05 describes ("a Sigma rule ... and a graph feature ... landing on the
same community").
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

import networkx as nx

from app.core.logging import get_logger
from app.detection.features import robust_z
from app.graph.builder import ENTITY_DOMAIN, ENTITY_DST_IP, ENTITY_USER, EntityKey

__all__ = [
    "GRAPH_FEATURE_NAMES",
    "GRAPH_Z_THRESHOLD",
    "INFRA_MIN_DISTINCT_USERS",
    "RARE_NODE_MAX_EVENT_COUNT",
    "GraphFeatureSignal",
    "NodeFeatures",
    "compute_node_features",
    "graph_signals_for_incident",
]

log = get_logger(__name__)

# Same threshold L2's volumetric burst uses (docs/04: "Flag |z| > 3.5") -- reused for every L5
# feature's own flagging rule rather than inventing a second "how extreme is extreme" number.
GRAPH_Z_THRESHOLD: Final[float] = 3.5

# docs/05's own literal number for infrastructure clustering: ">= 3 distinct user edges."
INFRA_MIN_DISTINCT_USERS: Final[int] = 3

# "Below a rarity threshold" (docs/05) -- a domain/dst_ip touched by at most this many events,
# file-wide, counts as rare enough to be an infra-clustering candidate. Mirrors
# `app.detection.signal.constants.RARITY_MAX_ORG_EVENT_COUNT` (10, "rare for a few-hundred-person
# org") -- re-derived independently here rather than imported across the `app/graph` <->
# `app/detection/signal` boundary, the same call `app/detection/ml/features.py` makes for its own
# analogous constant (see that module's docstring).
RARE_NODE_MAX_EVENT_COUNT: Final[int] = 10

GRAPH_FEATURE_NAMES: Final[tuple[str, ...]] = (
    "degree",
    "weighted_degree",
    "fan_out",
    "shared_infra_overlap",
    "betweenness",
    "clustering_coefficient",
)


@dataclass(frozen=True, slots=True)
class NodeFeatures:
    entity_key: EntityKey
    degree: float
    weighted_degree: float
    fan_out: float
    shared_infra_overlap: float
    betweenness: float
    clustering_coefficient: float
    z_scores: dict[str, float]


@dataclass(frozen=True, slots=True)
class GraphFeatureSignal:
    """A `graph.<feature>` finding -- shaped like `app.graph.incidents.SignalRef` so callers can
    fold it straight into an incident's signal list for fusion."""

    detector_key: str
    entity_type: str
    entity_value: str
    raw_score: float
    z_score: float
    explanation: dict[str, object]


def _simple_weighted(graph: nx.MultiGraph) -> nx.Graph:
    simple = nx.Graph()
    simple.add_nodes_from(graph.nodes(data=True))
    for u, v, data in graph.edges(data=True):
        if simple.has_edge(u, v):
            simple[u][v]["weight"] += data["weight"]
        else:
            simple.add_edge(u, v, weight=data["weight"])
    return simple


def _rare_neighbors(graph: nx.MultiGraph, node: EntityKey, *, of_type: str) -> set[EntityKey]:
    """Neighbors of `node` with type `of_type` whose own `event_count` is at or below the rarity
    threshold -- the "rare destination" half of fan_out/infra-clustering."""
    out: set[EntityKey] = set()
    if node not in graph:
        return out
    for nbr in graph.neighbors(node):
        ntype, _ = nbr
        if ntype != of_type:
            continue
        if graph.nodes[nbr].get("event_count", 0) <= RARE_NODE_MAX_EVENT_COUNT:
            out.add(nbr)
    return out


def _distinct_users_via(graph: nx.MultiGraph, node: EntityKey, *, hops: int) -> set[EntityKey]:
    """Distinct `user` nodes reachable from `node` within `hops` steps -- 1 hop for a `domain`
    node (direct `user --accessed--> domain` edges), 2 hops for a `dst_ip` node (`user
    --accessed--> domain --hosted_at--> dst_ip`, since users never touch a `dst_ip` directly)."""
    if node not in graph:
        return set()
    frontier = {node}
    seen = {node}
    users: set[EntityKey] = set()
    for _ in range(hops):
        next_frontier: set[EntityKey] = set()
        for n in frontier:
            for nbr in graph.neighbors(n):
                if nbr in seen:
                    continue
                seen.add(nbr)
                next_frontier.add(nbr)
                if nbr[0] == ENTITY_USER:
                    users.add(nbr)
        frontier = next_frontier
    return users


def compute_node_features(graph: nx.MultiGraph) -> dict[EntityKey, NodeFeatures]:
    """Every L5 feature for every node in `graph`, z-scored against `graph`'s own node
    population (docs/04: "the graph's own distribution") -- always the *full* per-analysis
    graph, never just an induced incident subgraph, so a node's anomaly score means the same
    thing regardless of which incident (if any) it ends up in.
    """
    if graph.number_of_nodes() == 0:
        return {}

    simple = _simple_weighted(graph)
    betweenness = nx.betweenness_centrality(simple, weight="weight")
    clustering = nx.clustering(simple, weight="weight")

    raw: dict[EntityKey, dict[str, float]] = {}
    for node in graph.nodes:
        degree = float(simple.degree(node))
        weighted_degree = float(sum(data["weight"] for _, _, data in graph.edges(node, data=True)))
        fan_out = float(
            len(_rare_neighbors(graph, node, of_type=ENTITY_DOMAIN))
            + len(_rare_neighbors(graph, node, of_type=ENTITY_DST_IP))
            if node[0] == ENTITY_USER
            else 0.0
        )
        shared_infra_overlap = 0.0
        if (
            node[0] in (ENTITY_DOMAIN, ENTITY_DST_IP)
            and graph.nodes[node].get("event_count", 0) <= RARE_NODE_MAX_EVENT_COUNT
        ):
            hops = 1 if node[0] == ENTITY_DOMAIN else 2
            shared_infra_overlap = float(len(_distinct_users_via(graph, node, hops=hops)))
        raw[node] = {
            "degree": degree,
            "weighted_degree": weighted_degree,
            "fan_out": fan_out,
            "shared_infra_overlap": shared_infra_overlap,
            "betweenness": float(betweenness.get(node, 0.0)),
            "clustering_coefficient": float(clustering.get(node, 0.0)),
        }

    # z-score each feature against its own reference population: fan_out only among `user`
    # nodes, shared_infra_overlap only among `domain`/`dst_ip` nodes (z-scoring either against
    # every node type would compare a fundamentally different-scale quantity, e.g. a `country`
    # node's fan_out, which is always 0 by construction, diluting the population); the four
    # generic topology features (degree, weighted_degree, betweenness, clustering_coefficient)
    # are meaningful for every node type, so they are scored against the whole graph.
    populations: dict[str, list[EntityKey]] = {
        "degree": list(graph.nodes),
        "weighted_degree": list(graph.nodes),
        "betweenness": list(graph.nodes),
        "clustering_coefficient": list(graph.nodes),
        "fan_out": [n for n in graph.nodes if n[0] == ENTITY_USER],
        "shared_infra_overlap": [n for n in graph.nodes if n[0] in (ENTITY_DOMAIN, ENTITY_DST_IP)],
    }
    z_by_node: dict[EntityKey, dict[str, float]] = {n: {} for n in graph.nodes}
    for feature, population in populations.items():
        values = [raw[n][feature] for n in population]
        if not values:
            continue
        for n in population:
            z_by_node[n][feature] = robust_z(values, raw[n][feature])

    out: dict[EntityKey, NodeFeatures] = {}
    for node in graph.nodes:
        r = raw[node]
        out[node] = NodeFeatures(
            entity_key=node,
            degree=r["degree"],
            weighted_degree=r["weighted_degree"],
            fan_out=r["fan_out"],
            shared_infra_overlap=r["shared_infra_overlap"],
            betweenness=r["betweenness"],
            clustering_coefficient=r["clustering_coefficient"],
            z_scores=z_by_node[node],
        )
    return out


def graph_signals_for_incident(
    entity_keys: Sequence[EntityKey],
    node_features: dict[EntityKey, NodeFeatures],
) -> list[GraphFeatureSignal]:
    """`graph.<feature>` signals for the entities in one incident. A feature fires when its
    z-score against the full graph clears `GRAPH_Z_THRESHOLD`; `shared_infra_overlap` also
    requires docs/05's own literal floor (`>= 3` distinct users) before it is even a candidate --
    see module docstring.
    """
    signals: list[GraphFeatureSignal] = []
    for key in entity_keys:
        nf = node_features.get(key)
        if nf is None:
            continue
        etype, evalue = key
        for feature in GRAPH_FEATURE_NAMES:
            z = nf.z_scores.get(feature)
            if z is None or z != z or abs(z) <= GRAPH_Z_THRESHOLD:  # NaN-safe
                continue
            raw_value = getattr(nf, feature)
            if feature == "shared_infra_overlap" and raw_value < INFRA_MIN_DISTINCT_USERS:
                continue
            signals.append(
                GraphFeatureSignal(
                    detector_key=f"graph.{feature}",
                    entity_type=etype,
                    entity_value=evalue,
                    raw_score=raw_value,
                    z_score=z,
                    explanation={
                        "feature": feature,
                        "value": raw_value,
                        "z_score": z,
                        "threshold": GRAPH_Z_THRESHOLD,
                    },
                )
            )
    return signals
