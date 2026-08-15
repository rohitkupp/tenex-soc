"""Unit tests for `app.graph.features` (docs/04 §L5, docs/05 "Infrastructure clustering").
Pure `GraphEvent` fixtures; no DB."""

from __future__ import annotations

from datetime import UTC, datetime

from app.graph.builder import ENTITY_DOMAIN, ENTITY_USER, GraphEvent, build_entity_graph
from app.graph.features import (
    INFRA_MIN_DISTINCT_USERS,
    compute_node_features,
    graph_signals_for_incident,
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _user_domain_event(event_id: int, user: str, domain: str) -> GraphEvent:
    return GraphEvent(
        event_id=event_id,
        ts=_T0,
        principal=user,
        src_ip=f"10.0.0.{event_id}",
        dst_ip=None,
        domain=domain,
        asn=None,
        country=None,
    )


def _build_shared_infra_graph(n_users: int) -> object:
    """`n_users` distinct users, each hitting the SAME rare domain once, plus a population of
    unrelated normal traffic (each on its own unique, also-rare-but-not-shared domain) so the
    shared domain's fan-in is a genuine population outlier. One event per (user, domain) pair
    keeps every domain's own `event_count` well under `RARE_NODE_MAX_EVENT_COUNT` (10) — a
    domain hit by enough users to be "shared" must still read as *rare* by volume, which is the
    whole point of docs/05's infrastructure-clustering shape (many distinct principals, each
    making only a handful of requests, converging on one low-volume destination)."""
    events: list[GraphEvent] = []
    eid = 0
    for u in range(n_users):
        eid += 1
        events.append(_user_domain_event(eid, f"user{u}@corp.example", "rare-c2.example.com"))
    for u in range(30):
        eid += 1
        events.append(_user_domain_event(eid, f"bg{u}@corp.example", f"unique{u}.example.com"))
    return build_entity_graph(events, prune_below_event_count=1).graph


def test_degree_and_weighted_degree_are_positive_for_connected_nodes() -> None:
    graph = _build_shared_infra_graph(n_users=1)
    features = compute_node_features(graph)
    node = features[(ENTITY_USER, "user0@corp.example")]
    assert node.degree >= 1
    assert node.weighted_degree > 0


def test_shared_infra_overlap_flags_a_rare_domain_with_many_distinct_users() -> None:
    graph = _build_shared_infra_graph(n_users=6)
    features = compute_node_features(graph)
    node = features[(ENTITY_DOMAIN, "rare-c2.example.com")]
    assert node.shared_infra_overlap == 6
    assert node.shared_infra_overlap >= INFRA_MIN_DISTINCT_USERS
    # z-scored against the graph's own population of domain/dst_ip nodes -- 6 distinct users is
    # a clear outlier against 30 background domains each with exactly 1 user.
    assert node.z_scores["shared_infra_overlap"] > 3.5


def test_shared_infra_overlap_is_one_for_a_domain_touched_by_a_single_user() -> None:
    graph = _build_shared_infra_graph(n_users=1)
    features = compute_node_features(graph)
    node = features[(ENTITY_DOMAIN, "unique5.example.com")]
    assert node.shared_infra_overlap == 1


def test_graph_signals_for_incident_fires_on_infra_clustering() -> None:
    graph = _build_shared_infra_graph(n_users=6)
    features = compute_node_features(graph)
    signals = graph_signals_for_incident(list(graph.nodes), features)
    infra_signals = [s for s in signals if s.detector_key == "graph.shared_infra_overlap"]
    assert any(s.entity_value == "rare-c2.example.com" for s in infra_signals)


def test_graph_signals_do_not_fire_below_the_infra_floor_even_if_z_scored_high() -> None:
    """A domain with 2 distinct users never fires `shared_infra_overlap`, regardless of z-score,
    because docs/05's own literal floor is `>= 3` distinct users."""
    graph = _build_shared_infra_graph(n_users=2)
    features = compute_node_features(graph)
    signals = graph_signals_for_incident(list(graph.nodes), features)
    infra_signals = [s for s in signals if s.detector_key == "graph.shared_infra_overlap"]
    assert infra_signals == []


def test_empty_graph_produces_no_features() -> None:
    graph = build_entity_graph([]).graph
    assert compute_node_features(graph) == {}
