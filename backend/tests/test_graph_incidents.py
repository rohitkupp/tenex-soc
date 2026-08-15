"""Unit tests for `app.graph.incidents.form_incidents` (docs/05 "Incident formation").
Pure `GraphEvent`/`SignalRef` fixtures; no DB."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.graph.builder import ENTITY_DOMAIN, ENTITY_USER, GraphEvent, build_entity_graph
from app.graph.incidents import SignalRef, form_incidents

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _signal(
    signal_id: int,
    *,
    detector_key: str = "signal.beaconing",
    detector_layer: str = "signal",
    entity_type: str = ENTITY_USER,
    entity_value: str = "alice@corp.example",
    confidence: float = 0.9,
    mitre_technique: str | None = "T1071.001",
) -> SignalRef:
    return SignalRef(
        signal_id=signal_id,
        detector_key=detector_key,
        detector_layer=detector_layer,
        confidence=confidence,
        entity_type=entity_type,
        entity_value=entity_value,
        mitre_technique=mitre_technique,
        evidence_event_ids=(signal_id,),
        window_start=_T0,
        window_end=_T0,
    )


def test_no_signals_produces_no_incidents() -> None:
    events = [
        GraphEvent(
            event_id=1,
            ts=_T0,
            principal="alice@corp.example",
            src_ip="10.0.0.1",
            dst_ip=None,
            domain="example.com",
            asn=None,
            country=None,
        )
    ]
    graph = build_entity_graph(events, prune_below_event_count=1).graph
    assert form_incidents(graph, []) == []


def test_a_seeded_entity_and_its_one_hop_neighbor_form_one_incident() -> None:
    """One user, accessing one domain, with a signal on the user -- the incident should include
    both the seed (user) and its 1-hop neighbor (domain)."""
    events = [
        GraphEvent(
            event_id=i,
            ts=_T0,
            principal="alice@corp.example",
            src_ip="10.0.0.1",
            dst_ip=None,
            domain="evil.example.com",
            asn=None,
            country=None,
        )
        for i in range(3)
    ]
    graph = build_entity_graph(events, prune_below_event_count=1).graph
    signals = [_signal(1)]
    incidents = form_incidents(graph, signals)
    assert len(incidents) == 1
    assert (ENTITY_USER, "alice@corp.example") in incidents[0].entity_keys
    assert (ENTITY_DOMAIN, "evil.example.com") in incidents[0].entity_keys
    assert incidents[0].seed_entity_keys == frozenset({(ENTITY_USER, "alice@corp.example")})


def test_two_unrelated_seeds_form_two_separate_incidents() -> None:
    events = [
        GraphEvent(
            event_id=1,
            ts=_T0,
            principal="alice@corp.example",
            src_ip="10.0.0.1",
            dst_ip=None,
            domain="a.example.com",
            asn=None,
            country=None,
        ),
        GraphEvent(
            event_id=1,
            ts=_T0,
            principal="alice@corp.example",
            src_ip="10.0.0.1",
            dst_ip=None,
            domain="a.example.com",
            asn=None,
            country=None,
        ),
        GraphEvent(
            event_id=2,
            ts=_T0,
            principal="bob@corp.example",
            src_ip="10.0.0.2",
            dst_ip=None,
            domain="b.example.com",
            asn=None,
            country=None,
        ),
        GraphEvent(
            event_id=2,
            ts=_T0,
            principal="bob@corp.example",
            src_ip="10.0.0.2",
            dst_ip=None,
            domain="b.example.com",
            asn=None,
            country=None,
        ),
    ]
    graph = build_entity_graph(events, prune_below_event_count=1).graph
    signals = [
        _signal(1, entity_value="alice@corp.example"),
        _signal(2, entity_value="bob@corp.example"),
    ]
    incidents = form_incidents(graph, signals)
    assert len(incidents) == 2
    seed_sets = {inc.seed_entity_keys for inc in incidents}
    assert seed_sets == {
        frozenset({(ENTITY_USER, "alice@corp.example")}),
        frozenset({(ENTITY_USER, "bob@corp.example")}),
    }


def test_signal_on_entity_absent_from_graph_is_skipped_not_fatal() -> None:
    events = [
        GraphEvent(
            event_id=1,
            ts=_T0,
            principal="alice@corp.example",
            src_ip="10.0.0.1",
            dst_ip=None,
            domain="a.example.com",
            asn=None,
            country=None,
        )
    ]
    graph = build_entity_graph(events, prune_below_event_count=1).graph
    signals = [_signal(1, entity_value="ghost@corp.example")]
    assert form_incidents(graph, signals) == []


def test_community_signal_density_and_n_distinct_detector_layers() -> None:
    events = [
        GraphEvent(
            event_id=1,
            ts=_T0,
            principal="alice@corp.example",
            src_ip="10.0.0.1",
            dst_ip=None,
            domain="evil.example.com",
            asn=None,
            country=None,
        )
        for _ in range(2)
    ]
    graph = build_entity_graph(events, prune_below_event_count=1).graph
    signals = [
        _signal(1, detector_key="signal.beaconing", detector_layer="signal"),
        _signal(2, detector_key="sigma.large_post", detector_layer="rule"),
    ]
    incidents = form_incidents(graph, signals)
    assert len(incidents) == 1
    incident = incidents[0]
    # 1 seed entity (user) out of 3 total entities (user + src_ip + domain, all 1-hop from the
    # user) => density 1/3.
    assert incident.community_signal_density == pytest.approx(1 / 3)
    assert incident.n_distinct_detector_layers == 2
