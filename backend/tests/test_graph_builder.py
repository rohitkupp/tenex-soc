"""Tests for `app.graph.builder`. `build_entity_graph` is pure (`GraphEvent` fixtures, no DB);
`persist_entity_graph` needs a real `entities`/`entity_edges` round trip against the live
Postgres from `docker-compose.yml`, same convention as the rest of this test suite."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from app.core.db import get_session_factory
from app.graph.builder import (
    ENTITY_ASN,
    ENTITY_COUNTRY,
    ENTITY_DOMAIN,
    ENTITY_DST_IP,
    ENTITY_SRC_IP,
    ENTITY_USER,
    REL_ACCESSED,
    REL_FROM,
    REL_HOSTED_AT,
    REL_LOCATED_IN,
    REL_RESOLVES_TO,
    GraphEvent,
    build_entity_graph,
    persist_entity_graph,
)
from app.models.base import tenant_scope
from app.models.entity import Entity
from app.models.entity_edge import EntityEdge
from tests.conftest import make_analysis, make_tenant, make_user

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _event(
    event_id: int,
    *,
    principal: str | None = "alice@corp.example",
    src_ip: str | None = "10.0.0.1",
    dst_ip: str | None = "93.184.216.34",
    domain: str | None = "example.com",
    asn: int | None = 15169,
    country: str | None = "US",
) -> GraphEvent:
    return GraphEvent(
        event_id=event_id,
        ts=_T0,
        principal=principal,
        src_ip=src_ip,
        dst_ip=dst_ip,
        domain=domain,
        asn=asn,
        country=country,
    )


def test_build_entity_graph_creates_all_six_node_types() -> None:
    events = [_event(1), _event(2)]
    result = build_entity_graph(events, prune_below_event_count=1)
    node_types = {t for t, _ in result.graph.nodes}
    assert node_types == {
        ENTITY_USER,
        ENTITY_SRC_IP,
        ENTITY_DOMAIN,
        ENTITY_DST_IP,
        ENTITY_ASN,
        ENTITY_COUNTRY,
    }


def test_build_entity_graph_creates_the_five_documented_edge_relations() -> None:
    events = [_event(1), _event(2)]
    result = build_entity_graph(events, prune_below_event_count=1)
    relations = {data["relation"] for _, _, data in result.graph.edges(data=True)}
    assert relations == {REL_ACCESSED, REL_FROM, REL_RESOLVES_TO, REL_HOSTED_AT, REL_LOCATED_IN}


def test_edge_weight_is_log_scaled_event_count() -> None:
    import math

    events = [_event(i) for i in range(5)]
    result = build_entity_graph(events, prune_below_event_count=1)
    user_key = (ENTITY_USER, "alice@corp.example")
    domain_key = (ENTITY_DOMAIN, "example.com")
    data = result.graph.get_edge_data(user_key, domain_key, key=REL_ACCESSED)
    assert data is not None
    assert data["event_count"] == 5
    assert math.isclose(data["weight"], math.log1p(5))


def test_singleton_edges_are_pruned_and_recorded() -> None:
    # `alice` appears twice (edge survives default threshold=2); `bob` appears once (pruned).
    events = [
        _event(1, principal="alice@corp.example", domain="a.example.com"),
        _event(2, principal="alice@corp.example", domain="a.example.com"),
        _event(3, principal="bob@corp.example", domain="b.example.com"),
    ]
    result = build_entity_graph(events)
    user_alice = (ENTITY_USER, "alice@corp.example")
    domain_a = (ENTITY_DOMAIN, "a.example.com")
    assert result.graph.has_edge(user_alice, domain_a)

    user_bob = (ENTITY_USER, "bob@corp.example")
    domain_b = (ENTITY_DOMAIN, "b.example.com")
    assert not result.graph.has_edge(user_bob, domain_b)

    pruned_pairs = {(p.src, p.dst, p.relation) for p in result.pruned_edges}
    assert (user_bob, domain_b, REL_ACCESSED) in pruned_pairs


def test_pruned_node_still_exists_even_though_its_edge_was_dropped() -> None:
    """docs/05: only edges are pruned, never nodes -- an entity keeps its node (and would keep
    its `entities` row) even if every edge touching it fell below the prune threshold."""
    events = [_event(1, principal="bob@corp.example", domain="b.example.com")]
    result = build_entity_graph(events, prune_below_event_count=2)
    assert (ENTITY_USER, "bob@corp.example") in result.graph.nodes
    assert (ENTITY_DOMAIN, "b.example.com") in result.graph.nodes
    assert result.graph.number_of_edges() == 0


def test_node_carries_event_count_and_first_last_seen() -> None:
    from datetime import timedelta

    e1 = _event(1)
    e2 = GraphEvent(
        event_id=2,
        ts=_T0 + timedelta(hours=1),
        principal="alice@corp.example",
        src_ip="10.0.0.1",
        dst_ip="93.184.216.34",
        domain="example.com",
        asn=15169,
        country="US",
    )
    result = build_entity_graph([e1, e2], prune_below_event_count=1)
    node = result.graph.nodes[(ENTITY_USER, "alice@corp.example")]
    assert node["event_count"] == 2
    assert node["first_seen"] == _T0
    assert node["last_seen"] == _T0 + timedelta(hours=1)


def test_missing_fields_do_not_create_partial_edges() -> None:
    """An event with no `dst_ip` must not create a `domain --hosted_at--> dst_ip` edge to
    `None`, or any node keyed on `None`."""
    events = [_event(1, dst_ip=None, asn=None, country=None)]
    result = build_entity_graph(events, prune_below_event_count=1)
    assert not any(v is None for _, v in result.graph.nodes)
    assert (ENTITY_DST_IP, None) not in result.graph.nodes  # type: ignore[comparison-overlap]
    relations = {data["relation"] for _, _, data in result.graph.edges(data=True)}
    assert REL_HOSTED_AT not in relations
    assert REL_RESOLVES_TO not in relations
    assert REL_LOCATED_IN not in relations


def test_empty_events_produce_empty_graph() -> None:
    result = build_entity_graph([])
    assert result.n_nodes == 0
    assert result.n_edges == 0
    assert result.pruned_edges == []


# ---------------------------------------------------------------------------- DB-backed


@pytest.fixture
def tenant_and_analysis(tenant_cleanup: list[uuid.UUID]) -> Iterator[tuple[uuid.UUID, uuid.UUID]]:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"builder-{uuid.uuid4().hex[:8]}@corp.example")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    yield tenant.id, analysis.id


def test_persist_entity_graph_writes_entities_and_edges(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    tenant_id, analysis_id = tenant_and_analysis
    events = [_event(1), _event(2)]
    result = build_entity_graph(events, prune_below_event_count=1)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            key_to_id = persist_entity_graph(session, analysis_id=analysis_id, result=result)
            session.commit()

            entities = (
                session.execute(select(Entity).where(Entity.analysis_id == analysis_id))
                .scalars()
                .all()
            )
            edges = (
                session.execute(select(EntityEdge).where(EntityEdge.analysis_id == analysis_id))
                .scalars()
                .all()
            )
    finally:
        session.close()

    assert len(entities) == result.n_nodes == len(key_to_id)
    assert len(edges) == result.n_edges
    user_entity = next(e for e in entities if e.type == ENTITY_USER)
    assert user_entity.event_count == 2
    assert key_to_id[(ENTITY_USER, "alice@corp.example")] == user_entity.id


def test_persist_entity_graph_is_idempotent_on_rerun(
    tenant_and_analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """Re-persisting the same analysis_id (e.g. a re-run) must not duplicate entities/edges."""
    tenant_id, analysis_id = tenant_and_analysis
    events = [_event(1), _event(2)]
    result = build_entity_graph(events, prune_below_event_count=1)

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            persist_entity_graph(session, analysis_id=analysis_id, result=result)
            session.commit()
            persist_entity_graph(session, analysis_id=analysis_id, result=result)
            session.commit()

            entities = (
                session.execute(select(Entity).where(Entity.analysis_id == analysis_id))
                .scalars()
                .all()
            )
            edges = (
                session.execute(select(EntityEdge).where(EntityEdge.analysis_id == analysis_id))
                .scalars()
                .all()
            )
    finally:
        session.close()

    assert len(entities) == result.n_nodes
    assert len(edges) == result.n_edges
