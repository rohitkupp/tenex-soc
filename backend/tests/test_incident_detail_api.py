"""`GET /api/analyses/{id}/incidents`, `GET /api/incidents/{id}`, `.../graph`, `.../timeline`
— HTTP integration tests through `TestClient` against the live Postgres.

Three properties matter more than the happy path here and each gets its own test:

1. **Keyset pagination is a strict total order.** Two incidents sharing a `fused_score` must not
   let a page boundary skip or repeat either of them (the same bar `test_events_api.py` holds
   `(ts, id)` to).
2. **Tenant isolation is structural.** Another tenant's incident id must 404, not 403 and not a
   row — including on the nested `/graph` and `/timeline` routes, which reach `entities` and
   `entity_edges`, two tables that carry no `tenant_id` of their own (docs/02 scopes them
   transitively through `analysis_id`).
3. **The graph never dangles.** An edge whose other endpoint fell outside `MAX_GRAPH_NEIGHBOURS`
   is dropped, so every `source`/`target` in the response resolves to a node in the same response.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.db import get_engine, get_session_factory
from app.models.entity import Entity
from app.models.entity_edge import EntityEdge
from tests.conftest import authenticate, make_analysis, make_tenant, make_user
from tests.fixtures.response import (
    make_incident,
    make_signal,
    make_triage_verdict,
    response_tenant_cleanup,  # noqa: F401
)


@pytest.fixture
def graph_cleanup(response_tenant_cleanup: list[uuid.UUID]) -> Iterator[list[uuid.UUID]]:  # noqa: F811
    """`entity_edges.src_entity_id` -> `entities.id` carries no `ON DELETE` action (docs/02),
    so a cascade from `analyses` can hit the edges and the entities in an order that violates it.
    Tearing edges down before entities, and both before `response_tenant_cleanup` drops the
    analyses, sidesteps that entirely — pytest finalises this fixture first because it was set up
    last."""
    yield response_tenant_cleanup
    if not response_tenant_cleanup:
        return
    with get_engine().begin() as conn:
        conn.execute(
            text(
                "DELETE FROM entity_edges WHERE analysis_id IN ("
                "  SELECT id FROM analyses WHERE tenant_id = ANY(:ids))"
            ),
            {"ids": response_tenant_cleanup},
        )
        conn.execute(
            text(
                "DELETE FROM entities WHERE analysis_id IN ("
                "  SELECT id FROM analyses WHERE tenant_id = ANY(:ids))"
            ),
            {"ids": response_tenant_cleanup},
        )


def make_entity(
    *,
    analysis_id: uuid.UUID,
    type_: str,
    value: str,
    risk_score: float = 0.5,
    event_count: int = 3,
) -> Entity:
    session = get_session_factory()()
    try:
        entity = Entity(
            analysis_id=analysis_id,
            type=type_,
            value=value,
            risk_score=risk_score,
            event_count=event_count,
            attrs={},
        )
        session.add(entity)
        session.commit()
        session.refresh(entity)
        return entity
    finally:
        session.close()


def make_edge(
    *,
    analysis_id: uuid.UUID,
    src: int,
    dst: int,
    relation: str = "accessed",
    weight: float = 1.0,
) -> EntityEdge:
    session = get_session_factory()()
    try:
        edge = EntityEdge(
            analysis_id=analysis_id,
            src_entity_id=src,
            dst_entity_id=dst,
            relation=relation,
            weight=weight,
            event_count=2,
        )
        session.add(edge)
        session.commit()
        session.refresh(edge)
        return edge
    finally:
        session.close()


@pytest.fixture
def ctx(graph_cleanup: list[uuid.UUID]) -> dict[str, Any]:
    tenant = make_tenant(name="Incident Read API Tenant")
    graph_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"incidents-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    return {"tenant": tenant, "user": user, "analysis": analysis}


# ------------------------------------------------------------------ GET .../incidents (queue)


def test_queue_returns_incidents_ranked_by_fused_score(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    for score in (0.2, 0.9, 0.55):
        make_incident(
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            title=f"incident {score}",
            fused_score=score,
        )

    resp = client.get(f"/api/analyses/{analysis.id}/incidents")
    assert resp.status_code == 200
    scores = [item["fused_score"] for item in resp.json()["items"]]
    assert scores == sorted(scores, reverse=True)
    assert resp.json()["next_cursor"] is None


def test_queue_marks_untriaged_incidents_needs_attention(client: TestClient, ctx: dict) -> None:
    """An incident the agent never reached is exactly the thing an analyst must look at
    personally — docs/07 triages only the top `MAX_TRIAGE_INCIDENTS`, so this is the common
    case, not an error state."""
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    untriaged = make_incident(tenant_id=tenant.id, analysis_id=analysis.id, fused_score=0.9)
    triaged = make_incident(tenant_id=tenant.id, analysis_id=analysis.id, fused_score=0.8)
    make_triage_verdict(incident_id=triaged.id, recommended_actions=[])

    by_id = {
        i["id"]: i for i in client.get(f"/api/analyses/{analysis.id}/incidents").json()["items"]
    }
    assert by_id[str(untriaged.id)]["needs_attention"] is True
    assert by_id[str(untriaged.id)]["disposition"] is None
    assert by_id[str(triaged.id)]["needs_attention"] is False
    assert by_id[str(triaged.id)]["disposition"] == "true_positive"


def test_queue_keyset_pagination_never_skips_or_repeats_a_tie(
    client: TestClient, ctx: dict
) -> None:
    """Five incidents, every one at the same `fused_score`: without the `id` tiebreak in both the
    ORDER BY and the cursor predicate, a page boundary here silently drops rows."""
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    created = {
        str(
            make_incident(
                tenant_id=tenant.id, analysis_id=analysis.id, title=f"tie {n}", fused_score=0.7
            ).id
        )
        for n in range(5)
    }

    seen: list[str] = []
    cursor: str | None = None
    for _ in range(10):  # bounded: 5 rows at limit=2 needs 3 pages
        url = f"/api/analyses/{analysis.id}/incidents?limit=2"
        if cursor:
            url += f"&cursor={cursor}"
        body = client.get(url).json()
        seen.extend(item["id"] for item in body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert cursor is None, "pagination did not terminate"
    assert len(seen) == len(set(seen)), "a row was returned on two different pages"
    assert set(seen) == created, "a row was skipped across a page boundary"


def test_queue_rejects_a_malformed_cursor(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    resp = client.get(f"/api/analyses/{ctx['analysis'].id}/incidents?cursor=not-base64!!")
    assert resp.status_code == 400
    assert resp.json()["code"] == "invalid_cursor"


# ------------------------------------------------------------------ GET /incidents/{id}


def test_detail_returns_signals_entities_and_verdict(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    signal = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="beacon.example.com",
        explanation={"mean_interval": 300.0, "cv": 0.02, "n_events": 288},
    )
    entity = make_entity(analysis_id=analysis.id, type_="domain", value="beacon.example.com")
    incident = make_incident(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signal_ids=[signal.id],
        entity_ids=[entity.id],
    )
    make_triage_verdict(incident_id=incident.id, recommended_actions=[])

    body = client.get(f"/api/incidents/{incident.id}").json()
    assert [s["id"] for s in body["signals"]] == [signal.id]
    assert body["signals"][0]["detector_key"] == "signal.beaconing"
    # The detector's own payload passes through verbatim — the UI dispatches on `detector_key`
    # to render it, so anything the server drops here is a chart the case file cannot draw.
    assert body["signals"][0]["explanation"] == {
        "mean_interval": 300.0,
        "cv": 0.02,
        "n_events": 288,
    }
    assert [e["id"] for e in body["entities"]] == [entity.id]
    assert body["verdict"]["disposition"] == "true_positive"


def test_queue_returns_deterministic_tags_for_every_incident(client: TestClient, ctx: dict) -> None:
    """ "EVERY incident to have a summary by default" / tags "a real pipeline output visible on
    the dashboard" — both must show up on the queue row, not just the case file, and neither
    depends on whether the incident was ever triaged."""
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    make_incident(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        tags=["technique:T1090", "layer:rule", "multi-layer"],
    )

    body = client.get(f"/api/analyses/{analysis.id}/incidents").json()
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["tags"] == ["technique:T1090", "layer:rule", "multi-layer"]
    # Untriaged: the LLM's own `mitre_techniques` stays empty, distinct from the deterministic
    # `tags` field, which is populated regardless (`app.graph.tags` module docstring).
    assert item["mitre_techniques"] == []


def test_detail_returns_tags_and_summary(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        tags=["detector:signal.beaconing", "layer:signal"],
        summary="3 signals from the signal layer fired on 1 domain. Fused severity: high.",
    )

    body = client.get(f"/api/incidents/{incident.id}").json()
    assert body["tags"] == ["detector:signal.beaconing", "layer:signal"]
    assert (
        body["summary"]
        == "3 signals from the signal layer fired on 1 domain. Fused severity: high."
    )


def test_detail_deterministic_summary_survives_when_an_llm_verdict_exists(
    client: TestClient, ctx: dict
) -> None:
    """ "the deterministic summary survives when an LLM verdict exists" (this task's test list):
    `Incident.summary` and `TriageVerdict.summary` are separate columns with separate
    provenance (docs/v2_migration change 3's "two confidences, never mixed" precedent, applied
    to prose) — triaging an incident must never blank out or overwrite the deterministic one."""
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    deterministic_summary = (
        "1 signal from the rule layer fired on 1 domain at 2026-01-01T12:00 UTC. "
        "1 event supports this finding; top technique Proxy (T1090). Fused severity: high."
    )
    incident = make_incident(
        tenant_id=tenant.id, analysis_id=analysis.id, summary=deterministic_summary
    )
    make_triage_verdict(
        incident_id=incident.id,
        recommended_actions=[],
        summary="The LLM's own narrative read of this incident, in prose the analyst reads.",
    )

    body = client.get(f"/api/incidents/{incident.id}").json()
    assert body["summary"] == deterministic_summary
    assert body["verdict"]["summary"] == (
        "The LLM's own narrative read of this incident, in prose the analyst reads."
    )
    assert body["summary"] != body["verdict"]["summary"]


def test_detail_verdict_is_null_when_untriaged(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    incident = make_incident(tenant_id=ctx["tenant"].id, analysis_id=ctx["analysis"].id)
    assert client.get(f"/api/incidents/{incident.id}").json()["verdict"] is None


def test_timeline_is_ordered_by_window_not_by_insertion(client: TestClient, ctx: dict) -> None:
    """docs/05: "Never let the model order events." Ordering comes from `window_start`, so
    inserting the later signal first must not change the output order."""
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    later = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="second.example.com",
        detector_key="signal.burst",
    )
    earlier = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="first.example.com",
    )
    session = get_session_factory()()
    try:
        session.execute(
            text("UPDATE signals SET window_start = :ts WHERE id = :id"),
            {"ts": "2026-01-01T02:00:00+00:00", "id": later.id},
        )
        session.execute(
            text("UPDATE signals SET window_start = :ts WHERE id = :id"),
            {"ts": "2026-01-01T01:00:00+00:00", "id": earlier.id},
        )
        session.commit()
    finally:
        session.close()
    incident = make_incident(
        tenant_id=tenant.id, analysis_id=analysis.id, signal_ids=[later.id, earlier.id]
    )

    phases = client.get(f"/api/incidents/{incident.id}/timeline").json()["phases"]
    assert [p["entity_value"] for p in phases] == ["first.example.com", "second.example.com"]
    assert phases[0]["tactic"] == "Command and Control"  # T1071.001, a real mapping
    assert phases[0]["tactic_is_placeholder"] is False


# ------------------------------------------------------------------ GET /incidents/{id}/graph


def test_graph_returns_seeds_plus_one_hop_and_marks_the_seeds(
    client: TestClient, ctx: dict
) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    seed = make_entity(analysis_id=analysis.id, type_="user", value="alice@corp.example")
    neighbour = make_entity(analysis_id=analysis.id, type_="domain", value="evil.example.com")
    stranger = make_entity(analysis_id=analysis.id, type_="domain", value="unrelated.example.com")
    make_edge(analysis_id=analysis.id, src=seed.id, dst=neighbour.id)
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id, entity_ids=[seed.id])

    body = client.get(f"/api/incidents/{incident.id}/graph").json()
    node_ids = {n["id"] for n in body["nodes"]}
    assert node_ids == {"user:alice@corp.example", "domain:evil.example.com"}
    assert f"domain:{stranger.value}" not in node_ids
    assert [n["is_seed"] for n in body["nodes"] if n["id"] == "user:alice@corp.example"] == [True]
    assert body["edges"] == [
        {
            "source": "user:alice@corp.example",
            "target": "domain:evil.example.com",
            "relation": "accessed",
            "weight": 1.0,
            "event_count": 2,
        }
    ]


def test_graph_never_returns_an_edge_with_a_missing_endpoint(client: TestClient, ctx: dict) -> None:
    """More neighbours than `MAX_GRAPH_NEIGHBOURS` allows: the cap must drop whole edges, not
    leave a `source`/`target` pointing at a node that isn't in the payload."""
    from app.api.incident_detail import MAX_GRAPH_NEIGHBOURS

    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    seed = make_entity(analysis_id=analysis.id, type_="ip", value="10.0.0.1")
    for n in range(MAX_GRAPH_NEIGHBOURS + 5):
        neighbour = make_entity(analysis_id=analysis.id, type_="domain", value=f"n{n}.example.com")
        make_edge(analysis_id=analysis.id, src=seed.id, dst=neighbour.id, weight=float(n))
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id, entity_ids=[seed.id])

    body = client.get(f"/api/incidents/{incident.id}/graph").json()
    node_ids = {n["id"] for n in body["nodes"]}
    assert len(node_ids) == MAX_GRAPH_NEIGHBOURS + 1  # the cap held
    for edge in body["edges"]:
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids


# ------------------------------------------------------------------ tenant isolation


def test_another_tenants_incident_is_not_found_on_every_route(
    client: TestClient, ctx: dict, graph_cleanup: list[uuid.UUID]
) -> None:
    """404, never 403 and never a row — including on `/graph`, which reads `entities` and
    `entity_edges`, neither of which carries a `tenant_id` column of its own."""
    other = make_tenant(name="Other Tenant")
    graph_cleanup.append(other.id)
    other_user = make_user(tenant_id=other.id, email=f"other-{uuid.uuid4()}@test.local")
    other_analysis = make_analysis(tenant_id=other.id, user_id=other_user.id)
    other_entity = make_entity(analysis_id=other_analysis.id, type_="ip", value="10.9.9.9")
    other_incident = make_incident(
        tenant_id=other.id, analysis_id=other_analysis.id, entity_ids=[other_entity.id]
    )

    authenticate(client, ctx["user"])
    for path in (
        f"/api/incidents/{other_incident.id}",
        f"/api/incidents/{other_incident.id}/timeline",
        f"/api/incidents/{other_incident.id}/graph",
    ):
        resp = client.get(path)
        assert resp.status_code == 404, path
        assert resp.json()["code"] == "not_found"

    listed = client.get(f"/api/analyses/{other_analysis.id}/incidents")
    assert listed.status_code == 404


def test_routes_require_authentication(client: TestClient, ctx: dict) -> None:
    incident = make_incident(tenant_id=ctx["tenant"].id, analysis_id=ctx["analysis"].id)
    for path in (
        f"/api/analyses/{ctx['analysis'].id}/incidents",
        f"/api/incidents/{incident.id}",
        f"/api/incidents/{incident.id}/timeline",
        f"/api/incidents/{incident.id}/graph",
    ):
        assert client.get(path).status_code == 401, path
