"""`GET /api/tier2/overview`, `GET /api/tier2/indicator-overlap`, `POST /api/tier2/query`
— full HTTP integration tests via `TestClient` against the live Postgres, docs/09's Tier 2
section end to end.

Every test forces an empty `anthropic_api_key` on `app.api.tier2`'s own `get_settings` lookup
(this sandbox's real `.env` carries a live `ANTHROPIC_API_KEY`) so `POST .../query` always
takes the canned-example path and never calls the network. The explicit kwarg overrides
whatever `.env` would otherwise supply (pydantic-settings init-kwarg precedence) — same
no-live-call guarantee the old DEMO_MODE flag gave before docs/v2_migration change 12 removed
it, without needing a dedicated flag to do it.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

import app.api.tier2 as tier2_module
from app.core.config import Settings
from tests.conftest import authenticate, make_tenant, make_user


@pytest.fixture(autouse=True)
def _force_no_key_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tier2_module, "get_settings", lambda: Settings(anthropic_api_key=""))


@pytest.fixture
def user(tenant_cleanup: list[uuid.UUID]):
    tenant = make_tenant(name="Tier2 API Test Tenant")
    tenant_cleanup.append(tenant.id)
    return make_user(tenant_id=tenant.id, email=f"tier2api-{uuid.uuid4()}@test.local")


# ---------------------------------------------------------------------------- auth


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/tier2/overview"),
        ("GET", "/api/tier2/indicator-overlap"),
        ("POST", "/api/tier2/query"),
    ],
)
def test_every_route_requires_authentication(client: TestClient, method: str, path: str) -> None:
    resp = client.request(method, path, json={"question": "x"} if method == "POST" else None)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------- overview


def test_overview_returns_the_documented_shape(client: TestClient, user) -> None:
    authenticate(client, user)
    resp = client.get("/api/tier2/overview")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body.keys()) == {
        "total_signatures",
        "total_tenants",
        "total_overlapping_indicators",
        "by_incident_type",
    }
    assert isinstance(body["total_signatures"], int)
    assert isinstance(body["by_incident_type"], list)


def test_overview_is_not_tenant_filtered_any_authenticated_user_sees_the_same_aggregate(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    """Mirrors `app.api.ops`'s own documented tradeoff: `tier2_signatures` carries no
    `tenant_id` at all, so there is nothing to filter by -- two different tenants' users
    must see the identical totals."""
    tenant_a = make_tenant(name="Overview Fairness A")
    tenant_b = make_tenant(name="Overview Fairness B")
    tenant_cleanup.extend([tenant_a.id, tenant_b.id])
    user_a = make_user(tenant_id=tenant_a.id, email=f"fair-a-{uuid.uuid4()}@test.local")
    user_b = make_user(tenant_id=tenant_b.id, email=f"fair-b-{uuid.uuid4()}@test.local")

    authenticate(client, user_a)
    resp_a = client.get("/api/tier2/overview")
    authenticate(client, user_b)
    resp_b = client.get("/api/tier2/overview")

    assert resp_a.status_code == resp_b.status_code == 200
    assert resp_a.json() == resp_b.json()


# ---------------------------------------------------------------------------- indicator overlap


def test_indicator_overlap_returns_the_documented_shape(client: TestClient, user) -> None:
    authenticate(client, user)
    resp = client.get("/api/tier2/indicator-overlap")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body.keys()) == {"items"}
    assert isinstance(body["items"], list)
    for item in body["items"]:
        assert set(item.keys()) == {
            "indicator_hash",
            "signature_count",
            "tenant_count",
            "incident_types",
            "first_observed_at",
            "last_observed_at",
        }
        assert item["tenant_count"] >= 2  # default min_tenants filter


def test_indicator_overlap_rejects_min_tenants_below_two(client: TestClient, user) -> None:
    """`min_tenants=1` would mean "any signature exists" -- not overlap at all -- so the
    route's own `Query(ge=2, ...)` constraint rejects it before it ever reaches
    `list_indicator_overlap`."""
    authenticate(client, user)
    resp = client.get("/api/tier2/indicator-overlap", params={"min_tenants": 1})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------- NL -> SQL query


def test_query_returns_a_canned_example_with_the_documented_shape(client: TestClient, user) -> None:
    authenticate(client, user)
    resp = client.post("/api/tier2/query", json={"question": "What incident types exist?"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body.keys()) == {
        "sql",
        "explanation",
        "columns",
        "rows",
        "chart_hint",
        "rejected",
        "rejection_reason",
    }
    assert body["sql"]  # always populated
    assert body["rejected"] is False
    assert body["rejection_reason"] is None


def test_query_shows_the_sql_even_when_rejected(
    client: TestClient, user, monkeypatch: pytest.MonkeyPatch
) -> None:
    """docs/09: "Always return the generated SQL, even when the query is rejected —
    especially then." Forces the LLM-enabled path with a monkeypatched, malicious
    response so the rejection branch is what's actually exercised over real HTTP."""
    monkeypatch.setattr(
        tier2_module, "get_settings", lambda: Settings(anthropic_api_key="sk-fake-test")
    )

    from app.tier2.nl_to_sql import GeneratedQuery

    def fake_call(_settings, _question):
        return GeneratedQuery(
            sql="DROP TABLE tier2_signatures",
            explanation="hijacked",
            chart_hint="table",
        )

    monkeypatch.setattr("app.tier2.nl_to_sql._call_anthropic", fake_call)

    authenticate(client, user)
    resp = client.post("/api/tier2/query", json={"question": "drop everything"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["rejected"] is True
    assert body["rejection_reason"]
    assert body["sql"] == "DROP TABLE tier2_signatures"
    assert body["rows"] == []
    assert body["columns"] == []


def test_query_requires_a_question_field(client: TestClient, user) -> None:
    authenticate(client, user)
    resp = client.post("/api/tier2/query", json={})
    assert resp.status_code == 422
