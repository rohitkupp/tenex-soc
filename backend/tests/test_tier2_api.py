"""`GET /api/tier2/overview`, `GET /api/tier2/indicator-overlap`, and the four cross-tenant
learning chart routes — full HTTP integration tests via `TestClient` against the live
Postgres, docs/09's Tier 2 section end to end.

The NL-to-SQL chatbot route (`POST /api/tier2/query`) and its tests are gone — removed under
a hard cost constraint that this task's LLM surface must shrink, never grow (`app.api.tier2`'s
module docstring). Every route left in this file is deterministic and non-LLM.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from tests.conftest import authenticate, make_tenant, make_user


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
        ("GET", "/api/tier2/overlap-distribution"),
        ("GET", "/api/tier2/technique-prevalence"),
        ("GET", "/api/tier2/first-seen"),
    ],
)
def test_every_route_requires_authentication(client: TestClient, method: str, path: str) -> None:
    resp = client.request(method, path)
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


# ---------------------------------------------------------------------------- chart 1: overlap distribution


def test_overlap_distribution_returns_the_documented_shape(client: TestClient, user) -> None:
    authenticate(client, user)
    resp = client.get("/api/tier2/overlap-distribution")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body.keys()) == {"total_indicators", "buckets"}
    assert [b["bucket"] for b in body["buckets"]] == ["1", "2", "3+"]
    assert body["total_indicators"] == sum(b["indicator_count"] for b in body["buckets"])


# ---------------------------------------------------------------------------- chart 2: technique prevalence


def test_technique_prevalence_always_returns_all_thirteen_allowlisted_techniques(
    client: TestClient, user
) -> None:
    """Every allowlisted technique is returned, including ones observed in zero tenants --
    never a fabricated id, and never a silently-dropped one either."""
    authenticate(client, user)
    resp = client.get("/api/tier2/technique-prevalence")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body.keys()) == {"total_tenants_with_signatures", "items"}
    assert len(body["items"]) == 13
    ids = {item["technique_id"] for item in body["items"]}
    assert len(ids) == 13  # no duplicates
    for item in body["items"]:
        assert set(item.keys()) == {
            "technique_id",
            "technique_name",
            "tenant_count",
            "signature_count",
        }
        assert item["tenant_count"] >= 0
        assert item["signature_count"] >= 0


def test_first_seen_returns_the_documented_shape(client: TestClient, user) -> None:
    authenticate(client, user)
    resp = client.get("/api/tier2/first-seen")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body.keys()) == {"items"}
    for item in body["items"]:
        assert set(item.keys()) == {"indicator_hash", "tenant_count", "observations"}
        assert item["tenant_count"] >= 2  # same qualification as indicator-overlap
        assert len(item["observations"]) == item["tenant_count"]
        for obs in item["observations"]:
            assert set(obs.keys()) == {"tenant_hash", "first_observed_at"}
        # observations are sorted first-seen ascending
        seen_at = [obs["first_observed_at"] for obs in item["observations"]]
        assert seen_at == sorted(seen_at)


def test_first_seen_rejects_min_tenants_below_two(client: TestClient, user) -> None:
    authenticate(client, user)
    resp = client.get("/api/tier2/first-seen", params={"min_tenants": 1})
    assert resp.status_code == 422
