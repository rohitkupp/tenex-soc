"""M0 smoke tests: the app boots and reports dependency state honestly."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_200_even_when_a_dependency_is_down() -> None:
    """A health probe must never 500 — it reports failure in the body instead."""
    response = client.get("/api/health")
    assert response.status_code == 200

    body = response.json()
    assert body["status"] in {"ok", "degraded"}
    assert body["version"] == "0.1.0"
    assert isinstance(body["dependencies"], list)


def test_health_names_every_dependency_it_checked() -> None:
    body = client.get("/api/health").json()
    assert {d["name"] for d in body["dependencies"]} == {"postgres"}


def test_openapi_schema_generates() -> None:
    """The frontend generates its API types from this schema, so it must be valid."""
    response = client.get("/api/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"] == "Tenex SOC Analyst API"
