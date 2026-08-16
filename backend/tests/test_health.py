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


def test_health_reports_the_modes_that_fail_quietly() -> None:
    """`llm_enabled` and `email_verification_enabled` are states the app can be in without
    anything looking wrong from outside. The latter fails *open* — signup stamps accounts
    verified instead of emailing a link — so a deploy that lost its Supabase credentials must
    be diagnosable from the health endpoint rather than only from a warning buried in the
    signup logs."""
    body = client.get("/api/health").json()
    for flag in ("llm_enabled", "email_verification_enabled"):
        assert isinstance(body[flag], bool), flag


def test_openapi_schema_generates() -> None:
    """The frontend generates its API types from this schema, so it must be valid."""
    response = client.get("/api/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"] == "Tenex SOC Analyst API"
