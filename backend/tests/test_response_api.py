"""`GET /api/incidents/{id}/plan`, `POST /api/plans/{id}/approve`, `POST /api/plans/{id}/rollback`,
`GET /api/plans/{id}/state-diff` — full HTTP integration tests via `TestClient` against the live
Postgres, mirroring the milestone's acceptance bar end to end: derive -> approve (state mutates)
-> state-diff -> rollback (state restores exactly) -> state-diff again, plus the halting and
tenant-isolation cases docs/13's M12 requires proof of.

Every test in this module forces `demo_mode=True` on `app.api.plans`'s settings lookup (this
sandbox's real `.env` carries a live `ANTHROPIC_API_KEY`) so `GET .../plan`'s LLM verification
pass always takes the skip branch — this file, like `test_response_verification.py`, never calls
the network.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

import app.api.plans as plans_module
from app.core.config import Settings
from app.core.db import get_session_factory
from app.models.base import tenant_scope
from app.response import state
from tests.conftest import authenticate, make_analysis, make_tenant, make_user
from tests.fixtures.response import (
    make_incident,
    make_signal,
    make_triage_verdict,
    response_tenant_cleanup,  # noqa: F401
)


@pytest.fixture(autouse=True)
def _force_demo_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(plans_module, "get_settings", lambda: Settings(demo_mode=True))


@pytest.fixture
def ctx(response_tenant_cleanup: list[uuid.UUID]) -> dict[str, object]:  # noqa: F811
    tenant = make_tenant(name="Response API Test Tenant")
    response_tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"plans-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    return {"tenant": tenant, "user": user, "analysis": analysis}


def _flip_domain_allowlisted(tenant_id: uuid.UUID, domain: str) -> None:
    """Simulates the real world changing between plan derivation and approval — the proxy
    team allowlists a partner domain after the plan was already shown to an analyst."""
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            state.write_state(
                session,
                tenant_id,
                state.RESOURCE_PROXY_POLICY,
                domain,
                {"kind": "domain", "blocked": False, "allowlisted": True},
            )
            session.commit()
    finally:
        session.close()


# ---------------------------------------------------------------------------- GET .../plan


def test_get_plan_derives_and_persists_a_plan(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    signal = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="evil.example.com",
    )
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id, signal_ids=[signal.id])
    make_triage_verdict(
        incident_id=incident.id,
        recommended_actions=[
            {
                "action": "block_domain_at_proxy",
                "target": "evil.example.com",
                "rationale": "C2 domain",
            }
        ],
    )

    resp = client.get(f"/api/incidents/{incident.id}/plan")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["incident_id"] == str(incident.id)
    assert body["status"] == "pending_approval"
    assert body["verification"] == {"skipped": "llm_disabled"}
    assert body["outcome"] is None
    assert len(body["actions"]) == 1
    step = body["actions"][0]
    assert step["action_id"] == "block_domain_at_proxy"
    assert step["target"] == "evil.example.com"
    assert step["rationale"] == "C2 domain"
    assert step["blast_radius"] == "org"
    assert step["rollback_available"] is True
    live_ok = {c["id"]: c["satisfied"] for c in step["live_preconditions"]}
    assert live_ok == {"domain_not_allowlisted": True}

    # idempotent: a second GET returns the SAME plan, not a freshly re-derived one.
    resp2 = client.get(f"/api/incidents/{incident.id}/plan")
    assert resp2.status_code == 200
    assert resp2.json()["id"] == body["id"]


def test_get_plan_404_for_unknown_incident(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    resp = client.get(f"/api/incidents/{uuid.uuid4()}/plan")
    assert resp.status_code == 404
    assert resp.json()["code"] == "not_found"


def test_get_plan_409_when_incident_has_no_verdict(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)

    resp = client.get(f"/api/incidents/{incident.id}/plan")
    assert resp.status_code == 409
    assert resp.json()["code"] == "no_verdict"


def test_get_plan_422_on_unmapped_free_text_action(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)
    make_triage_verdict(
        incident_id=incident.id,
        recommended_actions=[{"action": "wipe_the_server", "target": "host-1"}],
    )

    resp = client.get(f"/api/incidents/{incident.id}/plan")
    assert resp.status_code == 422
    assert resp.json()["code"] == "invalid_recommended_action"
    assert "wipe_the_server" in resp.json()["detail"]


def test_get_plan_requires_auth(client: TestClient) -> None:
    resp = client.get(f"/api/incidents/{uuid.uuid4()}/plan")
    assert resp.status_code == 401


def test_get_plan_is_tenant_isolated(
    client: TestClient,
    ctx: dict,
    response_tenant_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    other_tenant = make_tenant(name="Response API Other Tenant")
    response_tenant_cleanup.append(other_tenant.id)
    other_user = make_user(tenant_id=other_tenant.id, email=f"other-{uuid.uuid4()}@test.local")
    other_analysis = make_analysis(tenant_id=other_tenant.id, user_id=other_user.id)
    other_incident = make_incident(tenant_id=other_tenant.id, analysis_id=other_analysis.id)
    make_triage_verdict(
        incident_id=other_incident.id,
        recommended_actions=[{"action": "isolate_host", "target": "host-1"}],
    )

    authenticate(client, ctx["user"])  # a DIFFERENT tenant's user
    resp = client.get(f"/api/incidents/{other_incident.id}/plan")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------- approve


def _derive_plan(client: TestClient, incident_id: uuid.UUID) -> dict:
    resp = client.get(f"/api/incidents/{incident_id}/plan")
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_approve_requires_confirm_true_body(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)
    make_triage_verdict(
        incident_id=incident.id,
        recommended_actions=[{"action": "isolate_host", "target": "host-1"}],
    )
    plan = _derive_plan(client, incident.id)

    missing_body = client.post(f"/api/plans/{plan['id']}/approve", json={})
    assert missing_body.status_code == 422  # pydantic: confirm is required

    explicit_false = client.post(f"/api/plans/{plan['id']}/approve", json={"confirm": False})
    assert explicit_false.status_code == 400
    assert explicit_false.json()["code"] == "confirmation_required"


def test_approve_404_for_unknown_plan(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    resp = client.post(f"/api/plans/{uuid.uuid4()}/approve", json={"confirm": True})
    assert resp.status_code == 404


def test_approve_happy_path_mutates_state_journals_and_computes_outcome(
    client: TestClient, ctx: dict
) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    signal = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="c2.example.com",
    )
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id, signal_ids=[signal.id])
    make_triage_verdict(
        incident_id=incident.id,
        recommended_actions=[{"action": "block_domain_at_proxy", "target": "c2.example.com"}],
    )
    plan = _derive_plan(client, incident.id)

    resp = client.post(f"/api/plans/{plan['id']}/approve", json={"confirm": True})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "approved"
    assert body["halted"] is False
    assert len(body["journal"]) == 1
    entry = body["journal"][0]
    assert entry["succeeded"] is True
    assert entry["before_state"]["blocked"] is False
    assert entry["after_state"]["blocked"] is True
    assert body["outcome"] == "contained"
    assert body["outcome_detail"]["resolved_count"] == 1

    # re-fetching the plan reflects the same, now-persisted outcome.
    refetched = client.get(f"/api/incidents/{incident.id}/plan").json()
    assert refetched["status"] == "approved"
    assert refetched["outcome"] == "contained"
    assert refetched["approved_by"] is not None
    assert refetched["approved_at"] is not None


def test_approve_twice_is_rejected(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)
    make_triage_verdict(
        incident_id=incident.id,
        recommended_actions=[{"action": "isolate_host", "target": "host-1"}],
    )
    plan = _derive_plan(client, incident.id)

    first = client.post(f"/api/plans/{plan['id']}/approve", json={"confirm": True})
    assert first.status_code == 200

    second = client.post(f"/api/plans/{plan['id']}/approve", json={"confirm": True})
    assert second.status_code == 409
    assert second.json()["code"] == "invalid_status"


def test_approve_halts_on_a_real_precondition_failure(client: TestClient, ctx: dict) -> None:
    """State drifted between plan derivation and approval (a partner domain got allowlisted) —
    approval must halt on the real, current state, not whatever was true when the plan was
    shown."""
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    signal = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="domain",
        entity_value="partner.example.com",
    )
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id, signal_ids=[signal.id])
    make_triage_verdict(
        incident_id=incident.id,
        recommended_actions=[{"action": "block_domain_at_proxy", "target": "partner.example.com"}],
    )
    plan = _derive_plan(client, incident.id)
    assert plan["actions"][0]["live_preconditions"][0]["satisfied"] is True  # true at plan time

    _flip_domain_allowlisted(tenant.id, "partner.example.com")

    resp = client.post(f"/api/plans/{plan['id']}/approve", json={"confirm": True})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "halted"
    assert body["halted"] is True
    assert len(body["journal"]) == 1
    assert body["journal"][0]["succeeded"] is False
    assert "allowlisted" in body["journal"][0]["precondition_failure"]
    assert body["outcome"] == "failed"  # docs/08: a halted plan is failed, full stop


def test_approve_is_tenant_isolated(
    client: TestClient,
    ctx: dict,
    response_tenant_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    other_tenant = make_tenant(name="Response Approve Other Tenant")
    response_tenant_cleanup.append(other_tenant.id)
    other_user = make_user(
        tenant_id=other_tenant.id, email=f"approve-other-{uuid.uuid4()}@test.local"
    )
    other_analysis = make_analysis(tenant_id=other_tenant.id, user_id=other_user.id)
    other_incident = make_incident(tenant_id=other_tenant.id, analysis_id=other_analysis.id)
    make_triage_verdict(
        incident_id=other_incident.id,
        recommended_actions=[{"action": "isolate_host", "target": "host-1"}],
    )

    other_client = TestClient(client.app, headers=dict(client.headers))
    authenticate(other_client, other_user)
    plan = _derive_plan(other_client, other_incident.id)

    authenticate(client, ctx["user"])  # a different tenant now driving the shared `client`
    resp = client.post(f"/api/plans/{plan['id']}/approve", json={"confirm": True})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------- rollback + state-diff


def test_rollback_requires_an_executed_plan(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)
    make_triage_verdict(
        incident_id=incident.id,
        recommended_actions=[{"action": "isolate_host", "target": "host-1"}],
    )
    plan = _derive_plan(client, incident.id)

    resp = client.post(f"/api/plans/{plan['id']}/rollback")
    assert resp.status_code == 409
    assert resp.json()["code"] == "invalid_status"


def test_full_loop_approve_state_diff_rollback_state_diff(client: TestClient, ctx: dict) -> None:
    """The M12 acceptance bar, end to end: approve -> state mutates -> state-diff shows
    before != after -> rollback -> state-diff shows current state restored exactly."""
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    signal = make_signal(
        tenant_id=tenant.id, analysis_id=analysis.id, entity_type="user", entity_value="alice"
    )
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id, signal_ids=[signal.id])
    make_triage_verdict(
        incident_id=incident.id,
        recommended_actions=[
            {"action": "force_credential_reset", "target": "alice"}
        ],  # implies revoke first
    )
    plan = _derive_plan(client, incident.id)
    assert [s["action_id"] for s in plan["actions"]] == [
        "revoke_okta_sessions",
        "force_credential_reset",
    ]

    approve_resp = client.post(f"/api/plans/{plan['id']}/approve", json={"confirm": True})
    assert approve_resp.status_code == 200, approve_resp.text
    approve_body = approve_resp.json()
    assert approve_body["status"] == "approved"
    assert approve_body["outcome"] == "contained"  # re-detection reports contained

    diff_after_execute = client.get(f"/api/plans/{plan['id']}/state-diff").json()
    assert diff_after_execute["status"] == "approved"
    assert len(diff_after_execute["diff"]) == 2
    revoke_row, reset_row = diff_after_execute["diff"]
    assert revoke_row["action_id"] == "revoke_okta_sessions"
    assert revoke_row["before"]["sessions"][0]["active"] is True
    assert revoke_row["after"]["sessions"][0]["active"] is False
    assert reset_row["after"]["credential_reset_required"] is True
    # Both rows share one resource (okta_session:alice) — "current" (live) reflects the LAST
    # write to that resource (reset's after-state), not revoke's own intermediate snapshot.
    assert revoke_row["current"] == reset_row["after"]
    assert reset_row["current"] == reset_row["after"]  # not yet rolled back

    rollback_resp = client.post(f"/api/plans/{plan['id']}/rollback")
    assert rollback_resp.status_code == 200, rollback_resp.text
    rollback_body = rollback_resp.json()
    assert rollback_body["status"] == "rolled_back"
    assert len(rollback_body["restored"]) == 2

    diff_after_rollback = client.get(f"/api/plans/{plan['id']}/state-diff").json()
    assert diff_after_rollback["status"] == "rolled_back"
    revoke_row_2, reset_row_2 = diff_after_rollback["diff"]
    # `before`/`after` on each row are still the SAME historical execution-time values as the
    # first state-diff call — the journal itself never changes.
    assert revoke_row_2["before"] == revoke_row["before"]
    assert revoke_row_2["after"] == revoke_row["after"]
    assert reset_row_2["before"] == reset_row["before"]
    assert reset_row_2["after"] == reset_row["after"]
    # `current` (live, read fresh) now reflects the fully-rolled-back world: exactly the
    # original pre-execution state — this IS "rollback restores exactly."
    assert revoke_row_2["current"] == revoke_row["before"]
    assert reset_row_2["current"] == revoke_row["before"]
    assert reset_row_2["current"]["credential_reset_required"] is False
    assert all(s["active"] for s in reset_row_2["current"]["sessions"])

    # The plan's own outcome is left as the historical record of what execution achieved —
    # rollback does not retroactively rewrite "contained" into something else.
    final_plan = client.get(f"/api/incidents/{incident.id}/plan").json()
    assert final_plan["status"] == "rolled_back"
    assert final_plan["outcome"] == "contained"


def test_rollback_twice_is_rejected(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)
    make_triage_verdict(
        incident_id=incident.id,
        recommended_actions=[{"action": "isolate_host", "target": "host-1"}],
    )
    plan = _derive_plan(client, incident.id)
    client.post(f"/api/plans/{plan['id']}/approve", json={"confirm": True})

    first = client.post(f"/api/plans/{plan['id']}/rollback")
    assert first.status_code == 200

    second = client.post(f"/api/plans/{plan['id']}/rollback")
    assert second.status_code == 409
    assert second.json()["code"] == "invalid_status"


def test_state_diff_404_for_unknown_plan(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    resp = client.get(f"/api/plans/{uuid.uuid4()}/state-diff")
    assert resp.status_code == 404


def test_state_diff_empty_before_any_approval(client: TestClient, ctx: dict) -> None:
    authenticate(client, ctx["user"])
    tenant, analysis = ctx["tenant"], ctx["analysis"]
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)
    make_triage_verdict(
        incident_id=incident.id,
        recommended_actions=[{"action": "isolate_host", "target": "host-1"}],
    )
    plan = _derive_plan(client, incident.id)

    resp = client.get(f"/api/plans/{plan['id']}/state-diff")
    assert resp.status_code == 200
    assert resp.json()["diff"] == []
