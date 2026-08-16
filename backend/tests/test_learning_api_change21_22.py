"""HTTP surface for docs/v2_migration changes 21/22's new endpoints: per-claim thumbs, evidence
relevance, the `learning_events` feed, and gated-proposal accept/reject — added on top of the
existing `app.api.learning` router (`tests/test_learning_api.py` covers the pre-migration half).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.baseline_expansion import propose_baseline_expansion
from app.learning.benign_corpus import flag_benign_baseline
from app.learning.dga_retrain import propose_dga_retrain, record_dga_label_correction
from app.models.base import tenant_scope
from app.models.baseline_window import BaselineWindow
from tests.conftest import authenticate, make_analysis, make_tenant, make_user
from tests.fixtures.learning import (  # noqa: F401
    learning_cleanup,
    learning_session,
    make_feedback,
    make_incident_with_verdict,
    make_signal,
)


def test_override_technique_rejected_when_not_a_retrieved_candidate(
    client: TestClient,
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="API Technique Validation Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-technique-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    incident, _verdict = make_incident_with_verdict(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signals=[sig],
        mitre_techniques=["T1071.001"],
    )
    learning_session.commit()
    authenticate(client, user)

    response = client.post(
        f"/api/incidents/{incident.id}/feedback",
        json={"agrees": False, "corrected_technique": "T1567.002"},
    )
    assert response.status_code == 422
    assert response.json()["code"] == "invalid_corrected_technique"

    ok = client.post(
        f"/api/incidents/{incident.id}/feedback",
        json={"agrees": False, "corrected_technique": "NO_KNOWN_MAPPING"},
    )
    assert ok.status_code == 200


def test_claim_feedback_endpoint_records_thumbs_and_reports_proposal(
    client: TestClient,
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="API Claim Feedback Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-claim-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    incident, _verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[sig]
    )
    learning_session.commit()
    authenticate(client, user)

    response = client.post(
        f"/api/incidents/{incident.id}/claims/1/feedback",
        json={"helpful": False, "note": "confuses bytes_in and bytes_out for this host"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["step"] == 1
    assert body["helpful"] is False
    assert body["verifier_rule_proposed"] is False  # first of its kind, cluster not yet full


def test_evidence_relevance_endpoint_records_toggle(
    client: TestClient,
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="API Evidence Relevance Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-evidence-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    incident, _verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[sig]
    )
    learning_session.commit()
    authenticate(client, user)

    response = client.post(
        f"/api/incidents/{incident.id}/evidence/EVIDENCE-1/relevance",
        json={"extractor": "beaconing", "relevant": False},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["evidence_id"] == "EVIDENCE-1"
    assert body["relevant"] is False


def test_learning_events_endpoint_lists_auto_mechanism_events(
    client: TestClient,
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="API Learning Events Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-events-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    incident, _verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[sig]
    )
    learning_session.commit()
    authenticate(client, user)

    client.post(f"/api/incidents/{incident.id}/feedback", json={"agrees": True})

    response = client.get("/api/learning/events?mechanism=2&limit=5")
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) >= 1
    assert items[0]["mechanism"] == 2
    assert items[0]["mechanism_name"] == "fusion_weight_tuning"
    assert items[0]["applied"] is True


def test_learning_proposals_accept_and_reject_endpoints(
    client: TestClient,
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """Exercises the generic accept/reject dispatch against a real gated mechanism (8, DGA
    retraining) end to end over HTTP."""
    tenant = make_tenant(name="API Proposal Accept Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-proposal-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    incident, verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[sig]
    )
    learning_session.commit()
    fb = make_feedback(learning_session, verdict_id=verdict.id, user_id=user.id, agrees=True)
    learning_session.commit()

    for i in range(20):
        record_dga_label_correction(
            learning_session,
            tenant.id,
            domain=f"benign-{i}.com" if i % 2 == 0 else f"x{i}q9z.biz",
            is_dga=(i % 2 == 1),
            feedback_id=fb.id,
            incident_id=incident.id,
        )
    learning_session.commit()
    model_key = f"dga_logistic_regression.apitest.{uuid.uuid4().hex[:8]}"
    proposal = propose_dga_retrain(
        learning_session, tenant.id, trigger_feedback_id=fb.id, model_key=model_key
    )
    learning_session.commit()
    assert proposal is not None

    authenticate(client, user)

    # A pending proposal shows up in the review queue.
    pending = client.get("/api/learning/proposals")
    assert pending.status_code == 200
    assert any(p["id"] == str(proposal.id) for p in pending.json()["items"])

    accept = client.post(f"/api/learning/proposals/{proposal.id}/accept")
    assert accept.status_code == 200
    body = accept.json()
    assert body["passed"] is True
    assert body["status"] == "approved"

    # Already-decided proposals cannot be decided again.
    again = client.post(f"/api/learning/proposals/{proposal.id}/accept")
    assert again.status_code == 409


def test_learning_proposal_reject_endpoint_marks_rejected_without_applying(
    client: TestClient,
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="API Proposal Reject Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-reject-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    sig = make_signal(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
    )
    _incident, verdict = make_incident_with_verdict(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signals=[sig],
        disposition="false_positive",
    )
    learning_session.commit()
    fb = make_feedback(
        learning_session,
        verdict_id=verdict.id,
        user_id=user.id,
        agrees=False,
        dismissal_reason="sanctioned_automation",
        mark_benign_baseline=True,
    )
    learning_session.commit()
    flag_benign_baseline(learning_session, tenant.id, fb)
    learning_session.commit()
    proposal = propose_baseline_expansion(learning_session, tenant.id, fb.id)
    learning_session.commit()
    assert proposal is not None

    authenticate(client, user)
    response = client.post(f"/api/learning/proposals/{proposal.id}/reject")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "rejected"
    assert body["passed"] is False

    with tenant_scope(learning_session, tenant.id):
        windows = learning_session.execute(select(BaselineWindow)).scalars().all()
    assert windows == []  # rejected -- nothing was applied
