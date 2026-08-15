"""`app.api.learning` + `app.api.models` — the HTTP surface for docs/09's "Models & learning"
section (M13's half of it). Runs through the real FastAPI app (`TestClient`), including the
existing `app.core.csrf.CSRFMiddleware` on every POST -- `tests.conftest.authenticate` already
seeds a matching CSRF cookie/header, matching every other authenticated-POST test in this suite.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.base import tenant_scope
from app.models.incident import Incident
from tests.conftest import authenticate, make_analysis, make_tenant, make_user
from tests.fixtures.learning import (
    learning_cleanup,
    learning_session,
    make_feedback,
    make_incident_with_verdict,
    make_signal,
)

_BACKEND_ROOT = Path(__file__).resolve().parents[1]


def test_feedback_endpoint_requires_auth(client: TestClient) -> None:
    response = client.post(f"/api/incidents/{uuid.uuid4()}/feedback", json={"agrees": True})
    assert response.status_code == 401


def test_feedback_endpoint_404_for_unknown_incident(
    client: TestClient, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="API Feedback 404 Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-fb-404-{uuid.uuid4()}@test.local")
    authenticate(client, user)

    response = client.post(f"/api/incidents/{uuid.uuid4()}/feedback", json={"agrees": True})
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


def test_feedback_endpoint_409_for_untriaged_incident(
    client: TestClient, learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="API Feedback 409 Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-fb-409-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    authenticate(client, user)

    with tenant_scope(learning_session, tenant.id):
        incident = Incident(
            analysis_id=analysis.id,
            tenant_id=tenant.id,
            title="No verdict",
            severity="low",
            fused_score=0.1,
            entity_ids=[],
            signal_ids=[],
        )
        learning_session.add(incident)
        learning_session.flush()
    learning_session.commit()

    response = client.post(f"/api/incidents/{incident.id}/feedback", json={"agrees": True})
    assert response.status_code == 409
    assert response.json()["code"] == "incident_not_triaged"


def test_feedback_endpoint_records_feedback_and_returns_weight_changes(
    client: TestClient, learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="API Feedback Success Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-fb-ok-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    detector_key = f"test.api.{uuid.uuid4().hex[:8]}"

    sig = make_signal(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, detector_key=detector_key
    )
    incident, _verdict = make_incident_with_verdict(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signals=[sig],
        disposition="true_positive",
    )
    learning_session.commit()
    authenticate(client, user)

    response = client.post(
        f"/api/incidents/{incident.id}/feedback",
        json={"agrees": True, "note": "confirmed via API"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["feedback_id"]
    assert body["calibration_refit_triggered"] is False
    assert body["suppression_candidates_generated"] == []
    assert body["benign_baseline_entries_created"] == 0
    detector_keys = {c["detector_key"] for c in body["detector_weight_changes"]}
    assert detector_key in detector_keys


def test_feedback_endpoint_generates_suppression_candidate_on_dismissal(
    client: TestClient, learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="API Feedback Suppression Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-fb-suppress-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    incident, _verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[sig]
    )
    learning_session.commit()
    authenticate(client, user)

    response = client.post(
        f"/api/incidents/{incident.id}/feedback",
        json={"agrees": False, "dismissal_reason": "known sanctioned scanner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body["suppression_candidates_generated"]) == 1


def test_learning_metrics_endpoint_requires_auth(client: TestClient) -> None:
    response = client.get("/api/learning/metrics")
    assert response.status_code == 401


def test_learning_metrics_endpoint_reflects_recorded_feedback(
    client: TestClient, learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="API Metrics Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-metrics-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    _incident, verdict = make_incident_with_verdict(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signals=[sig],
        disposition="true_positive",
    )
    make_feedback(learning_session, verdict_id=verdict.id, user_id=user.id, agrees=True)
    learning_session.commit()
    authenticate(client, user)

    response = client.get("/api/learning/metrics")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["n_feedback_events"] == 1
    assert body["alignment_pct"] == 1.0
    assert body["synthetic"] is False  # no synthetic marker rows for this tenant


def test_suppressions_endpoints_list_and_accept(
    client: TestClient, learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="API Suppressions Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-suppress-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig = make_signal(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        detector_key="sigma.non_browser_user_agent",
        entity_type="src_ip",
        entity_value="203.0.113.99",
    )
    incident, _verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[sig]
    )
    learning_session.commit()
    authenticate(client, user)

    fb_response = client.post(
        f"/api/incidents/{incident.id}/feedback",
        json={"agrees": False, "dismissal_reason": "API-generated candidate for accept test"},
    )
    assert fb_response.status_code == 200, fb_response.text
    candidate_id = fb_response.json()["suppression_candidates_generated"][0]

    list_response = client.get("/api/learning/suppressions")
    assert list_response.status_code == 200
    ids = {item["id"] for item in list_response.json()["items"]}
    assert candidate_id in ids

    written_path = None
    try:
        accept_response = client.post(f"/api/learning/suppressions/{candidate_id}/accept")
        assert accept_response.status_code == 200, accept_response.text
        accepted = accept_response.json()
        assert accepted["status"] == "accepted"
        written_path = accepted["written_path"]
        assert written_path.startswith("app/detection/rules/suppressions/")
        assert (_BACKEND_ROOT / written_path).exists()

        # Accepted candidates no longer show up in the default (pending) listing.
        list_after = client.get("/api/learning/suppressions")
        ids_after = {item["id"] for item in list_after.json()["items"]}
        assert candidate_id not in ids_after

        accepted_listing = client.get(
            "/api/learning/suppressions", params={"status_filter": "accepted"}
        )
        accepted_ids = {item["id"] for item in accepted_listing.json()["items"]}
        assert candidate_id in accepted_ids
    finally:
        if written_path is not None:
            (_BACKEND_ROOT / written_path).unlink(missing_ok=True)


def test_suppressions_accept_404_for_unknown_candidate(
    client: TestClient, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="API Suppressions 404 Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-suppress-404-{uuid.uuid4()}@test.local")
    authenticate(client, user)

    response = client.post(f"/api/learning/suppressions/{uuid.uuid4()}/accept")
    assert response.status_code == 404


def test_models_calibration_endpoint_requires_auth(client: TestClient) -> None:
    response = client.get("/api/models/calibration")
    assert response.status_code == 401


def test_models_calibration_endpoint_reflects_feedback(
    client: TestClient, learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="API Calibration Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-calib-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    detector_key = f"test.api.calib.{uuid.uuid4().hex[:8]}"

    for i in range(6):
        sig = make_signal(
            learning_session,
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            detector_key=detector_key,
            raw_score=0.6,
            confidence=0.6,
        )
        _incident, verdict = make_incident_with_verdict(
            learning_session,
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            signals=[sig],
            disposition="true_positive" if i < 2 else "false_positive",
            fused_score=0.6,
        )
        make_feedback(learning_session, verdict_id=verdict.id, user_id=user.id, agrees=True)
    learning_session.commit()
    authenticate(client, user)

    response = client.get("/api/models/calibration")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["n_feedback_events"] == 6
    detector_payload = next(d for d in body["detectors"] if d["detector_key"] == detector_key)
    assert detector_payload["fitted"] is True
    assert len(detector_payload["reliability_after"]) == 10


def test_models_versions_endpoint_requires_auth(client: TestClient) -> None:
    response = client.get("/api/models/versions")
    assert response.status_code == 401


def test_models_versions_endpoint_returns_a_list(
    client: TestClient, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="API Versions Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"api-versions-{uuid.uuid4()}@test.local")
    authenticate(client, user)

    response = client.get("/api/models/versions")
    assert response.status_code == 200
    assert isinstance(response.json()["items"], list)
