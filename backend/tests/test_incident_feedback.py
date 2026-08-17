"""`POST /api/incidents/{id}/feedback` — the whole surviving feedback surface.

The 15-mechanism learning loop that used to consume feedback is deleted, so these tests assert
exactly two things and nothing more: the text lands in object storage under the incident's own
upload prefix, and the route is tenant-scoped. There is deliberately no test that feedback
changed a weight, a threshold, or a prompt, because it no longer does.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.storage.client import get_s3_client
from tests.conftest import authenticate, make_analysis, make_tenant, make_user
from tests.fixtures.response import (
    make_incident,
    response_tenant_cleanup,  # noqa: F401
)


@pytest.fixture
def ctx(response_tenant_cleanup: list[uuid.UUID]) -> dict[str, Any]:  # noqa: F811
    tenant = make_tenant()
    response_tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"analyst-{uuid.uuid4().hex[:8]}@corp.example")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    incident = make_incident(tenant_id=tenant.id, analysis_id=analysis.id)
    return {"tenant": tenant, "user": user, "analysis": analysis, "incident": incident}


def _body(client: TestClient, incident_id: uuid.UUID, text: str) -> Any:
    return client.post(f"/api/incidents/{incident_id}/feedback", json={"text": text})


def test_feedback_is_written_verbatim_under_the_incidents_own_upload_prefix(
    client: TestClient, ctx: dict
) -> None:
    """The storage key must sit under `{tenant_id}/{upload_id}/`, the same prefix
    `new_storage_key` gives the raw upload — that colocation is the whole point of the feature."""
    authenticate(client, ctx["user"])
    tenant, analysis, incident = ctx["tenant"], ctx["analysis"], ctx["incident"]

    text = "Disagree — svc-monitoring beacons on a 300s cron every night. Benign, not C2."
    res = _body(client, incident.id, text)

    assert res.status_code == 201, res.text
    key = res.json()["storage_key"]
    assert key.startswith(f"{tenant.id}/{analysis.upload_id}/feedback/{incident.id}/")
    assert key.endswith(".txt")

    stored = get_s3_client().get_object(Bucket=get_settings().s3_bucket, Key=key)
    assert stored["Body"].read().decode("utf-8") == text


def test_two_submissions_produce_two_objects_rather_than_overwriting(
    client: TestClient, ctx: dict
) -> None:
    """An analyst correcting themselves is information, not a typo to erase — the timestamped key
    is what keeps the first submission."""
    authenticate(client, ctx["user"])
    incident = ctx["incident"]

    first = _body(client, incident.id, "Looks like exfil.").json()["storage_key"]
    second = _body(client, incident.id, "Retracting — it was the backup job.").json()["storage_key"]

    assert first != second
    client_ = get_s3_client()
    bucket = get_settings().s3_bucket
    assert client_.get_object(Bucket=bucket, Key=first)["Body"].read() == b"Looks like exfil."


def test_feedback_on_another_tenants_incident_is_404_not_403(
    client: TestClient,
    ctx: dict,
    response_tenant_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """404, not 403: a tenant must not be able to confirm another tenant's incident exists by the
    shape of the error (docs/06). The incident is resolved through a tenant-scoped query, so the
    row is simply not found."""
    other = make_tenant()
    response_tenant_cleanup.append(other.id)
    other_user = make_user(tenant_id=other.id, email=f"other-{uuid.uuid4().hex[:8]}@corp.example")
    other_analysis = make_analysis(tenant_id=other.id, user_id=other_user.id)
    other_incident = make_incident(tenant_id=other.id, analysis_id=other_analysis.id)

    authenticate(client, ctx["user"])
    res = _body(client, other_incident.id, "should not be stored")

    assert res.status_code == 404


def test_empty_and_oversized_feedback_are_rejected(client: TestClient, ctx: dict) -> None:
    """Bounded so one request cannot stream an arbitrary object into the bucket, and non-empty so
    a stray click does not create a meaningless record."""
    authenticate(client, ctx["user"])
    incident = ctx["incident"]

    assert _body(client, incident.id, "").status_code == 422
    assert _body(client, incident.id, "x" * 8_001).status_code == 422
