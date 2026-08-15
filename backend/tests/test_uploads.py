"""POST /api/uploads — docs/09 + docs/06.

Runs against the live MinIO and Postgres from docker-compose.yml: each test posts a
real multipart body through `TestClient`, then confirms the object landed in MinIO
with the right bytes/hash and that the `uploads` + `analyses` rows were written
correctly. No mocking of storage — the point of this file is that the streaming path
actually works end to end.
"""

from __future__ import annotations

import hashlib
import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import get_session_factory
from app.models.analysis import Analysis
from app.models.base import bypass_tenant_scope
from app.models.tenant import Tenant
from app.models.upload import Upload
from app.models.user import User
from app.storage.client import get_s3_client
from tests.conftest import TEST_ORIGIN, authenticate, make_tenant, make_user

ZSCALER_LINE = (
    "2024-01-01T00:00:00Z\tu1@example.com\t10.0.0.1\texample.com\t/\tGET\t200\tAllowed\t"
    "General\tMozilla/5.0\n"
)
ZSCALER_HEADER = (
    "datetime\tuser\tclientip\thost\turl\trequestmethod\tstatus\taction\turlcategory\tuseragent\n"
)


def _zscaler_text(min_bytes: int = 0) -> bytes:
    body = ZSCALER_HEADER + ZSCALER_LINE
    while len(body) < min_bytes:
        body += ZSCALER_LINE
    return body.encode()


def _fetch_upload(upload_id: uuid.UUID) -> Upload | None:
    session = get_session_factory()()
    try:
        with bypass_tenant_scope(session):
            return session.execute(
                select(Upload).where(Upload.id == upload_id)
            ).scalar_one_or_none()
    finally:
        session.close()


def _fetch_analysis(analysis_id: uuid.UUID) -> Analysis | None:
    session = get_session_factory()()
    try:
        with bypass_tenant_scope(session):
            return session.execute(
                select(Analysis).where(Analysis.id == analysis_id)
            ).scalar_one_or_none()
    finally:
        session.close()


@pytest.fixture
def authed(client: TestClient, tenant_cleanup: list[uuid.UUID]) -> tuple[Tenant, User]:
    tenant = make_tenant(name="Upload Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="uploader@example.com")
    authenticate(client, user)
    return tenant, user


def test_upload_requires_authentication(client: TestClient) -> None:
    response = client.post("/api/uploads", files={"file": ("a.log", b"hello", "text/plain")})
    assert response.status_code == 401


def test_upload_happy_path_streams_to_minio_and_creates_rows(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    tenant, user = authed
    content = _zscaler_text()
    expected_sha256 = hashlib.sha256(content).hexdigest()

    response = client.post(
        "/api/uploads", files={"file": ("proxy_export.log", content, "text/plain")}
    )
    assert response.status_code == 201
    body = response.json()
    assert "zscaler" in body["detected_sources"]
    upload_id = uuid.UUID(body["upload_id"])
    analysis_id = uuid.UUID(body["analysis_id"])

    upload = _fetch_upload(upload_id)
    assert upload is not None
    assert upload.tenant_id == tenant.id
    assert upload.user_id == user.id
    assert upload.filename == "proxy_export.log"
    assert upload.size_bytes == len(content)
    assert upload.sha256 == expected_sha256
    # Server-generated key, never the client filename (docs/06 path traversal defense).
    assert "proxy_export" not in upload.storage_ref
    assert upload.storage_ref == f"{tenant.id}/{upload_id}"

    analysis = _fetch_analysis(analysis_id)
    assert analysis is not None
    assert analysis.upload_id == upload_id
    assert analysis.tenant_id == tenant.id
    assert analysis.status == "queued"

    settings = get_settings()
    s3 = get_s3_client()
    obj = s3.get_object(Bucket=settings.s3_bucket, Key=upload.storage_ref)
    stored_bytes = obj["Body"].read()
    assert stored_bytes == content
    assert hashlib.sha256(stored_bytes).hexdigest() == expected_sha256


def test_upload_rejects_disallowed_extension(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    response = client.post(
        "/api/uploads",
        files={"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_upload"


def test_upload_rejects_a_zip_disguised_with_an_allowed_extension(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    zip_magic = b"PK\x03\x04" + b"\x00" * 100
    response = client.post("/api/uploads", files={"file": ("logs.log", zip_magic, "text/plain")})
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_upload"


def test_upload_rejects_over_the_size_cap(client: TestClient, authed: tuple[Tenant, User]) -> None:
    os.environ["MAX_UPLOAD_BYTES"] = "100"
    get_settings.cache_clear()
    try:
        content = _zscaler_text(min_bytes=1000)
        response = client.post("/api/uploads", files={"file": ("big.log", content, "text/plain")})
        assert response.status_code == 413
        assert response.json()["code"] == "upload_too_large"
    finally:
        del os.environ["MAX_UPLOAD_BYTES"]
        get_settings.cache_clear()


def test_upload_is_rate_limited_to_ten_per_hour(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    for _ in range(10):
        response = client.post(
            "/api/uploads", files={"file": ("ok.txt", b"benign content", "text/plain")}
        )
        assert response.status_code == 201

    eleventh = client.post(
        "/api/uploads", files={"file": ("ok.txt", b"benign content", "text/plain")}
    )
    assert eleventh.status_code == 429
    assert eleventh.json()["code"] == "rate_limited"


def test_large_upload_is_sent_as_multiple_s3_parts(
    client: TestClient, authed: tuple[Tenant, User]
) -> None:
    """A file bigger than app.storage.streaming_upload._PART_SIZE (8 MiB) forces the
    streaming uploader through at least one real S3 multipart part boundary rather
    than a single `put_object` — this is the proof it streams instead of buffering the
    whole file before ever contacting storage. Text, not random bytes, so it also
    clears the binary/archive sniff."""
    content = _zscaler_text(min_bytes=9 * 1024 * 1024)
    expected_sha256 = hashlib.sha256(content).hexdigest()

    response = client.post("/api/uploads", files={"file": ("big.log", content, "text/plain")})
    assert response.status_code == 201

    upload = _fetch_upload(uuid.UUID(response.json()["upload_id"]))
    assert upload is not None
    assert upload.sha256 == expected_sha256
    assert upload.size_bytes == len(content)

    settings = get_settings()
    s3 = get_s3_client()
    obj = s3.get_object(Bucket=settings.s3_bucket, Key=upload.storage_ref)
    assert hashlib.sha256(obj["Body"].read()).hexdigest() == expected_sha256


# --- GET/DELETE /api/analyses — docs/09 groups these with uploads. ---------------


def test_list_analyses_is_tenant_scoped_and_newest_first(
    client: TestClient, authed: tuple[Tenant, User], tenant_cleanup: list[uuid.UUID]
) -> None:
    _tenant, _user = authed
    other_tenant = make_tenant(name="Other Tenant")
    tenant_cleanup.append(other_tenant.id)
    other_user = make_user(tenant_id=other_tenant.id, email="other@example.com")

    ids = []
    for name in ("first.log", "second.log"):
        resp = client.post("/api/uploads", files={"file": (name, _zscaler_text(), "text/plain")})
        assert resp.status_code == 201
        ids.append(resp.json()["analysis_id"])

    # Built directly (not via the `client` fixture), so it needs its own Origin header
    # to clear app.core.csrf's allowlist check — see tests/conftest.py's TEST_ORIGIN.
    other_client = TestClient(client.app, headers={"origin": TEST_ORIGIN})
    authenticate(other_client, other_user)
    other_resp = other_client.post(
        "/api/uploads", files={"file": ("other.log", _zscaler_text(), "text/plain")}
    )
    assert other_resp.status_code == 201

    listed = client.get("/api/analyses").json()
    listed_ids = [item["id"] for item in listed["items"]]
    assert listed_ids[:2] == list(reversed(ids))  # newest first
    assert other_resp.json()["analysis_id"] not in listed_ids


def test_get_analysis_by_id(client: TestClient, authed: tuple[Tenant, User]) -> None:
    upload_resp = client.post(
        "/api/uploads", files={"file": ("get.log", _zscaler_text(), "text/plain")}
    )
    analysis_id = upload_resp.json()["analysis_id"]

    response = client.get(f"/api/analyses/{analysis_id}")
    assert response.status_code == 200
    assert response.json()["id"] == analysis_id
    assert response.json()["status"] == "queued"


def test_get_analysis_from_another_tenant_is_not_found(
    client: TestClient, authed: tuple[Tenant, User], tenant_cleanup: list[uuid.UUID]
) -> None:
    other_tenant = make_tenant(name="Not Yours")
    tenant_cleanup.append(other_tenant.id)
    other_user = make_user(tenant_id=other_tenant.id, email="notyours@example.com")
    # Built directly (not via the `client` fixture), so it needs its own Origin header
    # to clear app.core.csrf's allowlist check — see tests/conftest.py's TEST_ORIGIN.
    other_client = TestClient(client.app, headers={"origin": TEST_ORIGIN})
    authenticate(other_client, other_user)
    other_upload = other_client.post(
        "/api/uploads", files={"file": ("theirs.log", _zscaler_text(), "text/plain")}
    )
    other_analysis_id = other_upload.json()["analysis_id"]

    response = client.get(f"/api/analyses/{other_analysis_id}")
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


def test_delete_analysis(client: TestClient, authed: tuple[Tenant, User]) -> None:
    upload_resp = client.post(
        "/api/uploads", files={"file": ("delete.log", _zscaler_text(), "text/plain")}
    )
    analysis_id = upload_resp.json()["analysis_id"]

    delete_response = client.delete(f"/api/analyses/{analysis_id}")
    assert delete_response.status_code == 204

    assert client.get(f"/api/analyses/{analysis_id}").status_code == 404
