"""ORM model shape and DB-enforced constraints for the M1 Core tables
(docs/02-DATA-MODEL.md), against the real Postgres from docker-compose.yml.

Tenant-scoping *behaviour* (the actual isolation guarantee) is covered by
test_tenant_isolation.py; this file is about the schema itself: defaults, the CITEXT
case-insensitive uniqueness on `users.email`, foreign keys, and the fact that
`analyses` deliberately has no `created_at` column (see app/models/analysis.py).
"""

from __future__ import annotations

import secrets
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.core.db import get_engine, get_session_factory
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.tenant import Tenant
from app.models.upload import Upload
from app.models.user import User
from tests.conftest import make_tenant, make_user


def test_tenant_defaults_id_and_created_at(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant = make_tenant(name="Acme")
    tenant_cleanup.append(tenant.id)

    assert isinstance(tenant.id, uuid.UUID)
    assert tenant.created_at is not None
    assert tenant.name == "Acme"


def test_user_email_is_unique_case_insensitively(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    make_user(tenant_id=tenant.id, email="Case@Example.com")

    session = get_session_factory()()
    try:
        # CITEXT: a case-different duplicate of an existing email violates the unique
        # constraint, matching docs/02's `email CITEXT UNIQUE NOT NULL`.
        session.add(User(tenant_id=tenant.id, email="case@example.com", password_hash="x"))
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.rollback()
        session.close()


def test_user_email_lookup_is_case_insensitive(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    make_user(tenant_id=tenant.id, email="Mixed@Example.com")

    with get_engine().connect() as conn:
        row = conn.execute(
            text("SELECT id FROM users WHERE email = :email"), {"email": "mixed@example.com"}
        ).first()
    assert row is not None


def test_upload_detected_sources_defaults_to_empty_array(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="uploader@example.com")

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant.id):
            upload = Upload(
                tenant_id=tenant.id,
                user_id=user.id,
                filename="access.log",
                size_bytes=123,
                sha256="a" * 64,
                storage_ref=f"{tenant.id}/{uuid.uuid4()}",
            )
            session.add(upload)
            session.commit()
            session.refresh(upload)
        assert upload.detected_sources == []
    finally:
        session.close()


def test_analysis_defaults(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="analyst@example.com")

    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant.id):
            upload = Upload(
                tenant_id=tenant.id,
                user_id=user.id,
                filename="events.jsonl",
                size_bytes=1,
                sha256="b" * 64,
                storage_ref=f"{tenant.id}/{uuid.uuid4()}",
            )
            session.add(upload)
            session.flush()

            analysis = Analysis(tenant_id=tenant.id, upload_id=upload.id)
            session.add(analysis)
            session.commit()
            session.refresh(analysis)

        assert analysis.status == "queued"
        assert analysis.progress == 0.0
        assert analysis.pending_parsers == 0
        assert analysis.counters == {}
        assert analysis.stage is None
        assert analysis.started_at is None
        assert analysis.finished_at is None
    finally:
        session.close()


def test_analyses_table_has_no_created_at_column() -> None:
    """docs/02-DATA-MODEL.md's `analyses` table has no `created_at` — matched exactly.
    See app/models/analysis.py for how list ordering works without it."""
    assert "created_at" not in Analysis.__table__.columns.keys()  # noqa: SIM118


def test_upload_rejects_unknown_tenant_id() -> None:
    """tenant_id is a real foreign key (docs/02: `REFERENCES tenants(id)`), not just a
    column developers are trusted to populate correctly."""
    session = get_session_factory()()
    try:
        bogus_tenant_id = uuid.uuid4()
        session.add(
            Upload(
                tenant_id=bogus_tenant_id,
                user_id=uuid.uuid4(),
                filename="x.log",
                size_bytes=1,
                sha256="c" * 64,
                storage_ref="nowhere",
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.rollback()
        session.close()


def test_tenant_pseudonym_salt_is_required() -> None:
    session = get_session_factory()()
    try:
        session.add(Tenant(name="No Salt", pseudonym_salt=None))  # type: ignore[arg-type]
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.rollback()
        session.close()


def test_tenant_pseudonym_salt_round_trips_bytes(tenant_cleanup: list[uuid.UUID]) -> None:
    salt = secrets.token_bytes(32)
    session = get_session_factory()()
    try:
        tenant = Tenant(name="Salted", pseudonym_salt=salt)
        session.add(tenant)
        session.commit()
        session.refresh(tenant)
        tenant_cleanup.append(tenant.id)
        assert bytes(tenant.pseudonym_salt) == salt
    finally:
        session.close()
