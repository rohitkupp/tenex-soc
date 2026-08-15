"""Proves the structural tenant-isolation guarantee in app/models/base.py against the
real Postgres — not a mock, so a bug in the SQL SQLAlchemy actually emits would show
up here exactly as it would in production.

docs/06-PRIVACY-SECURITY.md: tenant isolation must be "enforce[d] via a SQLAlchemy
base query class, not by remembering." The tests below are the proof: a forgotten
tenant filter raises before touching the database (never returns another tenant's
rows), and a correctly tenant-bound session cannot see across tenants even when the
query itself has no `WHERE tenant_id = ...` at all — for SELECT, bulk UPDATE, and bulk
DELETE alike.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select, update

from app.core.db import get_session_factory
from app.models.base import (
    MissingTenantScopeError,
    bypass_tenant_scope,
    tenant_scope,
    tenant_session,
)
from app.models.upload import Upload
from app.models.user import User
from tests.conftest import make_tenant, make_user


@pytest.fixture
def two_tenants(tenant_cleanup: list[uuid.UUID]) -> tuple[User, User]:
    """Tenant A / User A and Tenant B / User B — the minimal fixture every isolation
    test in this file needs."""
    tenant_a = make_tenant(name="Tenant A")
    tenant_b = make_tenant(name="Tenant B")
    tenant_cleanup.extend([tenant_a.id, tenant_b.id])
    user_a = make_user(tenant_id=tenant_a.id, email="a@tenant-a.example")
    user_b = make_user(tenant_id=tenant_b.id, email="b@tenant-b.example")
    return user_a, user_b


def test_bare_session_raises_instead_of_leaking(two_tenants: tuple[User, User]) -> None:
    """The headline guarantee: forgetting to scope a session is a loud exception, not
    a silent cross-tenant read."""
    session = get_session_factory()()
    try:
        with pytest.raises(MissingTenantScopeError):
            session.execute(select(User))
    finally:
        session.close()


def test_tenant_session_sees_only_its_own_rows(two_tenants: tuple[User, User]) -> None:
    user_a, user_b = two_tenants
    session = tenant_session(user_a.tenant_id)
    try:
        # Deliberately unfiltered — the point is that no manual WHERE is needed *or
        # possible to omit by mistake*.
        rows = session.execute(select(User)).scalars().all()
        seen_ids = {row.id for row in rows}
        assert user_a.id in seen_ids
        assert user_b.id not in seen_ids
    finally:
        session.close()


def test_cannot_fetch_another_tenants_row_even_by_primary_key(
    two_tenants: tuple[User, User],
) -> None:
    """A bug that guesses/leaks another tenant's row id still can't read it — the
    global criterion applies regardless of what the query's own WHERE clause says."""
    user_a, user_b = two_tenants
    session = tenant_session(user_a.tenant_id)
    try:
        result = session.execute(select(User).where(User.id == user_b.id)).scalar_one_or_none()
        assert result is None
    finally:
        session.close()


def test_tenant_scope_context_manager_nests_and_restores(
    two_tenants: tuple[User, User],
) -> None:
    user_a, user_b = two_tenants
    session = get_session_factory()()
    try:
        with tenant_scope(session, user_a.tenant_id):
            ids = {u.id for u in session.execute(select(User)).scalars().all()}
            assert ids == {user_a.id}

            with tenant_scope(session, user_b.tenant_id):
                ids = {u.id for u in session.execute(select(User)).scalars().all()}
                assert ids == {user_b.id}

            # Back out of the nested block: tenant A again, not unbound.
            ids = {u.id for u in session.execute(select(User)).scalars().all()}
            assert ids == {user_a.id}

        # Back out of the outer block entirely: unbound again.
        with pytest.raises(MissingTenantScopeError):
            session.execute(select(User))
    finally:
        session.close()


def test_bypass_tenant_scope_is_the_only_way_to_do_a_global_lookup(
    two_tenants: tuple[User, User],
) -> None:
    """This is exactly what app.api.auth.login does: resolve the tenant *from* a
    globally-unique email, which is impossible to do pre-scoped."""
    user_a, _user_b = two_tenants
    session = get_session_factory()()
    try:
        with pytest.raises(MissingTenantScopeError):
            session.execute(select(User).where(User.email == user_a.email))

        with bypass_tenant_scope(session):
            found = session.execute(
                select(User).where(User.email == user_a.email)
            ).scalar_one_or_none()
        assert found is not None
        assert found.id == user_a.id
    finally:
        session.close()


def test_bulk_update_is_scoped_too(two_tenants: tuple[User, User]) -> None:
    """`with_loader_criteria` applies to ORM-enabled bulk UPDATE, not just SELECT — an
    update with no WHERE at all still only touches the bound tenant's rows."""
    user_a, user_b = two_tenants
    session = tenant_session(user_a.tenant_id)
    try:
        session.execute(update(User).values(password_hash="rotated"))
        session.commit()
    finally:
        session.close()

    session = get_session_factory()()
    try:
        with bypass_tenant_scope(session):
            refreshed_a = session.get(User, user_a.id)
            refreshed_b = session.get(User, user_b.id)
        assert refreshed_a is not None
        assert refreshed_b is not None
        assert refreshed_a.password_hash == "rotated"
        assert refreshed_b.password_hash != "rotated"
    finally:
        session.close()


def test_bulk_delete_is_scoped_too(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant_a = make_tenant(name="Delete A")
    tenant_b = make_tenant(name="Delete B")
    tenant_cleanup.extend([tenant_a.id, tenant_b.id])
    user_a = make_user(tenant_id=tenant_a.id, email="del-a@example.com")
    user_b = make_user(tenant_id=tenant_b.id, email="del-b@example.com")

    session = get_session_factory()()
    try:
        upload_a = Upload(
            tenant_id=tenant_a.id,
            user_id=user_a.id,
            filename="a.log",
            size_bytes=1,
            sha256="d" * 64,
            storage_ref=f"{tenant_a.id}/{uuid.uuid4()}",
        )
        upload_b = Upload(
            tenant_id=tenant_b.id,
            user_id=user_b.id,
            filename="b.log",
            size_bytes=1,
            sha256="e" * 64,
            storage_ref=f"{tenant_b.id}/{uuid.uuid4()}",
        )
        session.add_all([upload_a, upload_b])
        session.commit()
    finally:
        session.close()

    # Delete-everything-in-Uploads, scoped to tenant A only.
    session = tenant_session(tenant_a.id)
    try:
        session.execute(delete(Upload))
        session.commit()
    finally:
        session.close()

    session = get_session_factory()()
    try:
        with bypass_tenant_scope(session):
            remaining_a = (
                session.execute(select(Upload).where(Upload.tenant_id == tenant_a.id))
                .scalars()
                .all()
            )
            remaining_b = (
                session.execute(select(Upload).where(Upload.tenant_id == tenant_b.id))
                .scalars()
                .all()
            )
    finally:
        session.close()

    assert remaining_a == []
    assert len(remaining_b) == 1
