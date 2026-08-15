"""Shared fixtures for the M1 backend tests. These run against the live Postgres
from docker-compose.yml (see backend/.env for the DSN) rather than a mock — the whole
point of `test_tenant_isolation.py` is proving the *real* database only ever returns
one tenant's rows.

Every row created by a test is deleted in fixture teardown, keyed off the tenant ids
it registers with `tenant_cleanup` — deleting by `tenant_id` sweeps whatever the test
created under it (users, uploads, analyses) regardless of exactly what was tracked.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.csrf import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, derive_csrf_token
from app.core.db import get_engine, get_session_factory
from app.core.rate_limit import limiter
from app.core.security import COOKIE_NAME, create_access_token, hash_password
from app.models.base import tenant_scope
from app.models.tenant import Tenant
from app.models.user import User

# The default (and, in these tests, only) entry in Settings.cors_origins — see
# backend/app/core/config.py and backend/.env. Requests from the shared `client`
# fixture carry this as their Origin header so app.core.csrf's Origin/Referer
# allowlist check (a defense-in-depth control this milestone adds, independent of the
# CSRF token) doesn't reject every existing test by default. tests/test_csrf.py is
# where that check itself gets exercised, including with a *foreign* origin.
TEST_ORIGIN = "http://localhost:3000"


@pytest.fixture(autouse=True)
def _reset_rate_limits() -> None:
    """Every test gets a clean slowapi bucket. `limiter` is one process-wide instance
    (app.core.rate_limit) shared by every request TestClient makes, which always
    reports the same source address — without this, an earlier test's login/upload
    calls would trip a later test's rate-limit assertions."""
    limiter.reset()


@pytest.fixture
def tenant_cleanup() -> Iterator[list[uuid.UUID]]:
    created: list[uuid.UUID] = []
    yield created
    if not created:
        return
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM analyses WHERE tenant_id = ANY(:ids)"), {"ids": created})
        conn.execute(text("DELETE FROM uploads WHERE tenant_id = ANY(:ids)"), {"ids": created})
        conn.execute(text("DELETE FROM users WHERE tenant_id = ANY(:ids)"), {"ids": created})
        conn.execute(text("DELETE FROM tenants WHERE id = ANY(:ids)"), {"ids": created})


def make_tenant(*, name: str = "Test Tenant") -> Tenant:
    session = get_session_factory()()
    try:
        tenant = Tenant(name=name, pseudonym_salt=secrets.token_bytes(16))
        session.add(tenant)
        session.commit()
        session.refresh(tenant)
        return tenant
    finally:
        session.close()


def make_user(*, tenant_id: uuid.UUID, email: str, password: str = "correct horse battery") -> User:
    session = get_session_factory()()
    try:
        # session.refresh() below issues a SELECT, and User is tenant-scoped
        # (app.models.base) — same rule as any other code, test helpers included.
        with tenant_scope(session, tenant_id):
            user = User(tenant_id=tenant_id, email=email, password_hash=hash_password(password))
            session.add(user)
            session.commit()
            session.refresh(user)
        return user
    finally:
        session.close()


@pytest.fixture
def client() -> TestClient:
    from app.main import app

    return TestClient(app, headers={"origin": TEST_ORIGIN})


def authenticate(client: TestClient, user: User) -> None:
    """Set a valid session cookie directly, bypassing the real /api/auth/login call.
    Used by tests that need an authenticated session but aren't themselves testing
    login — keeps their setup from eating into login's 5/min rate-limit bucket.

    Also seeds the matching CSRF cookie *and* a default `X-CSRF-Token` header on this
    client, mirroring what a real login response + a well-behaved frontend would do
    (app.core.csrf) — so tests that authenticate this way but aren't themselves about
    CSRF (almost all of them) don't have to think about it. tests/test_csrf.py is
    where that default gets deliberately overridden or removed to exercise the real
    checks.
    """
    token = create_access_token(user_id=user.id, tenant_id=user.tenant_id)
    client.cookies.set(COOKIE_NAME, token)
    csrf_token = derive_csrf_token(token)
    client.cookies.set(CSRF_COOKIE_NAME, csrf_token)
    client.headers[CSRF_HEADER_NAME] = csrf_token
