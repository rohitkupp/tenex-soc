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
from datetime import UTC, datetime

import anthropic
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.csrf import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, derive_csrf_token
from app.core.db import get_engine, get_session_factory
from app.core.rate_limit import limiter
from app.core.security import COOKIE_NAME, create_access_token, hash_password
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.tenant import Tenant
from app.models.upload import Upload
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


@pytest.fixture(autouse=True)
def _forbid_live_anthropic_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """change 25's LLM row: "recorded fixtures, zero live calls in CI" — a structural guarantee
    for the whole suite, not an absence-of-evidence claim. `app.agent.client.LiveCaller` is the
    only thing in this codebase that ever constructs `anthropic.Anthropic`, reached from three,
    all API-key-gated, production call sites (`app.agent.orchestrator.triage_incident`'s
    `caller or LiveCaller(...)` fallback, `app.api.analyses`'s two narrate/triage routes) — every
    test in this suite instead injects a scripted caller (`tests/test_agent_orchestrator.py`'s
    `_RecordingCaller`, `app.agent.client.FixtureCaller`/`RecordingCaller`) or monkeypatches the
    higher-level function around it (`tests/test_overview_evidence_api.py`'s `_fake_narrate`/
    `_fake_assess`). A few of those tests *do* legitimately construct a real `LiveCaller` (with a
    fake key, exercising the `llm_enabled=True` wiring) without ever calling it — so this blocks
    the actual network boundary, `Messages.create` (what `LiveCaller.create` calls), not
    `Anthropic.__init__` itself, which does no I/O on its own. A test (or a future change to any
    of those three call sites) that slips past every mock and reaches a real `.messages.create(
    )` fails immediately and loudly, everywhere, rather than this guarantee resting on "nothing
    has tried it yet". Scoped to this one SDK method (not a blanket socket block, unlike
    `test_agent_mitre.py::test_no_network_calls_at_runtime`) because plenty of legitimate traffic
    — Postgres, RabbitMQ, Redis, MinIO — shares this same process during the suite."""

    def _blocked_create(self: object, *_args: object, **_kwargs: object) -> None:
        raise AssertionError(
            "a test called the real anthropic Messages.create — CI must never make a live LLM "
            "call (CLAUDE.md rule 7); inject a scripted caller (FixtureCaller/RecordingCaller/"
            "_RecordingCaller) or monkeypatch the higher-level function around it instead"
        )

    monkeypatch.setattr(anthropic.resources.messages.Messages, "create", _blocked_create)


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


# M15: default `make_user` to an already-verified account. Computed once, at import
# time, rather than freshly per call — every consumer only ever asserts NULL-ness
# (never recency), so a fixed real timestamp is exactly as good as a live one and
# avoids a datetime.now() call on every one of this fixture's (many) call sites.
# Almost every existing test that calls `make_user` predates M15 and only cares about
# authenticating, not about the verification gate itself — defaulting to verified is
# what keeps all of them passing unchanged. Pass `email_verified_at=None` explicitly
# to build the unverified account tests/test_auth_signup.py's login tests need.
_DEFAULT_VERIFIED_AT = datetime.now(UTC)


def make_user(
    *,
    tenant_id: uuid.UUID,
    email: str,
    password: str = "correct horse battery",
    email_verified_at: datetime | None = _DEFAULT_VERIFIED_AT,
) -> User:
    session = get_session_factory()()
    try:
        # session.refresh() below issues a SELECT, and User is tenant-scoped
        # (app.models.base) — same rule as any other code, test helpers included.
        with tenant_scope(session, tenant_id):
            user = User(
                tenant_id=tenant_id,
                email=email,
                password_hash=hash_password(password),
                email_verified_at=email_verified_at,
            )
            session.add(user)
            session.commit()
            session.refresh(user)
        return user
    finally:
        session.close()


def make_analysis(
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    filename: str = "events.log",
    detected_sources: list[str] | None = None,
    storage_ref: str | None = None,
) -> Analysis:
    """A real `uploads` + `analyses` row pair, for M4's pipeline tests
    (`tests/test_pipeline_*.py`, `tests/test_ops_*.py`) — the same 1:1 creation
    `app.api.uploads.create_upload` does, without going through the HTTP layer or
    actually touching MinIO (pipeline tests exercise the queue/DB/Redis side; the parse
    stage's own tests are responsible for real MinIO objects)."""
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            upload = Upload(
                tenant_id=tenant_id,
                user_id=user_id,
                filename=filename,
                size_bytes=1,
                sha256="a" * 64,
                storage_ref=storage_ref or f"{tenant_id}/{uuid.uuid4()}",
                detected_sources=detected_sources or [],
            )
            session.add(upload)
            session.flush()
            analysis = Analysis(tenant_id=tenant_id, upload_id=upload.id, status="queued")
            session.add(analysis)
            session.commit()
            session.refresh(analysis)
        return analysis
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
