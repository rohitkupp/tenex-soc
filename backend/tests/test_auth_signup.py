"""POST /api/auth/signup, /resend-verification, and the verification-aware parts of
POST /api/auth/login — M15, docs/09 + docs/06.

Every test here runs with `Settings.email_verification_enabled` False (the suite's
default — no `SUPABASE_URL`/`SUPABASE_SERVICE_ROLE_KEY` in `backend/.env`), so
`app.api.auth.signup`'s local/CI fallback is exercised on every call: new accounts are
stamped `email_verified_at` immediately rather than mailed a link nobody in this
environment could ever click. `test_signup_persists_user_even_when_the_verification_
email_fails_to_send` is the one exception — it monkeypatches verification "on" to
exercise the real Supabase-configured branch without a live Supabase project.

The CSRF *enforcement* behaviour itself lives in tests/test_csrf.py; the CSRF
*exemption* of signup/resend-verification is proven here (`test_signup_works_with_no_
csrf_token`) because it's part of these endpoints' own contract, not CSRF's.

**Change 23 (docs/v2_migration/MIGRATION-01-evidence-first.md, "Shared workspace,
single live tenant"): signup no longer mints a `Tenant`.** Every account here joins the
one live tenant (`app.models.tenant.LIVE_TENANT_NAME`/`get_or_create_live_tenant`),
which — unlike the throwaway tenants `tests/conftest.py`'s `make_tenant()` creates for
every other test file — is never torn down: it persists across the whole suite and
across `make seed` runs, the same as production. That is why every test below that
signs up a *new* account cleans up only the user it created (`signup_user_cleanup`,
by id) rather than `tenant_cleanup` (by `tenant_id`, which would delete the live
tenant's row and every other user/analysis under it out from under any other test or
seeded demo data). Tests that build their own throwaway tenant directly via
`make_tenant()` (not through signup) are unaffected and keep using `tenant_cleanup` as
before.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import func, select, text

import app.api.auth as auth_module
from app.core.config import Settings
from app.core.db import get_engine, get_session_factory
from app.core.security import COOKIE_NAME
from app.models.base import bypass_tenant_scope
from app.models.tenant import LIVE_TENANT_NAME, Tenant, get_or_create_live_tenant
from app.models.user import User
from tests.conftest import make_tenant, make_user

_STRONG_PASSWORD = "a-strong-password-1"  # 20 chars, well over the 12-char floor


def _fetch_user(email: str) -> User:
    session = get_session_factory()()
    try:
        with bypass_tenant_scope(session):
            return session.execute(select(User).where(User.email == email)).scalar_one()
    finally:
        session.close()


@pytest.fixture
def signup_user_cleanup() -> Iterator[list[uuid.UUID]]:
    """Deletes only the specific users a test created through `/api/auth/signup`, by
    id — never the tenant. See this module's docstring for why `tenant_cleanup` is the
    wrong tool once signup joins the shared live tenant."""
    created: list[uuid.UUID] = []
    yield created
    if not created:
        return
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM users WHERE id = ANY(:ids)"), {"ids": created})


def _count_tenants_named(name: str) -> int:
    session = get_session_factory()()
    try:
        return session.execute(
            select(func.count()).select_from(Tenant).where(Tenant.name == name)
        ).scalar_one()
    finally:
        session.close()


def test_signup_joins_the_live_tenant_and_creates_no_second_tenant(
    client: TestClient, signup_user_cleanup: list[uuid.UUID]
) -> None:
    """The change 23 contract, literally: "signup creates a user in the existing live
    tenant and does NOT create a second tenant." Counts tenants named
    `LIVE_TENANT_NAME` specifically (must stay exactly 1 across the signup) rather than
    every `tenants` row in the database — this suite's other files freely create and
    tear down their own, differently-named throwaway tenants
    (`tests/conftest.py::make_tenant`), so a global count would be a false-flaky
    assertion, not a more thorough one. `get_or_create_live_tenant` is called first so
    this test itself is what guarantees the tenant exists, closing the one genuine
    first-creation race that helper's own docstring documents."""
    session = get_session_factory()()
    try:
        live_tenant_before = get_or_create_live_tenant(session)
        session.commit()
    finally:
        session.close()

    count_before = _count_tenants_named(LIVE_TENANT_NAME)
    assert count_before == 1

    response = client.post(
        "/api/auth/signup",
        json={
            "email": "newsignup@example.com",
            "password": _STRONG_PASSWORD,
            "org_name": "Acme Corp",
        },
    )

    assert response.status_code == 201
    assert response.json() == {"status": "verification_sent", "email": "newsignup@example.com"}

    user = _fetch_user("newsignup@example.com")
    signup_user_cleanup.append(user.id)

    # No second tenant: still exactly one `northwind`, and the user landed in the live
    # tenant that already existed, not a fresh one named after `org_name` ("Acme Corp"
    # is accepted but ignored — see app.api.auth.signup).
    assert _count_tenants_named(LIVE_TENANT_NAME) == 1
    assert user.tenant_id == live_tenant_before.id
    assert user.password_hash.startswith("$argon2id$")
    # No Supabase configured in this suite -- signup's local/CI fallback stamps
    # verification immediately instead of leaving it NULL forever.
    assert user.email_verified_at is not None


def test_signup_with_already_registered_email_returns_identical_201_and_creates_no_second_user(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    make_user(tenant_id=tenant.id, email="taken@example.com")

    response = client.post(
        "/api/auth/signup",
        json={"email": "taken@example.com", "password": _STRONG_PASSWORD, "org_name": "Evil Corp"},
    )

    assert response.status_code == 201
    # Identical to a genuine signup's success body -- docs/06's enumeration guarantee.
    # Internally this path creates nothing and sends nothing.
    assert response.json() == {"status": "verification_sent", "email": "taken@example.com"}

    session = get_session_factory()()
    try:
        with bypass_tenant_scope(session):
            count = session.execute(
                select(func.count()).select_from(User).where(User.email == "taken@example.com")
            ).scalar_one()
    finally:
        session.close()
    assert count == 1


def test_signup_with_short_password_returns_400_weak_password(client: TestClient) -> None:
    response = client.post(
        "/api/auth/signup",
        json={"email": "shortpw@example.com", "password": "short1", "org_name": "Acme"},
    )

    assert response.status_code == 400
    assert response.json()["code"] == "weak_password"


def test_signup_works_with_no_csrf_token(
    client: TestClient, signup_user_cleanup: list[uuid.UUID]
) -> None:
    # The shared `client` fixture (tests/conftest.py) carries no CSRF cookie/header
    # unless `authenticate()` sets them, and this test never calls it -- proving
    # app.core.csrf._TOKEN_CHECK_EXEMPT_PATHS covers signup end to end through a real
    # request, not just by inspection of the exemption set.
    response = client.post(
        "/api/auth/signup",
        json={"email": "nocsrf@example.com", "password": _STRONG_PASSWORD, "org_name": "Acme"},
    )

    assert response.status_code == 201
    signup_user_cleanup.append(_fetch_user("nocsrf@example.com").id)


def test_signup_persists_user_even_when_the_verification_email_fails_to_send(
    client: TestClient, signup_user_cleanup: list[uuid.UUID], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Flip verification "on" without a live Supabase project, so this exercises the
    # branch that actually calls send_verification_email -- then make that call fail,
    # the way a down or rate-limiting mail provider would.
    monkeypatch.setattr(
        auth_module,
        "get_settings",
        lambda: Settings(
            _env_file=None,
            supabase_url="https://project.supabase.co",
            supabase_service_role_key=SecretStr("service-role-key"),
        ),
    )
    monkeypatch.setattr(auth_module, "send_verification_email", lambda email: False)

    response = client.post(
        "/api/auth/signup",
        json={"email": "emailfails@example.com", "password": _STRONG_PASSWORD, "org_name": "Acme"},
    )

    assert response.status_code == 201
    assert response.json() == {"status": "verification_sent", "email": "emailfails@example.com"}

    user = _fetch_user("emailfails@example.com")
    signup_user_cleanup.append(user.id)
    # A signup must not 500 (or silently vanish) because the email provider is down --
    # the account exists, unverified, and can retry via /api/auth/resend-verification.
    assert user.email_verified_at is None


def test_login_rejected_403_when_email_not_verified(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    make_user(
        tenant_id=tenant.id,
        email="unverified@example.com",
        password="correct-horse-battery",
        email_verified_at=None,
    )

    response = client.post(
        "/api/auth/login",
        json={"email": "unverified@example.com", "password": "correct-horse-battery"},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "email_not_verified"
    assert COOKIE_NAME not in response.cookies


def test_login_succeeds_once_email_is_verified(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    # make_user defaults to a verified account (tests/conftest.py) -- this is the
    # sibling of the 403 test above, same account shape, only the verification
    # timestamp differs.
    make_user(tenant_id=tenant.id, email="verified@example.com", password="correct-horse-battery")

    response = client.post(
        "/api/auth/login",
        json={"email": "verified@example.com", "password": "correct-horse-battery"},
    )

    assert response.status_code == 200
    assert COOKIE_NAME in response.cookies


def test_login_wrong_password_on_unverified_account_is_401_not_403(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    make_user(
        tenant_id=tenant.id,
        email="unverified-wrong@example.com",
        password="the-real-password",
        email_verified_at=None,
    )

    response = client.post(
        "/api/auth/login",
        json={"email": "unverified-wrong@example.com", "password": "not-the-password"},
    )

    # Proves the order app.api.auth.login documents: the password check runs first,
    # so a wrong password against an unverified account still produces the generic
    # 401 -- never the 403 that would confirm the account exists and merely isn't
    # verified yet.
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_credentials"


def test_resend_verification_returns_202_for_unknown_email(client: TestClient) -> None:
    response = client.post(
        "/api/auth/resend-verification", json={"email": "nobody-at-all@example.com"}
    )

    assert response.status_code == 202
    assert response.json() == {"status": "verification_sent", "email": "nobody-at-all@example.com"}
