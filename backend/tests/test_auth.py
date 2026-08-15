"""POST /api/auth/login, POST /api/auth/logout, GET /api/auth/me — docs/09 + docs/06.

Covers: argon2id hashing, the httpOnly/SameSite=Lax session cookie, the *identical*
generic failure for an unknown email vs. a wrong password, server-side route
protection on /me, and the 5/min login rate limit.
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.security import COOKIE_NAME, verify_password
from tests.conftest import authenticate, make_tenant, make_user


def test_password_hash_is_argon2id(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="hash@example.com", password="s3cret-passw0rd")

    assert user.password_hash.startswith("$argon2id$")
    assert verify_password("s3cret-passw0rd", user.password_hash)
    assert not verify_password("wrong-password", user.password_hash)


def test_login_succeeds_and_sets_session_cookie(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    make_user(tenant_id=tenant.id, email="login@example.com", password="correct-horse")

    response = client.post(
        "/api/auth/login", json={"email": "login@example.com", "password": "correct-horse"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == "login@example.com"
    assert body["user"]["tenant_id"] == str(tenant.id)
    assert "password" not in body["user"]
    assert COOKIE_NAME in response.cookies

    set_cookie = response.headers.get("set-cookie", "")
    assert "HttpOnly" in set_cookie
    assert "samesite=lax" in set_cookie.lower()
    # docs/06 mandates Secure; the one documented exception is local dev over plain
    # HTTP, where a Secure cookie would be silently dropped by curl/browsers alike.
    # See app.core.security.set_session_cookie.
    if get_settings().environment == "local":
        assert "secure" not in set_cookie.lower()
    else:
        assert "Secure" in set_cookie


def test_login_wrong_password_and_unknown_email_return_the_identical_error(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    make_user(tenant_id=tenant.id, email="known@example.com", password="the-real-password")

    wrong_password = client.post(
        "/api/auth/login", json={"email": "known@example.com", "password": "not-it"}
    )
    unknown_email = client.post(
        "/api/auth/login", json={"email": "nobody@example.com", "password": "not-it"}
    )

    assert wrong_password.status_code == 401
    assert unknown_email.status_code == 401
    # Never reveal whether the email exists (docs/06) — the bodies must be identical.
    assert wrong_password.json() == unknown_email.json()
    assert wrong_password.json() == {
        "detail": "Invalid email or password.",
        "code": "invalid_credentials",
    }
    assert COOKIE_NAME not in wrong_password.cookies


def test_logout_clears_cookie_and_revokes_access(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="logout@example.com")
    authenticate(client, user)

    assert client.get("/api/auth/me").status_code == 200

    logout_response = client.post("/api/auth/logout")
    assert logout_response.status_code == 204

    # Assert the server's deletion directive directly rather than relying on the test
    # client to act on it: httpx's cookie jar (stdlib `http.cookiejar`) does not honor
    # `Max-Age=0` the way a real browser does — verified empirically, the cookie stays
    # in TestClient's jar and gets resent on the next request regardless of Max-Age.
    # `max-age=0` (case-insensitive) is what tells a real browser to delete it now.
    set_cookie = logout_response.headers.get("set-cookie", "")
    assert "max-age=0" in set_cookie.lower()

    # Simulate what a spec-compliant browser does with that header, then confirm the
    # rest of the revocation flow (no cookie -> 401) actually works.
    client.cookies.delete(COOKIE_NAME)
    assert client.get("/api/auth/me").status_code == 401


def test_me_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert response.json()["code"] == "not_authenticated"


def test_me_returns_current_user_and_tenant(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Me Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="me@example.com")
    authenticate(client, user)

    response = client.get("/api/auth/me")
    assert response.status_code == 200
    body = response.json()
    assert body["user"]["id"] == str(user.id)
    assert body["user"]["email"] == "me@example.com"
    assert body["tenant"]["id"] == str(tenant.id)
    assert body["tenant"]["name"] == "Me Tenant"


def test_me_rejects_a_tampered_cookie(client: TestClient) -> None:
    client.cookies.set(COOKIE_NAME, "not-a-real-jwt")
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_session"


def test_login_is_rate_limited_to_five_per_minute(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    make_user(tenant_id=tenant.id, email="ratelimit@example.com", password="whatever-it-is")

    payload = {"email": "ratelimit@example.com", "password": "wrong"}
    statuses = [client.post("/api/auth/login", json=payload).status_code for _ in range(5)]
    assert statuses == [401, 401, 401, 401, 401]

    sixth = client.post("/api/auth/login", json=payload)
    assert sixth.status_code == 429
    assert sixth.json()["code"] == "rate_limited"
