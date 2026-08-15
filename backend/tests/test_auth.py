"""POST /api/auth/login, POST /api/auth/logout, GET /api/auth/me — docs/09 + docs/06.

Covers: argon2id hashing, the session + CSRF cookie pair and their SameSite/Secure
branch (Lax/non-Secure on local, None/Secure everywhere else — see
app.core.security.cookie_security_flags and docs/06's "SameSite decision record"),
the *identical* generic failure for an unknown email vs. a wrong password,
server-side route protection on /me, and the 5/min login rate limit.

The CSRF *enforcement* behaviour itself (missing/wrong/valid token, Origin
validation) lives in tests/test_csrf.py, not here.
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from pydantic import SecretStr
from starlette.responses import Response

from app.core.config import Settings, get_settings
from app.core.csrf import CSRF_COOKIE_NAME, derive_csrf_token, issue_csrf_cookie
from app.core.security import (
    COOKIE_NAME,
    cookie_security_flags,
    set_session_cookie,
    verify_password,
)
from tests.conftest import authenticate, make_tenant, make_user

# Mirrors tests/test_config.py's REAL fixture — a non-local Settings needs every
# dev-secret sentinel replaced or it refuses to construct (app.core.config).
_REAL_PRODUCTION_SECRETS = {
    "jwt_secret": SecretStr("a-real-48-byte-secret-from-the-environment"),
    "pseudonym_salt": SecretStr("a-real-per-tenant-salt"),
    "s3_secret_key": SecretStr("a-real-object-store-key"),
}


def _production_settings() -> Settings:
    return Settings(_env_file=None, environment="production", **_REAL_PRODUCTION_SECRETS)


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
    assert CSRF_COOKIE_NAME in response.cookies

    # httpx's `response.cookies` collapses same-named attributes across the multiple
    # Set-Cookie headers in this response, so assert per-cookie flags off the raw
    # header lines instead of the joined `set-cookie` string used below for the
    # session cookie's own flags.
    raw_set_cookie_headers = response.headers.get_list("set-cookie")
    session_set_cookie = next(h for h in raw_set_cookie_headers if h.startswith(f"{COOKIE_NAME}="))
    csrf_set_cookie = next(
        h for h in raw_set_cookie_headers if h.startswith(f"{CSRF_COOKIE_NAME}=")
    )

    assert "HttpOnly" in session_set_cookie
    # The CSRF cookie must be JS-readable — that's the entire double-submit
    # mechanism (app.core.csrf) — so it must NOT be httpOnly.
    assert "HttpOnly" not in csrf_set_cookie

    # Session and CSRF cookies must always agree on SameSite/Secure (both flow from
    # app.core.security.cookie_security_flags) — Lax/non-Secure on local, since a
    # Secure cookie is silently dropped over the plain HTTP the reviewer/curl use
    # against localhost; None/Secure everywhere else, since Vercel + Fly are
    # different registrable domains and Lax cookies never ride along on a cross-site
    # fetch/XHR. See docs/06-PRIVACY-SECURITY.md, "SameSite decision record".
    for set_cookie in (session_set_cookie, csrf_set_cookie):
        if get_settings().environment == "local":
            assert "secure" not in set_cookie.lower()
            assert "samesite=lax" in set_cookie.lower()
        else:
            assert "Secure" in set_cookie
            assert "samesite=none" in set_cookie.lower()

    # The CSRF cookie's value is exactly what a mutating request's header must equal
    # — this is the double-submit contract end to end, not just "some cookie exists".
    session_token = response.cookies[COOKIE_NAME]
    assert response.cookies[CSRF_COOKIE_NAME] == derive_csrf_token(session_token)


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
    # Logout must clear *both* cookies (app.core.auth.logout calls clear_session_cookie
    # and clear_csrf_cookie) — check each Set-Cookie line individually rather than the
    # joined string, so a bug that clears one but not the other can't hide behind the
    # other cookie's "max-age=0" substring.
    raw_set_cookie_headers = logout_response.headers.get_list("set-cookie")
    session_set_cookie = next(h for h in raw_set_cookie_headers if h.startswith(f"{COOKIE_NAME}="))
    csrf_set_cookie = next(
        h for h in raw_set_cookie_headers if h.startswith(f"{CSRF_COOKIE_NAME}=")
    )
    assert "max-age=0" in session_set_cookie.lower()
    assert "max-age=0" in csrf_set_cookie.lower()

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


# --- SameSite/Secure branch (docs/06 "SameSite decision record") -----------------
#
# The live suite always runs with environment=local (backend/.env, and CI sets no
# ENVIRONMENT so the Settings default applies), so the tests above only ever exercise
# the Lax/non-Secure branch end to end through a real request. These tests exercise
# the None/Secure branch directly against a real (non-local) Settings object and a
# real Starlette Response — no mocking of cookie_security_flags itself — which is the
# most direct way to prove that branch's actual behaviour without standing up a
# second deployment.


def test_cookie_security_flags_is_lax_and_not_secure_on_local() -> None:
    local_settings = Settings(_env_file=None, environment="local")
    assert cookie_security_flags(local_settings) == (False, "lax")


def test_cookie_security_flags_is_none_and_secure_outside_local() -> None:
    for env in ("staging", "production"):
        settings = Settings(_env_file=None, environment=env, **_REAL_PRODUCTION_SECRETS)
        assert cookie_security_flags(settings) == (True, "none")


def _raw_set_cookie_headers(response: Response) -> list[str]:
    """`starlette.responses.Response.headers` (a `MutableHeaders`) has no `get_list` —
    that's an httpx.Headers method, only reachable through TestClient responses.
    Decode `.raw` directly instead so this works against a bare Response too."""
    return [v.decode() for k, v in response.headers.raw if k.decode().lower() == "set-cookie"]


def test_session_cookie_is_none_and_secure_outside_local() -> None:
    response = Response()
    set_session_cookie(response, "a-jwt-would-go-here", settings=_production_settings())

    set_cookie = next(
        h for h in _raw_set_cookie_headers(response) if h.startswith(f"{COOKIE_NAME}=")
    )
    assert "Secure" in set_cookie
    assert "samesite=none" in set_cookie.lower()
    assert "HttpOnly" in set_cookie


def test_csrf_cookie_is_none_and_secure_outside_local() -> None:
    response = Response()
    issue_csrf_cookie(response, "a-session-token", settings=_production_settings())

    set_cookie = next(
        h for h in _raw_set_cookie_headers(response) if h.startswith(f"{CSRF_COOKIE_NAME}=")
    )
    assert "Secure" in set_cookie
    assert "samesite=none" in set_cookie.lower()
    assert "HttpOnly" not in set_cookie
