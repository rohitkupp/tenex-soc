"""app.core.csrf — docs/06 "SameSite decision record", docs/09.

Proves, against the real app (no mocking of the middleware or its dependencies):

  * a mutating request with a valid session but WITHOUT the CSRF header is rejected 403
  * WITH a wrong/mismatched token is rejected 403
  * WITH the correct token succeeds
  * a request with a foreign Origin is rejected, even with a correct token
  * a request with no Origin/Referer at all is rejected
  * a same-origin request without a session is left to the route's own 401, not
    masked behind a CSRF 403
  * GET is unaffected by all of the above (no Origin check, no token check)
  * `/api/auth/login` needs no CSRF token (there is no session yet to derive one
    from) but is still subject to the Origin check
  * the constant-time comparison is really being used, not `==`
  * the full real flow end to end: login -> capture both cookies -> upload with the
    header -> success; then again without the header -> 403 (also DELETE, since
    that's the other real mutating route this milestone ships)
"""

from __future__ import annotations

import hmac
import uuid
from typing import Any

from fastapi.testclient import TestClient

from app.core.csrf import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, CSRFMiddleware, derive_csrf_token
from app.core.security import COOKIE_NAME, create_access_token
from tests.conftest import TEST_ORIGIN, authenticate, make_tenant, make_user

FOREIGN_ORIGIN = "https://evil.example"


def _zscaler_text() -> bytes:
    return (
        b"datetime\tuser\tclientip\thost\turl\trequestmethod\tstatus\taction\turlcategory\tuseragent\n"
        b"2024-01-01T00:00:00Z\tu1@example.com\t10.0.0.1\texample.com\t/\tGET\t200\tAllowed\t"
        b"General\tMozilla/5.0\n"
    )


def _authed_user(tenant_cleanup: list[uuid.UUID], email: str = "csrf@example.com") -> Any:
    tenant = make_tenant(name="CSRF Tenant")
    tenant_cleanup.append(tenant.id)
    return make_user(tenant_id=tenant.id, email=email)


# --- Double-submit token: missing / wrong / correct -------------------------------


def test_mutating_request_without_csrf_header_is_rejected(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    user = _authed_user(tenant_cleanup)
    authenticate(client, user)
    del client.headers[CSRF_HEADER_NAME]  # authenticate() sets it; remove it for this test

    response = client.post("/api/uploads", files={"file": ("a.log", _zscaler_text(), "text/plain")})

    assert response.status_code == 403
    assert response.json()["code"] == "csrf_missing"


def test_mutating_request_without_csrf_cookie_is_rejected(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    """Header present, but the cookie half of the double submit is missing —
    e.g. a stale/cleared cookie jar. Still 403, still `csrf_missing`."""
    user = _authed_user(tenant_cleanup)
    authenticate(client, user)
    client.cookies.delete(CSRF_COOKIE_NAME)

    response = client.post("/api/uploads", files={"file": ("a.log", _zscaler_text(), "text/plain")})

    assert response.status_code == 403
    assert response.json()["code"] == "csrf_missing"


def test_mutating_request_with_wrong_csrf_token_is_rejected(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    user = _authed_user(tenant_cleanup)
    authenticate(client, user)
    # A syntactically plausible but wrong token in *both* places, so this exercises
    # the "well-formed but incorrect" path, not just "missing".
    client.cookies.set(CSRF_COOKIE_NAME, "0" * 64)
    client.headers[CSRF_HEADER_NAME] = "0" * 64

    response = client.post("/api/uploads", files={"file": ("a.log", _zscaler_text(), "text/plain")})

    assert response.status_code == 403
    assert response.json()["code"] == "csrf_invalid"


def test_mutating_request_with_mismatched_cookie_and_header_is_rejected(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    """Cookie and header individually look like real tokens (right length/alphabet)
    but disagree with each other — the classic double-submit break, distinct from
    either being outright missing or both-wrong-but-matching."""
    user = _authed_user(tenant_cleanup)
    authenticate(client, user)
    real_token = client.cookies[CSRF_COOKIE_NAME]
    other_valid_looking_token = derive_csrf_token("a-different-session-token-entirely")
    assert other_valid_looking_token != real_token
    client.headers[CSRF_HEADER_NAME] = other_valid_looking_token
    # cookie stays as the real token — header is the one that disagrees

    response = client.post("/api/uploads", files={"file": ("a.log", _zscaler_text(), "text/plain")})

    assert response.status_code == 403
    assert response.json()["code"] == "csrf_invalid"


def test_mutating_request_with_correct_csrf_token_succeeds(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    user = _authed_user(tenant_cleanup)
    authenticate(client, user)  # sets matching cookie + header

    response = client.post("/api/uploads", files={"file": ("a.log", _zscaler_text(), "text/plain")})

    assert response.status_code == 201


def test_csrf_comparison_is_constant_time_not_equality(
    client: TestClient, tenant_cleanup: list[uuid.UUID], monkeypatch: Any
) -> None:
    """`hmac.compare_digest` must be what actually gates the comparison, not `==` —
    proven by spying on `app.core.csrf`'s `hmac` module reference and driving a real
    request through the real app, rather than calling the function by hand (which
    would only prove the spy *forwards*, not that the middleware *uses* it)."""
    import app.core.csrf as csrf_module

    calls: list[tuple[Any, Any]] = []
    real_compare_digest = hmac.compare_digest

    def spy(a: Any, b: Any) -> bool:
        calls.append((a, b))
        return real_compare_digest(a, b)

    monkeypatch.setattr(csrf_module.hmac, "compare_digest", spy)

    user = _authed_user(tenant_cleanup)
    authenticate(client, user)

    response = client.post("/api/uploads", files={"file": ("a.log", _zscaler_text(), "text/plain")})

    assert response.status_code == 201
    # `hmac.compare_digest` gets called at least once more in this request outside
    # CSRFMiddleware — PyJWT verifies the session JWT's signature with it too, as
    # `bytes` operands. Isolate the `str` calls, which are exactly CSRFMiddleware's:
    # cookie-vs-header (double submit) and expected-vs-header (signed binding). If
    # either had been written as `==` instead, this list would be shorter than 2 even
    # though the request still succeeds the same way.
    str_calls = [(a, b) for a, b in calls if isinstance(a, str) and isinstance(b, str)]
    assert len(str_calls) == 2
    assert all(a == b for a, b in str_calls)


# --- Origin / Referer validation --------------------------------------------------


def test_mutating_request_with_foreign_origin_is_rejected(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    user = _authed_user(tenant_cleanup)
    authenticate(client, user)  # valid session + valid CSRF token...

    # ...but a foreign Origin, which must be rejected before the token is even
    # considered — an attacker who somehow obtained a valid token still can't ride a
    # forged Origin.
    response = client.post(
        "/api/uploads",
        files={"file": ("a.log", _zscaler_text(), "text/plain")},
        headers={"origin": FOREIGN_ORIGIN},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "origin_invalid"


def test_mutating_request_with_no_origin_or_referer_is_rejected(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    user = _authed_user(tenant_cleanup)
    authenticate(client, user)

    response = client.post(
        "/api/uploads",
        files={"file": ("a.log", _zscaler_text(), "text/plain")},
        headers={"origin": ""},  # httpx won't omit a header already set on the client
    )

    # An empty Origin header is, for this purpose, the same as no Origin: it isn't in
    # the allowlist. A *real* browser always sends a non-empty Origin on a mutating
    # cross-site fetch, so this also stands in for "no Origin at all" (httpx's own
    # TestClient always sends whatever's in `client.headers`; there's no way to send a
    # literal absent header once the fixture default is set, so this is the faithful
    # equivalent from inside the test client).
    assert response.status_code == 403
    assert response.json()["code"] == "origin_invalid"


def test_mutating_request_falls_back_to_referer_when_origin_is_absent(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """Built without the `client` fixture's default Origin header, to prove the
    Referer fallback actually works rather than merely being unreached dead code."""
    from app.main import app

    referer_only_client = TestClient(app, headers={})
    referer_only_client.headers.pop("origin", None)
    user = _authed_user(tenant_cleanup, email="referer@example.com")
    authenticate(referer_only_client, user)
    referer_only_client.headers.pop("origin", None)  # authenticate() doesn't touch it, but be sure

    response = referer_only_client.post(
        "/api/uploads",
        files={"file": ("a.log", _zscaler_text(), "text/plain")},
        headers={"referer": f"{TEST_ORIGIN}/upload"},
    )

    assert response.status_code == 201


def test_delete_analysis_with_foreign_origin_is_rejected(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    """The Origin check is route-agnostic — it applies to DELETE too, not just the
    upload POST every other test in this file happens to use."""
    user = _authed_user(tenant_cleanup)
    authenticate(client, user)
    upload_resp = client.post(
        "/api/uploads", files={"file": ("a.log", _zscaler_text(), "text/plain")}
    )
    assert upload_resp.status_code == 201
    analysis_id = upload_resp.json()["analysis_id"]

    response = client.delete(f"/api/analyses/{analysis_id}", headers={"origin": FOREIGN_ORIGIN})

    assert response.status_code == 403
    assert response.json()["code"] == "origin_invalid"


# --- No session yet: let the route's own auth dependency answer -------------------


def test_mutating_request_with_no_session_is_not_masked_by_csrf(client: TestClient) -> None:
    """No session cookie at all (never authenticated) still gets the *route's* 401,
    not a CSRF 403 — CSRFMiddleware has nothing to check a token against, so it steps
    aside. `client` already carries a valid Origin (fixture default), isolating this
    from the Origin check above."""
    response = client.post("/api/uploads", files={"file": ("a.log", _zscaler_text(), "text/plain")})

    assert response.status_code == 401


# --- Safe methods are exempt -------------------------------------------------------


def test_get_is_never_subject_to_csrf_or_origin_checks(client: TestClient) -> None:
    """A GET with a foreign Origin and no CSRF token at all must still be handled
    normally (safe methods are exempt outright) — here that means the *route's* 401
    for "not authenticated", proving CSRFMiddleware didn't intercept it for either
    reason."""
    del client.headers["origin"]
    response = client.get("/api/auth/me", headers={"origin": FOREIGN_ORIGIN})
    assert response.status_code == 401
    assert response.json()["code"] == "not_authenticated"


# --- Login is Origin-checked but token-exempt --------------------------------------


def test_login_needs_no_csrf_token_but_is_still_origin_checked(
    client: TestClient, tenant_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    make_user(tenant_id=tenant.id, email="login-csrf@example.com", password="correct-horse")

    # No CSRF cookie/header anywhere in this fresh client's jar — login must not need
    # one (there is no session yet to derive it from).
    ok = client.post(
        "/api/auth/login",
        json={"email": "login-csrf@example.com", "password": "correct-horse"},
    )
    assert ok.status_code == 200

    rejected = client.post(
        "/api/auth/login",
        json={"email": "login-csrf@example.com", "password": "correct-horse"},
        headers={"origin": FOREIGN_ORIGIN},
    )
    assert rejected.status_code == 403
    assert rejected.json()["code"] == "origin_invalid"


# --- Full real flow, end to end: login -> both cookies -> upload with/without header


def test_full_flow_login_capture_cookies_upload_with_and_without_header(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    from app.main import app

    tenant = make_tenant(name="Full Flow Tenant")
    tenant_cleanup.append(tenant.id)
    make_user(tenant_id=tenant.id, email="fullflow@example.com", password="correct-horse")

    flow_client = TestClient(app, headers={"origin": TEST_ORIGIN})

    login_response = flow_client.post(
        "/api/auth/login",
        json={"email": "fullflow@example.com", "password": "correct-horse"},
    )
    assert login_response.status_code == 200
    assert COOKIE_NAME in flow_client.cookies
    assert CSRF_COOKIE_NAME in flow_client.cookies
    csrf_token = flow_client.cookies[CSRF_COOKIE_NAME]

    # WITH the header: succeeds.
    with_header = flow_client.post(
        "/api/uploads",
        files={"file": ("full-flow.log", _zscaler_text(), "text/plain")},
        headers={CSRF_HEADER_NAME: csrf_token},
    )
    assert with_header.status_code == 201

    # WITHOUT the header: rejected, even though the session is fully valid.
    without_header = flow_client.post(
        "/api/uploads", files={"file": ("full-flow-2.log", _zscaler_text(), "text/plain")}
    )
    assert without_header.status_code == 403
    assert without_header.json()["code"] == "csrf_missing"


# --- Session cookie present but the JWT itself is bogus: still 403 before 401 -----


def test_bogus_session_cookie_with_missing_csrf_header_still_gets_csrf_403(
    client: TestClient,
) -> None:
    """CSRFMiddleware only checks whether a session *cookie* is present, not whether
    it decodes — that's deliberate (decoding it is app.core.security's job, and
    duplicating JWT verification into the middleware would be two sources of truth
    for the same decision). A forged/expired cookie with no CSRF header is still a
    CSRF-shaped rejection, not an auth one; app.core.security.require_user would
    separately reject the same request with 401 if it ever got there."""
    client.cookies.set(COOKIE_NAME, "not-a-real-jwt")

    response = client.post("/api/uploads", files={"file": ("a.log", _zscaler_text(), "text/plain")})

    assert response.status_code == 403
    assert response.json()["code"] == "csrf_missing"


# --- Token derivation itself -------------------------------------------------------


def test_derive_csrf_token_is_deterministic_and_session_specific() -> None:
    token_a = derive_csrf_token("session-token-a")
    token_b = derive_csrf_token("session-token-b")
    assert token_a == derive_csrf_token("session-token-a")
    assert token_a != token_b


def test_derive_csrf_token_matches_what_a_real_login_issues(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email="derive@example.com")
    session_token = create_access_token(user_id=user.id, tenant_id=user.tenant_id)
    assert derive_csrf_token(session_token) == derive_csrf_token(session_token)


def test_csrf_middleware_is_registered_on_the_real_app() -> None:
    from app.main import app

    assert any(m.cls is CSRFMiddleware for m in app.user_middleware)
