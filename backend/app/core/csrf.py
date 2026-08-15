"""Double-submit CSRF defense for state-changing requests (docs/06, docs/09).

**Why this exists.** `app.core.security.cookie_security_flags` switches the session
cookie to `SameSite=None; Secure` outside local dev, because Vercel (web) and Fly
(api) are different registrable domains and `SameSite=Lax` cookies are never attached
to cross-site fetch/XHR. `SameSite=None` gives up the browser's built-in CSRF defense
(a `Lax`/`Strict` cookie simply never rides along on a forged cross-site request) —
so from here on, *this module* is the CSRF defense, not a nice-to-have on top of one.

**Why a signed/derived token, not a bare random value in server-side storage.** The
session cookie (`tenex_session`) is `httpOnly`, so no legitimate JavaScript running on
the frontend's own origin can read it to prove it is talking to our API on the
victim's behalf. On login we hand the browser a *second* cookie — readable by JS,
its value cryptographically bound to that session — and require every mutating
request to echo it back in a header. Binding it to the session instead of generating
an unrelated random value and keeping a `session_id -> csrf_token` table server-side
means:

  * No new storage, no extra DB round trip on every mutating request, no expiry/cleanup
    job — the token is a pure function of the session token, recomputed on the fly.
  * It self-invalidates whenever the session does (new login -> new `iat` -> new JWT
    -> new derived token) with no explicit revocation bookkeeping.
  * It resists cookie tossing (an attacker who manages to plant a *bare* CSRF cookie
    for our origin, e.g. from a compromised sibling subdomain): verification never
    trusts the value the client presents in the CSRF cookie on its own — it recomputes
    the expected token from the real `httpOnly` session cookie the browser attached
    and constant-time-compares *that* against the header. A forged CSRF cookie cannot
    produce a header value that passes, because producing one requires the HMAC key,
    which never leaves the server.

The HMAC key is itself derived from `settings.jwt_secret` via a domain-separated
sub-key (`HMAC(jwt_secret, "tenex-csrf-token-v1")`), not the raw JWT signing key
reused directly — one extra HMAC call buys key separation, so a future JWT algorithm
change or key rotation never silently doubles as (or is blocked by) a CSRF-key
rotation, without provisioning a second secret.

**Why Origin/Referer validation on top of the token.** Defense in depth, and the only
defense available on `/api/auth/login`: at the moment a login request arrives there is
no session yet, so there is nothing to derive a double-submit token from and nothing
in the client's cookie jar to echo back. Login is instead covered by the Origin check
below (which needs no pre-existing session) plus the existing 5/min rate limit
(`app.core.rate_limit`) — the standard shape of the "login CSRF" trade-off. See
docs/06-PRIVACY-SECURITY.md, "SameSite decision record".

GET/HEAD/OPTIONS are exempt everywhere: they must stay safe and side-effect-free by
construction, so there is nothing here for them to protect against. If a GET route
ever mutates state, that is a bug in the route, not something to patch over with CSRF
checks on a safe method.
"""

from __future__ import annotations

import hashlib
import hmac
from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.security import COOKIE_NAME, cookie_security_flags

CSRF_COOKIE_NAME = "tenex_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"

# Methods the spec requires to be safe/idempotent. Never add to this set to work
# around a route that shouldn't be mutating in the first place — fix the route.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Login is the one state-changing route the double-submit token cannot cover — see
# the module docstring. Exact path match on purpose (no prefix/regex matching that
# could accidentally widen this later).
_TOKEN_CHECK_EXEMPT_PATHS = frozenset({"/api/auth/login"})

_CSRF_KEY_LABEL = b"tenex-csrf-token-v1"

log = get_logger(__name__)


def _csrf_key(jwt_secret: str) -> bytes:
    """Domain-separated sub-key derived from the JWT signing secret. See module
    docstring for why this isn't the raw secret."""
    return hmac.new(jwt_secret.encode(), _CSRF_KEY_LABEL, hashlib.sha256).digest()


def derive_csrf_token(session_token: str, *, settings: Settings | None = None) -> str:
    """The CSRF cookie's value, and the value every mutating request's header must
    match: `HMAC(csrf_subkey, session_token)`, hex-encoded."""
    settings = settings or get_settings()
    key = _csrf_key(settings.jwt_secret.get_secret_value())
    return hmac.new(key, session_token.encode(), hashlib.sha256).hexdigest()


def issue_csrf_cookie(
    response: Response, session_token: str, *, settings: Settings | None = None
) -> None:
    """Called alongside `app.core.security.set_session_cookie` on login. Same
    `Secure`/`SameSite` branch as the session cookie (`cookie_security_flags`) —
    `httponly=False` is the one deliberate difference, since the entire point of this
    cookie is that frontend JavaScript can read it and echo it back in a header."""
    settings = settings or get_settings()
    secure, samesite = cookie_security_flags(settings)
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=derive_csrf_token(session_token, settings=settings),
        max_age=settings.jwt_ttl_minutes * 60,
        httponly=False,
        secure=secure,
        samesite=samesite,
        path="/",
    )


def clear_csrf_cookie(response: Response, *, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    secure, samesite = cookie_security_flags(settings)
    response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        path="/",
        httponly=False,
        secure=secure,
        samesite=samesite,
    )


def _origin_from_referer(referer: str) -> str | None:
    """`scheme://host[:port]` from a Referer header, or `None` if it doesn't parse.
    Fallback only — Origin is what real browsers send on every cross-site fetch/XHR
    with a non-safe method, and it cannot be set or suppressed by page JavaScript."""
    parts = urlsplit(referer)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def _forbidden(code: str, detail: str) -> JSONResponse:
    return JSONResponse(status_code=403, content={"detail": detail, "code": code})


class CSRFMiddleware(BaseHTTPMiddleware):
    """Enforces, on every non-safe request: (1) `Origin` (or `Referer` fallback) is in
    the CORS allowlist, and (2) except for login, a double-submit CSRF token bound to
    the caller's session. See the module docstring for the full reasoning.

    Registered in `app.main` *inside* `CORSMiddleware` (added before it, so it ends up
    the inner layer — Starlette wraps middleware such that the last one added via
    `add_middleware` is outermost). That ordering matters: a rejection generated here
    must still pass back out through `CORSMiddleware` so the browser's `fetch` actually
    receives the 403 instead of an opaque CORS failure with no readable body.

    Only inspects the method, URL path, headers, and cookies of the request — never
    the body — so it does not interfere with `app.api.uploads`' streaming multipart
    read (a naive `BaseHTTPMiddleware` that called `await request.body()` would buffer
    the entire upload in memory before the route ever saw it).
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method in _SAFE_METHODS:
            return await call_next(request)

        settings = get_settings()

        origin = request.headers.get("origin")
        if origin is None:
            referer = request.headers.get("referer")
            origin = _origin_from_referer(referer) if referer else None

        if origin is None or origin not in settings.cors_origins:
            log.warning(
                "csrf.origin_rejected", path=request.url.path, method=request.method, origin=origin
            )
            return _forbidden("origin_invalid", "Request origin is not allowed.")

        if request.url.path in _TOKEN_CHECK_EXEMPT_PATHS:
            return await call_next(request)

        session_token = request.cookies.get(COOKIE_NAME)
        if session_token is None:
            # No session cookie at all: nothing to check a CSRF token against, and
            # this is not the place to decide what happens to an unauthenticated
            # mutating request. Let it through to the route, whose own auth dependency
            # (app.core.security.require_user) returns the real 401 — a 403 here would
            # just be a confusing, wrong-reason rejection.
            return await call_next(request)

        cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
        header_token = request.headers.get(CSRF_HEADER_NAME)
        if not cookie_token or not header_token:
            log.warning("csrf.token_missing", path=request.url.path, method=request.method)
            return _forbidden("csrf_missing", "Missing CSRF token.")

        expected = derive_csrf_token(session_token, settings=settings)
        # Both comparisons matter and both must be constant-time: the first is the
        # classic double-submit check (cookie must match header — an attacker's page
        # cannot read our cookie to produce a matching header); the second is the
        # signed-binding check (the header must match what we'd derive from the *real*
        # session cookie the browser attached — an attacker who somehow tossed a
        # cookie onto our origin still can't forge a header without the HMAC key).
        cookie_matches_header = hmac.compare_digest(cookie_token, header_token)
        header_matches_session = hmac.compare_digest(expected, header_token)
        if not (cookie_matches_header and header_matches_session):
            log.warning("csrf.token_invalid", path=request.url.path, method=request.method)
            return _forbidden("csrf_invalid", "Invalid CSRF token.")

        return await call_next(request)
