"""Auth: argon2id password hashing, JWT session cookies, and the FastAPI dependency
that resolves the current user + tenant on every protected route (docs/06, docs/09).

**Why `argon2-cffi` directly, not `passlib`.** `passlib`'s argon2 backend is a thin
wrapper around this same C library, called through the same C extension — it adds an
abstraction layer, not different behaviour. `passlib` has had no release since 2020
and has open compatibility issues on current Python/`bcrypt` (unrelated to argon2, but
a signal about maintenance). Calling `argon2-cffi`'s `PasswordHasher` directly is one
fewer dependency for the same guarantee: argon2id, its default variant, with its
current-recommended defaults (`m=65536` KiB, `t=3`, `p=4`).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError
from fastapi import Cookie, Depends, Response
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.db import get_db
from app.core.errors import ApiError
from app.models.base import tenant_scope
from app.models.tenant import Tenant
from app.models.user import User

COOKIE_NAME = "tenex_session"

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHash):
        return False


class InvalidTokenError(Exception):
    """The session cookie is missing, malformed, expired, or forged."""


class _TokenClaims(BaseModel):
    user_id: uuid.UUID
    tenant_id: uuid.UUID


def create_access_token(*, user_id: uuid.UUID, tenant_id: uuid.UUID) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_ttl_minutes),
    }
    return jwt.encode(
        payload, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm
    )


def decode_access_token(token: str) -> _TokenClaims:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token, settings.jwt_secret.get_secret_value(), algorithms=[settings.jwt_algorithm]
        )
        return _TokenClaims(user_id=payload["sub"], tenant_id=payload["tenant_id"])
    except (jwt.PyJWTError, KeyError, ValidationError) as exc:
        raise InvalidTokenError from exc


def cookie_security_flags(settings: Settings | None = None) -> tuple[bool, Literal["lax", "none"]]:
    """`(secure, samesite)` for every cookie this app sets — one branch, shared by the
    session cookie (below) and the CSRF cookie (`app.core.csrf`), so the two can never
    silently disagree.

    **Why this branches at all.** The deployed topology is Vercel (`*.vercel.app`) +
    Fly (`*.fly.dev`) — different registrable domains, so every browser -> API call is
    cross-site. `SameSite=Lax` cookies are never attached to cross-site fetch/XHR (only
    to top-level GET navigations), which would silently drop the session cookie on
    every login in production. `SameSite=None` is required to make cross-site
    credentialed requests work at all, and the cookie spec requires `None` to be paired
    with `Secure`. A `Secure` cookie is dropped by the browser (and never sent by curl)
    over plain HTTP, which is exactly what local dev (`http://localhost`) is — so local
    keeps the old `Lax` + non-`Secure` pair, which works there because the frontend and
    API are same-site on `localhost` regardless of port. This is a documented deviation
    between environments, not an oversight: see docs/06-PRIVACY-SECURITY.md, "SameSite
    decision record", for the full reasoning and the compensating CSRF controls
    (`app.core.csrf`) this trade requires.
    """
    settings = settings or get_settings()
    if settings.environment == "local":
        return False, "lax"
    return True, "none"


def set_session_cookie(response: Response, token: str, *, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    secure, samesite = cookie_security_flags(settings)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=settings.jwt_ttl_minutes * 60,
        httponly=True,
        secure=secure,
        samesite=samesite,
        path="/",
    )


def clear_session_cookie(response: Response, *, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    secure, samesite = cookie_security_flags(settings)
    response.delete_cookie(
        key=COOKIE_NAME,
        path="/",
        httponly=True,
        secure=secure,
        samesite=samesite,
    )


@dataclass
class CurrentUser:
    """What every protected route gets after `require_user` runs."""

    user: User
    tenant: Tenant


def _unauthorized(code: str = "not_authenticated") -> ApiError:
    return ApiError(status_code=401, code=code, detail="Not authenticated.")


def require_user(
    db: Annotated[Session, Depends(get_db)],
    session_cookie: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
) -> CurrentUser:
    """FastAPI dependency: resolves the caller from the session cookie and binds the
    request's DB session to their tenant for the lifetime of the request. Every
    non-auth route in `app.api` depends on this — route protection is enforced here,
    server-side, not left to the frontend (docs/06)."""
    if session_cookie is None:
        raise _unauthorized()

    try:
        claims = decode_access_token(session_cookie)
    except InvalidTokenError as exc:
        raise _unauthorized(code="invalid_session") from exc

    with tenant_scope(db, claims.tenant_id):
        user = db.execute(select(User).where(User.id == claims.user_id)).scalar_one_or_none()
        tenant = db.get(Tenant, claims.tenant_id)  # Tenant is not tenant-scoped

    if user is None or tenant is None:
        # Token was well-formed and signed, but the user/tenant it names no longer
        # exists. Same generic response as any other auth failure.
        raise _unauthorized(code="invalid_session")

    return CurrentUser(user=user, tenant=tenant)
