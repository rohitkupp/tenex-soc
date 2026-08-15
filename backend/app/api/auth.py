"""POST /api/auth/signup, /resend-verification, /login, /logout, GET /me — docs/09 +
docs/06.

Login failure is deliberately generic — the same `invalid_credentials` response for an
unknown email and for a wrong password — so a response never discloses whether an
account exists (docs/06: "Generic failure message — never reveal whether an email
exists"). Signup and resend-verification extend that same guarantee to account
*creation*: both return the identical success body whether or not the email was
already registered, and neither endpoint's response depends on the account's current
verification state.

**Self-serve signup + email verification.** Supabase Auth is the
email-ownership oracle only — this app never authenticates against it and never
stores a second password there. See `app.core.verification`'s module docstring for
the full design. `signup` always creates our own `Tenant` + `User` row (mirroring
`app.scripts.seed.seed`) and, when a Supabase project is configured
(`Settings.email_verification_enabled`), asks Supabase to email a confirmation link.
When it is *not* configured — local dev, CI, and every test in this suite —
`email_verified_at` is stamped immediately instead of left `NULL`; see `signup`'s
docstring for why that branch is a deliberate, loud fallback and not an accidental
bypass. `login` is the enforcement point: it checks the password first and the
verification state second, in that order, and only the second check can produce the
new `email_not_verified` response — see `login`'s docstring for why the order itself
is load-bearing.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette import status

from app.core.config import get_settings
from app.core.csrf import clear_csrf_cookie, issue_csrf_cookie
from app.core.db import get_db
from app.core.errors import ApiError
from app.core.logging import get_logger
from app.core.rate_limit import limiter
from app.core.security import (
    CurrentUser,
    clear_session_cookie,
    create_access_token,
    hash_password,
    require_user,
    set_session_cookie,
    verify_password,
)
from app.core.verification import is_email_confirmed_upstream, send_verification_email
from app.models.base import bypass_tenant_scope
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    MeResponse,
    ResendVerificationRequest,
    SignupRequest,
    TenantOut,
    UserOut,
    VerificationSentResponse,
)

router = APIRouter()
log = get_logger(__name__)

# docs/09: password policy is enforced here, not in the Pydantic schema, so the
# `weak_password` failure is a normal `ApiError` (machine-readable `code`, docs/09's
# envelope) rather than a generic 422 field-validation error the frontend would have
# to special-case to get the same UX.
_MIN_PASSWORD_LENGTH = 12


@router.post(
    "/signup", response_model=VerificationSentResponse, status_code=status.HTTP_201_CREATED
)
@limiter.limit("3/hour")
def signup(
    request: Request,  # required by slowapi's @limiter.limit, even though unused here
    body: SignupRequest,
    db: Annotated[Session, Depends(get_db)],
) -> VerificationSentResponse:
    """Creates our own `Tenant` + `User` (mirroring `app.scripts.seed.seed`'s
    tenant-then-user, fresh-random-salt sequence exactly — two places building a
    tenant's first user is one place too many to let the salt scheme drift) and,
    when Supabase is configured, asks it to email a confirmation link.

    Returns the *same* 201 body whether or not `body.email` was already registered
    (docs/06: never disclose account existence) — on a collision this creates nothing
    and sends nothing, it just reports the same success shape a genuine signup would.

    **The `email_verification_enabled is False` branch below is a deliberate local/CI
    fallback, not an accidental bypass.** With no Supabase project configured there is
    nothing to send a confirmation link through and no upstream row `login` could ever
    read as confirmed — refusing every signup until someone provisions Supabase would
    make `make up` (and this entire test suite) unusable out of the box. So instead:
    stamp `email_verified_at` immediately and log loudly that verification is
    disabled, so this is grep-able and impossible to mistake for the real, upstream
    verified path in a review of logs or code.
    """
    if len(body.password) < _MIN_PASSWORD_LENGTH:
        raise ApiError(
            status_code=400,
            code="weak_password",
            detail=f"Password must be at least {_MIN_PASSWORD_LENGTH} characters.",
        )

    settings = get_settings()

    # Same cross-tenant-by-email lookup as login, for the same reason: the tenant
    # this email belongs to (if any) is exactly what we're trying to determine.
    with bypass_tenant_scope(db):
        existing = db.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
    if existing is not None:
        log.info("auth.signup_email_already_registered")
        return VerificationSentResponse(status="verification_sent", email=body.email)

    tenant = Tenant(name=body.org_name, pseudonym_salt=secrets.token_bytes(32))
    db.add(tenant)
    db.flush()  # assign tenant.id before the user row references it

    if settings.email_verification_enabled:
        email_verified_at = None
    else:
        email_verified_at = datetime.now(UTC)
        # No `email=` here, deliberately. Every other auth log line in this module
        # identifies by tenant_id/user_id and never by address, because structured logs
        # are exactly the kind of place docs/06 does not want identifiable data
        # accumulating. The tenant_id on `auth.signup_created` below is enough to trace
        # any individual signup back through the database if someone needs to.
        log.warning("auth.signup_verification_disabled")

    user = User(
        tenant_id=tenant.id,
        email=body.email,
        password_hash=hash_password(body.password),
        email_verified_at=email_verified_at,
    )
    db.add(user)
    db.flush()

    email_sent = False
    if settings.email_verification_enabled:
        email_sent = send_verification_email(body.email)

    log.info(
        "auth.signup_created",
        tenant_id=str(tenant.id),
        user_id=str(user.id),
        verification_enabled=settings.email_verification_enabled,
        email_sent=email_sent,
    )
    return VerificationSentResponse(status="verification_sent", email=body.email)


@router.post(
    "/resend-verification",
    response_model=VerificationSentResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
@limiter.limit("3/hour")
def resend_verification(
    request: Request,  # required by slowapi's @limiter.limit, even though unused here
    body: ResendVerificationRequest,
    db: Annotated[Session, Depends(get_db)],
) -> VerificationSentResponse:
    """Always 202s with the same body — an unknown email, an already-verified
    account, and a genuine resend are indistinguishable from the response
    (docs/06). Only the last of those actually triggers a Supabase call; the other
    two are silent no-ops that still report success."""
    settings = get_settings()

    if settings.email_verification_enabled:
        with bypass_tenant_scope(db):
            user = db.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
        if user is not None and user.email_verified_at is None:
            send_verification_email(body.email)

    log.info("auth.resend_verification_requested")
    return VerificationSentResponse(status="verification_sent", email=body.email)


@router.post("/login", response_model=LoginResponse)
@limiter.limit("5/minute")
def login(
    request: Request,  # required by slowapi's @limiter.limit, even though unused here
    response: Response,
    body: LoginRequest,
    db: Annotated[Session, Depends(get_db)],
) -> LoginResponse:
    """Two failure modes, checked in a deliberate order. The password check runs
    first and stays generic (`invalid_credentials`, docs/06) for both an unknown email
    and a wrong password. The verification check runs *only after* that check passes:
    someone who doesn't own these credentials learns nothing beyond "invalid" either
    way, and someone who does has already proven it by supplying the right password —
    telling *them* their email isn't verified yet discloses nothing an attacker
    without the password could use. Reversing this order (checking verification before
    the password) would leak account-existence-and-verification-state to anyone who
    can merely guess an email.
    """
    settings = get_settings()

    # The one legitimate cross-tenant lookup: we don't know the tenant until we know
    # which user this email belongs to. See app.models.base.bypass_tenant_scope.
    with bypass_tenant_scope(db):
        user = db.execute(select(User).where(User.email == body.email)).scalar_one_or_none()

    if user is None or not verify_password(body.password, user.password_hash):
        log.info("auth.login_failed")
        raise ApiError(
            status_code=401, code="invalid_credentials", detail="Invalid email or password."
        )

    if user.email_verified_at is None:
        # Ask the oracle once, live, rather than trust a stale local NULL forever —
        # see app.core.verification's module docstring. Only meaningful when Supabase
        # is actually configured; with it disabled there is no upstream row to check,
        # so a NULL here can only mean a genuinely unverified account.
        if settings.email_verification_enabled and is_email_confirmed_upstream(db, user.email):
            # First successful read of the upstream oracle: stamp our own durable
            # record now, so every login after this one is a single local column
            # check, never a second round trip to Supabase.
            user.email_verified_at = datetime.now(UTC)
            db.flush()
        else:
            log.info("auth.login_blocked_unverified", tenant_id=str(user.tenant_id))
            raise ApiError(
                status_code=403,
                code="email_not_verified",
                detail="Please verify your email before logging in.",
            )

    token = create_access_token(user_id=user.id, tenant_id=user.tenant_id)
    set_session_cookie(response, token)
    # Second, JS-readable cookie for the double-submit CSRF check every mutating
    # request after this one must pass (app.core.csrf). Its value is derived from
    # `token`, so it is bound to this session without any server-side token storage.
    issue_csrf_cookie(response, token)
    log.info("auth.login_succeeded", tenant_id=str(user.tenant_id))
    return LoginResponse(user=UserOut.model_validate(user))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response) -> None:
    clear_session_cookie(response)
    clear_csrf_cookie(response)


@router.get("/me", response_model=MeResponse)
def me(current: Annotated[CurrentUser, Depends(require_user)]) -> MeResponse:
    return MeResponse(
        user=UserOut.model_validate(current.user),
        tenant=TenantOut.model_validate(current.tenant),
    )
