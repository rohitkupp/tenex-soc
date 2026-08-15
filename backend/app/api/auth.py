"""POST /api/auth/login, POST /api/auth/logout, GET /api/auth/me — docs/09 + docs/06.

Login failure is deliberately generic — the same `invalid_credentials` response for an
unknown email and for a wrong password — so a response never discloses whether an
account exists (docs/06: "Generic failure message — never reveal whether an email
exists").
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette import status

from app.core.csrf import clear_csrf_cookie, issue_csrf_cookie
from app.core.db import get_db
from app.core.errors import ApiError
from app.core.logging import get_logger
from app.core.rate_limit import limiter
from app.core.security import (
    CurrentUser,
    clear_session_cookie,
    create_access_token,
    require_user,
    set_session_cookie,
    verify_password,
)
from app.models.base import bypass_tenant_scope
from app.models.user import User
from app.schemas.auth import LoginRequest, LoginResponse, MeResponse, TenantOut, UserOut

router = APIRouter()
log = get_logger(__name__)


@router.post("/login", response_model=LoginResponse)
@limiter.limit("5/minute")
def login(
    request: Request,  # required by slowapi's @limiter.limit, even though unused here
    response: Response,
    body: LoginRequest,
    db: Annotated[Session, Depends(get_db)],
) -> LoginResponse:
    # The one legitimate cross-tenant lookup: we don't know the tenant until we know
    # which user this email belongs to. See app.models.base.bypass_tenant_scope.
    with bypass_tenant_scope(db):
        user = db.execute(select(User).where(User.email == body.email)).scalar_one_or_none()

    if user is None or not verify_password(body.password, user.password_hash):
        log.info("auth.login_failed")
        raise ApiError(
            status_code=401, code="invalid_credentials", detail="Invalid email or password."
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
