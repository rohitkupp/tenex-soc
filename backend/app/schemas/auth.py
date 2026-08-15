"""Pydantic v2 schemas for docs/09-API-CONTRACT.md's Auth section.

Email validation is a hand-rolled regex rather than Pydantic's `EmailStr` because
`EmailStr` requires the separate `email-validator` package, which is not in the stack
table (`CLAUDE.md` — "Do not add libraries not listed in the stack table without
asking"). This regex is intentionally permissive; it exists to reject obvious
malformed input, not to validate deliverability.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    tenant_id: uuid.UUID
    created_at: datetime


class TenantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    created_at: datetime


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        if not _EMAIL_RE.match(value):
            raise ValueError("Not a valid email address.")
        return value.strip().lower()


class LoginResponse(BaseModel):
    user: UserOut


class MeResponse(BaseModel):
    user: UserOut
    tenant: TenantOut


class SignupRequest(BaseModel):
    email: str
    password: str
    org_name: str

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        if not _EMAIL_RE.match(value):
            raise ValueError("Not a valid email address.")
        return value.strip().lower()

    @field_validator("org_name")
    @classmethod
    def _validate_org_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Organization name is required.")
        return value


class ResendVerificationRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        if not _EMAIL_RE.match(value):
            raise ValueError("Not a valid email address.")
        return value.strip().lower()


class VerificationSentResponse(BaseModel):
    """Shared response shape for signup (201) and resend-verification (202) — both
    endpoints return this exact body regardless of whether the account already
    existed or was already verified (docs/06's enumeration guarantee)."""

    status: Literal["verification_sent"]
    email: str
