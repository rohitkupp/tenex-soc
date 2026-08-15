"""A tenant's login. Auth is credentials-only per docs/06 — no OAuth, no MFA."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Text, func, text
from sqlalchemy.dialects.postgresql import CITEXT
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class User(Base, TenantScopedMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    # Globally unique per docs/02 — not scoped per tenant. Login resolves the tenant
    # *from* this column, so it cannot itself be tenant-scoped. See
    # app.models.base.bypass_tenant_scope.
    email: Mapped[str] = mapped_column(CITEXT, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)  # argon2id
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # NULL until confirmed. M15 self-serve signup (app.core.verification,
    # app.api.auth.signup/login) -- see that module's docstring for the oracle design
    # and alembic/versions/88fcc9caf4ea_users_email_verified_at.py for why this has no
    # server_default: every write path that creates a User must decide this value
    # explicitly (signup: None or now(), depending on whether verification is even
    # configured) rather than inherit a silent default that could paper over a real
    # unverified account.
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
