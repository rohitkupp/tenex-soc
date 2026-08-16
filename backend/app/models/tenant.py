"""The tenant itself. Not tenant-scoped — it *is* the scope."""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime
from typing import Final

from sqlalchemy import DateTime, LargeBinary, Text, func, select, text
from sqlalchemy.orm import Mapped, Session, mapped_column
from sqlalchemy.types import Uuid

from app.core.db import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    # HMAC salt for pseudonymization (docs/06). Never logged, never in an error message,
    # never rendered — see app.core.logging._REDACT_KEYS and Settings.pseudonym_salt.
    pseudonym_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# docs/v2_migration/MIGRATION-01-evidence-first.md, change 23 ("Shared workspace, single
# live tenant"): every login and every new signup lands in this one tenant instead of
# getting a tenant of its own. Named to match the synthetic corpus generator's train-split
# org (`docs/v2_migration/generate_corpus.py`, `Org.build("northwind", ...)`) — deliberate,
# so the eventual historical-baseline load (migration change 1, not this one) can key off
# this exact name without a mapping table.
LIVE_TENANT_NAME: Final[str] = "northwind"


def get_or_create_live_tenant(session: Session) -> Tenant:
    """Idempotent lookup-or-create for the single live tenant every account joins.

    `Tenant` is deliberately not `TenantScopedMixin` (see this module's own docstring) —
    a plain `select` needs no `tenant_scope`/`bypass_tenant_scope` wrapper, unlike every
    other query in `app.api.auth` and `app.scripts.seed`.

    Not fully race-proof (no unique constraint on `tenants.name` — adding one is a schema
    change, out of scope for this change: change 23 is explicit that no migration is
    needed here). Two concurrent first-ever callers could each insert a `northwind` row.
    That mirrors the same check-then-insert idempotency `app.scripts.seed.seed` already
    uses for the demo user by email, and in practice `make seed` always runs once, before
    any signup traffic exists.
    """
    tenant = session.execute(
        select(Tenant).where(Tenant.name == LIVE_TENANT_NAME)
    ).scalar_one_or_none()
    if tenant is not None:
        return tenant
    tenant = Tenant(name=LIVE_TENANT_NAME, pseudonym_salt=secrets.token_bytes(32))
    session.add(tenant)
    session.flush()  # assign tenant.id for callers that need it before commit
    return tenant
