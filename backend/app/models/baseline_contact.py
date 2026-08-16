"""`baseline_contacts` — docs/v2_migration/MIGRATION-01-evidence-first.md, change 1, matched
exactly:

```sql
CREATE TABLE baseline_contacts (
  tenant_id UUID NOT NULL,
  scope TEXT NOT NULL,                -- user|department|org
  scope_value TEXT NOT NULL,
  domain TEXT NOT NULL,
  contact_count BIGINT NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, scope, scope_value, domain)
);
CREATE INDEX ON baseline_contacts (tenant_id, domain);
```

Rarity resolves against this table at three scopes (`app.baseline.resolve.contact_counts`) —
"zero for Alice, one for Finance, four org-wide" per the migration doc. `docs/v2_migration/
generate_corpus.py::build_baseline()` only emits `scope="user"` rows; `app.baseline.loader`
deterministically rolls those up into `department` and `org` rows at load time — see that
module's docstring for exactly how, and for why `first_seen`/`last_seen` (also absent from the
generator's output) are set to the loaded baseline period's own bounds rather than fabricated.

Not given a `tenants` FK, same reasoning as `baseline_windows`/`baseline_profiles` and every
other high-volume detection table — the migration's SQL above declares `tenant_id UUID NOT NULL`
with no `REFERENCES tenants(id)`.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Index, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class BaselineContact(Base, TenantScopedMixin):
    __tablename__ = "baseline_contacts"

    # Overrides TenantScopedMixin's tenant_id (no FK, no bare index; part of the composite PK
    # instead) — see module docstring.
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    scope: Mapped[str] = mapped_column(Text, primary_key=True)
    scope_value: Mapped[str] = mapped_column(Text, primary_key=True)
    domain: Mapped[str] = mapped_column(Text, primary_key=True)
    contact_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (Index("ix_baseline_contacts_tenant_domain", "tenant_id", "domain"),)
