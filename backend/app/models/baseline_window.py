"""`baseline_windows` — docs/v2_migration/MIGRATION-01-evidence-first.md, change 1
("Historical baseline store"), matched exactly:

```sql
CREATE TABLE baseline_windows (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID NOT NULL,
  entity_type TEXT NOT NULL,          -- user|src_ip|department|org
  entity_value TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  features JSONB NOT NULL,            -- same ~50-feature vector as L3
  UNIQUE (tenant_id, entity_type, entity_value, window_start)
);
CREATE INDEX ON baseline_windows (tenant_id, entity_type, entity_value);
```

The migration is explicit that this table carries "the single biggest change" in the
v2 architecture: percentiles resolve against this 6-month per-tenant history
(`app.baseline.resolve.percentile_for`), never against the uploaded file. One row per
`(entity, hour-bucket)` — the same grain L3 (docs/04) scores at — loaded by
`app.baseline.loader` from `data/baseline/baseline_windows.jsonl`, the file
`docs/v2_migration/generate_corpus.py`'s `build_baseline()` writes.

**`features` carries 9 keys today, not ~50.** The generator's `build_baseline()` only emits
`n_events, n_unique_domains, bytes_out, bytes_in, post_ratio, blocked_ratio, off_hours_ratio,
automation_ua_ratio, direct_ip_ratio` per window — see `app.baseline.loader` module docstring
for the full delta against the L3 feature vector (docs/04 "~40 named features"). The loader does
not fabricate the missing features; it loads exactly what the generator produces.

**Why `tenant_id` here carries neither a `tenants` FK nor its own index**, matching
`app.models.event.Event` and `app.models.signal.Signal`: the migration's own SQL above declares
`tenant_id UUID NOT NULL` with no `REFERENCES tenants(id)`, same pattern as every other
high-volume table (this one is windows x hundreds of users x 6 months). Structural tenant
scoping (`app.models.base.TenantScopedMixin`) still fully applies at the ORM layer — the guard
keys off the class, not the column's FK/index.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Index, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class BaselineWindow(Base, TenantScopedMixin):
    __tablename__ = "baseline_windows"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    # Overrides TenantScopedMixin's tenant_id (no FK, no bare index) — see module docstring.
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_value: Mapped[str] = mapped_column(Text, nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    features: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "entity_type",
            "entity_value",
            "window_start",
            name="uq_baseline_windows_tenant_entity_window",
        ),
        Index(
            "ix_baseline_windows_tenant_entity",
            "tenant_id",
            "entity_type",
            "entity_value",
        ),
    )
