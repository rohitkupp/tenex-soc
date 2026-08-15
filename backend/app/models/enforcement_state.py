"""`enforcement_state` — docs/02-DATA-MODEL.md "Enforcement plane (simulated, stateful)",
matched exactly:

```sql
CREATE TABLE enforcement_state (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  state JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, resource_type, resource_id)
);
```

`tenant_id` overrides `TenantScopedMixin`'s column exactly like `app.models.event.Event` /
`app.models.signal.Signal` / `app.models.incident.Incident` — no FK, no *bare* index, matching
docs/02's literal SQL. The `UNIQUE (tenant_id, resource_type, resource_id)` constraint below
still produces its own composite index leading with `tenant_id` (that's what docs/02 specifies
— a uniqueness constraint, not a plain lookup index), so this table is not left without any
index that can drive a tenant-scoped query.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class EnforcementState(Base, TenantScopedMixin):
    __tablename__ = "enforcement_state"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    # Overrides TenantScopedMixin's `tenant_id` column (no FK, no bare index) — see the
    # module docstring; same pattern as app.models.event.Event et al.
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    resource_type: Mapped[str] = mapped_column(Text, nullable=False)
    resource_id: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "resource_type",
            "resource_id",
            name="uq_enforcement_state_tenant_id_resource_type_resource_id",
        ),
    )
