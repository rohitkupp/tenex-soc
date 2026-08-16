"""`detector_stats` — docs/02-DATA-MODEL.md "Learning", matched exactly:

```sql
CREATE TABLE detector_stats (
  detector_key TEXT PRIMARY KEY,
  tenant_id UUID NOT NULL,
  true_positives INT NOT NULL DEFAULT 0,
  false_positives INT NOT NULL DEFAULT 0,
  fusion_weight REAL NOT NULL DEFAULT 1.0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

The primary key is `detector_key` itself (no surrogate `id`) — matched exactly, docs/02's own
choice, not an oversight here.

`tenant_id` overrides `TenantScopedMixin`'s column exactly like `app.models.event.Event` /
`app.models.signal.Signal` / `app.models.incident.Incident` — no FK, no bare index, matching
docs/02's literal SQL.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import REAL, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class DetectorStats(Base, TenantScopedMixin):
    __tablename__ = "detector_stats"

    detector_key: Mapped[str] = mapped_column(Text, primary_key=True)
    # Overrides TenantScopedMixin's `tenant_id` column (no FK, no bare index) — see the
    # module docstring; same pattern as app.models.event.Event et al.
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    true_positives: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    false_positives: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    fusion_weight: Mapped[float] = mapped_column(REAL, nullable=False, server_default="1.0")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
