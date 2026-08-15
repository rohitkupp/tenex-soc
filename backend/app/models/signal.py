"""`signals` — docs/02-DATA-MODEL.md "Detection", matched exactly:

```sql
CREATE TABLE signals (
  id BIGSERIAL PRIMARY KEY,
  analysis_id UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL,
  detector_key TEXT NOT NULL,
  detector_layer TEXT NOT NULL,
  raw_score REAL NOT NULL,
  confidence REAL NOT NULL,
  entity_type TEXT NOT NULL,
  entity_value TEXT NOT NULL,
  window_start TIMESTAMPTZ,
  window_end TIMESTAMPTZ,
  mitre_technique TEXT,
  evidence_event_ids BIGINT[] NOT NULL,
  explanation JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON signals (analysis_id, confidence DESC);
```

`tenant_id` here overrides `TenantScopedMixin`'s column exactly the way `app.models.event.Event`
does, for the same reason: docs/02's own SQL gives `signals.tenant_id` neither a
`REFERENCES tenants(id)` FK nor a standalone index — it's one of the high-volume detection
tables (evaluated at 1M+ event scale per analysis), and the FK/index costs aren't paid twice
when `(analysis_id, confidence DESC)` below is what real queries actually drive on. Structural
tenant scoping (`app.models.base.TenantScopedMixin`) still fully applies at the ORM layer
regardless — the guard keys off the class, not the column's FK/index.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ARRAY, REAL, BigInteger, ForeignKey, Index, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class Signal(Base, TenantScopedMixin):
    __tablename__ = "signals"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    # Overrides TenantScopedMixin's `tenant_id` column (no FK, no bare index) — see the
    # module docstring; same pattern as app.models.event.Event.
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    detector_key: Mapped[str] = mapped_column(Text, nullable=False)
    detector_layer: Mapped[str] = mapped_column(Text, nullable=False)
    raw_score: Mapped[float] = mapped_column(REAL, nullable=False)
    confidence: Mapped[float] = mapped_column(REAL, nullable=False)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_value: Mapped[str] = mapped_column(Text, nullable=False)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_event_ids: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), nullable=False)
    explanation: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (Index("ix_signals_analysis_id_confidence", "analysis_id", confidence.desc()),)
