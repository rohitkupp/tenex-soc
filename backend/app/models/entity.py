"""`entities` — docs/02-DATA-MODEL.md "Graph & incidents", matched exactly:

```sql
CREATE TABLE entities (
  id BIGSERIAL PRIMARY KEY,
  analysis_id UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  first_seen TIMESTAMPTZ,
  last_seen TIMESTAMPTZ,
  event_count INT NOT NULL DEFAULT 0,
  risk_score REAL NOT NULL DEFAULT 0,
  attrs JSONB NOT NULL DEFAULT '{}',
  UNIQUE (analysis_id, type, value)
);
```

Not tenant-scoped — docs/02's own SQL has no `tenant_id` column on this table at all (unlike
`signals`/`incidents`/etc., which at least carry a bare `tenant_id`, same reasoning as
`app.models.dead_letter.DeadLetter`). Isolation is transitive through `analysis_id`, which
cascades from `analyses` — a tenant-scoped table itself. Because there is no `tenant_id` column
to scope on, this model does **not** mix in `app.models.base.TenantScopedMixin`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import REAL, BigInteger, ForeignKey, Integer, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base


class Entity(Base):
    __tablename__ = "entities"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    risk_score: Mapped[float] = mapped_column(REAL, nullable=False, server_default="0")
    attrs: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")

    __table_args__ = (
        UniqueConstraint("analysis_id", "type", "value", name="uq_entities_analysis_id_type_value"),
    )
