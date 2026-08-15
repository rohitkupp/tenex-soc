"""`incidents` — docs/02-DATA-MODEL.md "Graph & incidents", matched exactly:

```sql
CREATE TABLE incidents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_id UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  fused_score REAL NOT NULL,
  entity_ids BIGINT[] NOT NULL,
  signal_ids BIGINT[] NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  recurrence_of UUID REFERENCES incidents(id),
  recurrence_similarity REAL,
  embedding VECTOR(1024),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON incidents USING hnsw (embedding vector_cosine_ops);
```

`tenant_id` overrides `TenantScopedMixin`'s column exactly like `app.models.event.Event` and
`app.models.signal.Signal` — no FK, no bare index, matching docs/02's literal SQL for this
table. Structural tenant scoping still fully applies (the guard is keyed off the class).

`recurrence_of` is a self-referential FK (`REFERENCES incidents(id)`, no `ON DELETE` action
per docs/02) — an incident can point at an earlier one it's a recurrence of.

`embedding` is `VECTOR(1024)` (`pgvector.sqlalchemy.Vector`), backing the HNSW index
(`vector_cosine_ops`) created in the migration for nearest-neighbor recurrence search.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import ARRAY, REAL, BigInteger, ForeignKey, Index, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class Incident(Base, TenantScopedMixin):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    # Overrides TenantScopedMixin's `tenant_id` column (no FK, no bare index) — see the
    # module docstring; same pattern as app.models.event.Event / app.models.signal.Signal.
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    fused_score: Mapped[float] = mapped_column(REAL, nullable=False)
    entity_ids: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), nullable=False)
    signal_ids: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="open")
    recurrence_of: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id"), nullable=True
    )
    recurrence_similarity: Mapped[float | None] = mapped_column(REAL, nullable=True)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index(
            "ix_incidents_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )
