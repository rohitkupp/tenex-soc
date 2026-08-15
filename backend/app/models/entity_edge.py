"""`entity_edges` — docs/02-DATA-MODEL.md "Graph & incidents", matched exactly:

```sql
CREATE TABLE entity_edges (
  id BIGSERIAL PRIMARY KEY,
  analysis_id UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  src_entity_id BIGINT NOT NULL REFERENCES entities(id),
  dst_entity_id BIGINT NOT NULL REFERENCES entities(id),
  relation TEXT NOT NULL,
  weight REAL NOT NULL DEFAULT 1,
  event_count INT NOT NULL DEFAULT 0
);
```

Not tenant-scoped, same reasoning as `app.models.entity.Entity`: docs/02's SQL has no
`tenant_id` column here either, and isolation is transitive through `analysis_id`.

`src_entity_id`/`dst_entity_id` carry no `ON DELETE` action in docs/02 (unlike `analysis_id`'s
`CASCADE`) — matched exactly. In practice this table's rows are always deleted alongside their
entities as part of the same `analyses` cascade (both `entities` and `entity_edges` reference
`analysis_id ON DELETE CASCADE`), so the missing action on the entity FKs is never exercised on
its own.
"""

from __future__ import annotations

import uuid

from sqlalchemy import REAL, BigInteger, ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from app.core.db import Base


class EntityEdge(Base):
    __tablename__ = "entity_edges"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    src_entity_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("entities.id"), nullable=False
    )
    dst_entity_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("entities.id"), nullable=False
    )
    relation: Mapped[str] = mapped_column(Text, nullable=False)
    weight: Mapped[float] = mapped_column(REAL, nullable=False, server_default="1")
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
