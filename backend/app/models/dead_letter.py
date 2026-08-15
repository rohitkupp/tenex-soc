"""`dead_letters` — docs/02-DATA-MODEL.md "Ops & Tier 2", matched exactly:

```sql
CREATE TABLE dead_letters (
  id BIGSERIAL PRIMARY KEY,
  analysis_id UUID,
  stage TEXT NOT NULL,
  payload JSONB NOT NULL,
  error TEXT NOT NULL,
  attempts INT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  retried_at TIMESTAMPTZ
);
```

Not tenant-scoped — docs/02's own SQL has no `tenant_id` column here at all (unlike
`events`/`signals`/etc., which at least carry a bare `tenant_id` even without an FK).
This is deliberate for an ops/admin table: a dead letter is failure telemetry about the
*pipeline*, read by whoever operates it (`GET /api/ops/dead-letters`), not customer
data scoped to one tenant's view. `payload` is the full `StageMessage` JSON that failed
(analysis_id/tenant_id are already inside it), which is enough for an operator to find
the owning tenant/analysis without this table needing its own column for it. Because
there is no `tenant_id` to scope on, this model does **not** mix in
`app.models.base.TenantScopedMixin` — doing so would either be a no-op (no column to
filter) or require inventing a column the data model doesn't have.

`analysis_id` has no `REFERENCES analyses(id)` either, again matching docs/02 exactly:
a dead letter must survive `DELETE /api/analyses/{id}`'s cascade (docs/09) intact as a
historical record, not disappear or block the delete with an FK violation.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Integer, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from app.core.db import Base


class DeadLetter(Base):
    __tablename__ = "dead_letters"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    analysis_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    stage: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    error: Mapped[str] = mapped_column(Text, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    retried_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
