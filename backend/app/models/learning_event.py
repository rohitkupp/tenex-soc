"""`learning_events` — docs/v2_migration/MIGRATION-01-evidence-first.md change 21's ledger,
matched exactly to the task brief's schema:

```sql
CREATE TABLE learning_events (
  id BIGSERIAL PRIMARY KEY,
  mechanism INT NOT NULL,              -- 1..15
  trigger_feedback_id UUID,
  applied BOOL NOT NULL,               -- false = proposed, awaiting approval
  before_state JSONB, after_state JSONB,
  metric_delta JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Not tenant-scoped — the schema above carries no `tenant_id` column, and change 23 (shared
workspace, single live tenant) already removed per-tenant partitioning as a live concern: every
login shares one workspace, so a single global ledger of "what the learning loop did" is the
correct grain, not an artificial per-tenant split the schema was never given.

`mechanism` is one of the 15 numbered consumers in change 21's two tables (`app.learning.
mechanisms.MECHANISMS` is the single source of truth for the id -> name -> auto/gated mapping;
this column is deliberately a bare `INT`, not an enum, so a new mechanism never needs a migration
to add a value). `applied=True` means the state change in `after_state` is live; `applied=False`
means it is a gated proposal awaiting human approval (`app.learning.proposals`) — see that
module's docstring for why a rejected gated candidate also stays `applied=False` forever rather
than being deleted ("keep the rejection history," change 21).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, Integer, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base


class LearningEvent(Base):
    __tablename__ = "learning_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    mechanism: Mapped[int] = mapped_column(Integer, nullable=False)
    trigger_feedback_id: Mapped[Any | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    applied: Mapped[bool] = mapped_column(Boolean, nullable=False)
    before_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    after_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    metric_delta: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
