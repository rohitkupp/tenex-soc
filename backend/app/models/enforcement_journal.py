"""`enforcement_journal` — docs/02-DATA-MODEL.md "Enforcement plane (simulated, stateful)",
matched exactly:

```sql
CREATE TABLE enforcement_journal (
  id BIGSERIAL PRIMARY KEY,
  plan_id UUID NOT NULL REFERENCES response_plans(id),
  action_id TEXT NOT NULL,
  before_state JSONB,
  after_state JSONB,
  succeeded BOOL NOT NULL,
  precondition_failure TEXT,
  executed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Not tenant-scoped — no `tenant_id` column in docs/02's SQL. Isolation is transitive through
`plan_id` -> `response_plans` -> `incidents` (a tenant-scoped table). `plan_id` carries no
`ON DELETE` action, matching docs/02 verbatim — "the journal is what makes rollback real", so a
journal row deliberately does not disappear via cascade the way `entities`/`events` rows do.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base


class EnforcementJournal(Base):
    __tablename__ = "enforcement_journal"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    plan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("response_plans.id"), nullable=False
    )
    action_id: Mapped[str] = mapped_column(Text, nullable=False)
    before_state: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    after_state: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    precondition_failure: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
