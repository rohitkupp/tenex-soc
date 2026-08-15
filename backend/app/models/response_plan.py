"""`response_plans` — docs/02-DATA-MODEL.md "Triage & response", matched exactly:

```sql
CREATE TABLE response_plans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  actions JSONB NOT NULL,
  verification JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending_approval',
  approved_by UUID REFERENCES users(id),
  approved_at TIMESTAMPTZ,
  execution_log JSONB NOT NULL DEFAULT '[]',
  outcome TEXT,
  outcome_detail JSONB
);
```

Not tenant-scoped — no `tenant_id` column in docs/02's SQL. Isolation is transitive through
`incident_id`, which cascades from `incidents` (a tenant-scoped table). `approved_by` carries
no `ON DELETE` action, matching docs/02 verbatim.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base


class ResponsePlan(Base):
    __tablename__ = "response_plans"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    actions: Mapped[Any] = mapped_column(JSONB, nullable=False)
    verification: Mapped[Any] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="pending_approval")
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_log: Mapped[Any] = mapped_column(JSONB, nullable=False, server_default="[]")
    outcome: Mapped[str | None] = mapped_column(Text, nullable=True)
    outcome_detail: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
