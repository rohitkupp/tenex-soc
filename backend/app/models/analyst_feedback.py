"""`analyst_feedback` — docs/02-DATA-MODEL.md "Learning", matched exactly:

```sql
CREATE TABLE analyst_feedback (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  verdict_id UUID NOT NULL REFERENCES triage_verdicts(id),
  user_id UUID NOT NULL REFERENCES users(id),
  agrees BOOL NOT NULL,
  corrected_disposition TEXT,
  corrected_technique TEXT,
  dismissal_reason TEXT,
  mark_benign_baseline BOOL NOT NULL DEFAULT false,
  note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Not tenant-scoped — no `tenant_id` column in docs/02's SQL. Isolation is transitive through
`verdict_id` -> `triage_verdicts` -> `incidents` (a tenant-scoped table), and `user_id` is
itself scoped to one tenant. Neither FK carries an `ON DELETE` action, matching docs/02
verbatim — feedback is a durable analyst record, not a row meant to vanish on cascade.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    verdict_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("triage_verdicts.id"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    agrees: Mapped[bool] = mapped_column(Boolean, nullable=False)
    corrected_disposition: Mapped[str | None] = mapped_column(Text, nullable=True)
    corrected_technique: Mapped[str | None] = mapped_column(Text, nullable=True)
    dismissal_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    mark_benign_baseline: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
