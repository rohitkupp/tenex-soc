"""`eval_runs` — docs/02-DATA-MODEL.md "Eval", matched exactly:

```sql
CREATE TABLE eval_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  git_sha TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metrics JSONB NOT NULL,
  passed BOOL NOT NULL
);
```

Not tenant-scoped — no `tenant_id` column in docs/02's SQL. An eval run scores the platform's
detectors/models against a fixed labeled dataset (docs/12); it is not customer data and has no
tenant to scope to.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base


class EvalRun(Base):
    __tablename__ = "eval_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    git_sha: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
