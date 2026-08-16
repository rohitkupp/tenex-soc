"""`model_versions` — docs/02-DATA-MODEL.md "Learning", matched exactly:

```sql
CREATE TABLE model_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  model_key TEXT NOT NULL,
  version INT NOT NULL,
  artifact_ref TEXT NOT NULL,
  trained_at TIMESTAMPTZ NOT NULL,
  eval_scores JSONB NOT NULL,
  promoted BOOL NOT NULL DEFAULT false,
  UNIQUE (model_key, version)
);
```

Not tenant-scoped — no `tenant_id` column in docs/02's SQL. Models (`iforest`, `mahalanobis`,
`ecod`, `lof`, `lightgbm` -- the learning loop's retrain-candidate classifier,
`app.learning.classifier`, not the deleted `app.graph.classifier`; see migration change 19,
`docs/v2_migration/MIGRATION-01-evidence-first.md`) are trained and versioned globally across the
whole platform, not per tenant. `autoencoder`, `logbert`, and `markov` no longer apply -- all
three were cut (autoencoder: change 19; logbert/markov: the earlier L4 sequence-model rejection,
docs/04 §L4).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, Integer, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    model_key: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    artifact_ref: Mapped[str] = mapped_column(Text, nullable=False)
    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    eval_scores: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    promoted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))

    __table_args__ = (
        UniqueConstraint("model_key", "version", name="uq_model_versions_model_key_version"),
    )
