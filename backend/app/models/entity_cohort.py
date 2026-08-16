"""`entity_cohorts` — change 21 mechanism 7, "cohort re-derivation" (gated).

The *applied* side of a cohort-re-derivation proposal (`app.learning.cohorts`,
`app.models.learning_proposal`): one row per `(tenant_id, entity_type, entity_value)`, upserted
whenever an analyst accepts a re-clustering candidate. `app.detection.ml.features`'s own
department-cohort features (`*_z_vs_cohort`) key off the entity's literal HR `department` string —
this table is not a replacement for that, it is the re-derived grouping this milestone's learning
loop proposes when the literal department label stops matching observed peer behavior (docs/04
"Peer-group cohorts"), for a future LOF-retrain integration to read.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Integer, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime

from app.core.db import Base
from app.models.base import TenantScopedMixin


class EntityCohort(Base, TenantScopedMixin):
    __tablename__ = "entity_cohorts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_value: Mapped[str] = mapped_column(Text, nullable=False)
    cohort_label: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(Text, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "entity_type", "entity_value", name="uq_entity_cohorts_entity"
        ),
    )


__all__ = ["EntityCohort"]
