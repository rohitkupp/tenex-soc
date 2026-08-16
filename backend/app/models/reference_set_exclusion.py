"""`reference_set_exclusions` — change 21 mechanism 5, "contamination exclusion."

The ledger of every entity-window a confirmed *true positive* verdict has pulled out of the
kNN/LOF/EIF reference and training pools. `app.learning.reference_sets.exclude_from_reference_set`
writes one row here **and**, in the same call, mutates the live `knn.joblib`/`lof.joblib`
artifacts in place (instance-based models: removing a contaminating point is immediate, no
training loop — see that module's docstring). EIF is not instance-based, so its own exclusion is
recorded here for the *next* retrain to consult (`models` below always lists `ml.eif` even though
this table's insert does not itself touch any EIF artifact) — "none / next refit" in change 21's
own mechanism table.

`models` is the literal set of detector keys (`app.detection.ml.detect.ML_*`) this exclusion has
been (or will be) applied to, so a partial failure (e.g. the LOF artifact file is missing) is
visible in the row itself rather than silently assumed complete.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ARRAY, ForeignKey, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class ReferenceSetExclusion(Base, TenantScopedMixin):
    __tablename__ = "reference_set_exclusions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_value: Mapped[str] = mapped_column(Text, nullable=False)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    feedback_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("analyst_feedback.id"), nullable=False
    )
    models: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


__all__ = ["ReferenceSetExclusion"]
