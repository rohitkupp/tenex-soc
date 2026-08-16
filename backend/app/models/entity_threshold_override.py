"""`entity_threshold_overrides` — change 21 mechanism 3, "entity threshold adaptation."

Not in docs/02's literal SQL (that document predates change 21's 15 mechanisms), matching the
precedent every M13-era learning table already set (`app.models.suppression_candidate`,
`app.models.benign_baseline_entry`): additive-only, no existing table touched.

One row per `(tenant_id, entity_type, entity_value, detector_key)` — `detector_key` uses the
sentinel `""` (empty string, `ALL_DETECTORS` below) rather than `NULL` for "applies to every
detector for this entity," so the natural composite unique constraint below actually enforces
uniqueness (`NULL <> NULL` in a Postgres unique index would silently allow duplicate "all
detectors" rows for the same entity, one clobbering the other's history at read time).

`threshold_percentile` starts at `app.detection.ml.detect.SIGNAL_CONFIDENCE_THRESHOLD` (0.995,
the system-wide default every detector's binary emit/suppress decision uses) and is only ever
*raised* for an entity with a pattern of dismissals, or relaxed back down toward the default on a
pattern of confirmations — see `app.learning.entity_thresholds` for the update rule. This table is
the read side for a future detection-layer integration to consult (the same "propose a change,
document the read contract, do not wire it into a package this milestone does not own" pattern
`app.learning.calibration.apply_calibrator` and `app.learning.suppression`'s module docstring both
already establish for this codebase).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import REAL, Integer, Text, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime

from app.core.db import Base
from app.models.base import TenantScopedMixin

ALL_DETECTORS = ""


class EntityThresholdOverride(Base, TenantScopedMixin):
    __tablename__ = "entity_threshold_overrides"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_value: Mapped[str] = mapped_column(Text, nullable=False)
    # `ALL_DETECTORS` ("") when the override applies across every detector for this entity —
    # see module docstring for why this is a sentinel, not `NULL`.
    detector_key: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("''"))
    threshold_percentile: Mapped[float] = mapped_column(REAL, nullable=False)
    confirm_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    dismiss_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "entity_type",
            "entity_value",
            "detector_key",
            name="uq_entity_threshold_overrides_entity_detector",
        ),
    )


__all__ = ["ALL_DETECTORS", "EntityThresholdOverride"]
