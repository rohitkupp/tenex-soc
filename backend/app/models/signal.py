"""`signals` — docs/02-DATA-MODEL.md "Detection", matched exactly (plus `calibrated`, added by
migration `signals_calibrated_provenance` / docs/04 §Fusion "Calibration provenance"):

```sql
CREATE TABLE signals (
  id BIGSERIAL PRIMARY KEY,
  analysis_id UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL,
  detector_key TEXT NOT NULL,
  detector_layer TEXT NOT NULL,
  raw_score REAL NOT NULL,
  confidence REAL NOT NULL,
  calibrated BOOLEAN NOT NULL DEFAULT FALSE,
  entity_type TEXT NOT NULL,
  entity_value TEXT NOT NULL,
  window_start TIMESTAMPTZ,
  window_end TIMESTAMPTZ,
  mitre_technique TEXT,
  evidence_event_ids BIGINT[] NOT NULL,
  explanation JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON signals (analysis_id, confidence DESC);
```

`tenant_id` here overrides `TenantScopedMixin`'s column exactly the way `app.models.event.Event`
does, for the same reason: docs/02's own SQL gives `signals.tenant_id` neither a
`REFERENCES tenants(id)` FK nor a standalone index — it's one of the high-volume detection
tables (evaluated at 1M+ event scale per analysis), and the FK/index costs aren't paid twice
when `(analysis_id, confidence DESC)` below is what real queries actually drive on. Structural
tenant scoping (`app.models.base.TenantScopedMixin`) still fully applies at the ORM layer
regardless — the guard keys off the class, not the column's FK/index.

## `calibrated` — is `confidence` a real probability, or `clamp01(raw_score)` in a trenchcoat?

`app.detection.calibration.CalibratorStore.calibrate()` falls back to `clamp01(raw_score)` when
a detector has no fitted isotonic calibrator yet (never seen during fitting, or too few/
degenerate samples — `MIN_SAMPLES_TO_FIT`). That fallback is permanent policy, not a gap to
eventually close: new detectors ship before their first fit, and some (`sigma.blocked_then_
allowed`, `signal.stl_residual` at this measurement) never accumulate enough labeled samples.
The bug this column fixes is not the fallback existing — it's that `clamp01` on an unbounded
raw score (a robust-z, in `signal.stl_residual`'s case) saturates at exactly `1.0`, which then
LOOKS like a calibrated model's most confident possible output and silently outranks genuinely
calibrated signals wherever `confidence` is sorted (`app.agent.orchestrator.
_build_incident_context_block`'s top-30 selection, chiefly).

`calibrated=True` means this row's `confidence` came from a real `IsotonicCalibrator` fit on
labeled data (a genuine, if imperfect, probability). `calibrated=False` means `confidence` is
the `clamp01(raw_score)` fallback — a number in `[0, 1]` shaped like a probability but
carrying none of the guarantees of one. Set once, at the same call site that computes
`confidence` (`CalibratorStore.has(detector_key)`, checked before `.calibrate()` is called —
see `app/pipeline/stages/detect.py::_recalibrate_signals` and `app/graph/pipeline_demo.py::
run_scenario`), never recomputed afterward. A column, not a derived/computed property: the
same detector_key can be calibrated at one point in time and not at another (a fresh detector
before its first `fit-calibrators` run, or an existing detector whose calibrator artifact was
deleted/degraded) — provenance is a fact about *when this specific row was written*, which a
property recomputed against today's `CalibratorStore` on every read would get wrong for any
already-persisted row.

Existing rows, backfilled to `False` by the migration that added this column: their true
provenance can't be reconstructed after the fact (the calibrator roster has changed over time,
so "was `store.has(detector_key)` true at write time" isn't answerable retroactively), and
`False` — "treat as unmeasured until proven otherwise" — is the safe direction to be wrong in,
matching this column's whole reason for existing.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ARRAY, REAL, BigInteger, Boolean, ForeignKey, Index, Text, false, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class Signal(Base, TenantScopedMixin):
    __tablename__ = "signals"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    # Overrides TenantScopedMixin's `tenant_id` column (no FK, no bare index) — see the
    # module docstring; same pattern as app.models.event.Event.
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    detector_key: Mapped[str] = mapped_column(Text, nullable=False)
    detector_layer: Mapped[str] = mapped_column(Text, nullable=False)
    raw_score: Mapped[float] = mapped_column(REAL, nullable=False)
    confidence: Mapped[float] = mapped_column(REAL, nullable=False)
    # Calibration provenance -- see module docstring "calibrated" section. Defaults to False
    # (the safe direction: "unmeasured until proven otherwise") both in Python (for any
    # constructor call site that predates this column, e.g. app/scripts/seed_feedback.py's
    # explicitly-uncalibrated synthetic rows) and at the DB level (server_default, for any
    # insert that bypasses the ORM default).
    calibrated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_value: Mapped[str] = mapped_column(Text, nullable=False)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_event_ids: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), nullable=False)
    explanation: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (Index("ix_signals_analysis_id_confidence", "analysis_id", confidence.desc()),)
