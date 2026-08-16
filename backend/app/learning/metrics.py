"""`GET /api/learning/metrics` (docs/09): "alignment %, per-detector precision trend." This
module computes both, live, from `analyst_feedback`/`signals` — no separate metrics table; the
source data is small enough at this scale that a stored rollup would just be a second,
driftable copy.

Every returned figure that could be influenced by `make seed`'s synthetic feedback history
(`app/scripts/seed_feedback.py`) is paired with a synthetic count so `GET /api/learning/metrics`
never presents seeded numbers as if they were real analyst activity (docs/08 "Demo honesty").

Containment rate (docs/08 Part 1's headline response metric) was removed along with the
response action graph and enforcement plane in docs/v2_migration change 20 — "autonomous
containment rate is gone as a metric" — so it no longer appears here.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.feedback_data import LabeledExample, labeled_examples
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.synthetic_seed_marker import SyntheticSeedMarker
from app.models.triage_verdict import TriageVerdict

__all__ = [
    "AlignmentPoint",
    "DetectorPrecisionPoint",
    "LearningMetrics",
    "compute_learning_metrics",
    "synthetic_feedback_ids",
]

_TREND_BUCKET = timedelta(days=7)


def synthetic_feedback_ids(session: Session, tenant_id: uuid.UUID) -> set[uuid.UUID]:
    """Every `analyst_feedback.id` `app/scripts/seed_feedback.py` created, per the
    `learning_synthetic_seed` marker table (`app.models.synthetic_seed_marker`'s docstring).
    Public: `app/api/models.py`'s calibration route reuses this directly rather than
    re-deriving the same query."""
    with tenant_scope(session, tenant_id):
        rows = (
            session.execute(
                select(SyntheticSeedMarker.row_id).where(
                    SyntheticSeedMarker.table_name == "analyst_feedback"
                )
            )
            .scalars()
            .all()
        )
    return {uuid.UUID(r) for r in rows}


def _bucket_start(ts: datetime, epoch: datetime) -> datetime:
    elapsed = ts - epoch
    n_buckets = int(elapsed / _TREND_BUCKET)
    return epoch + n_buckets * _TREND_BUCKET


@dataclass(frozen=True, slots=True)
class AlignmentPoint:
    period_start: datetime
    period_end: datetime
    alignment_pct: float
    n: int
    synthetic: bool


@dataclass(frozen=True, slots=True)
class DetectorPrecisionPoint:
    detector_key: str
    period_start: datetime
    period_end: datetime
    precision: float | None
    n: int
    synthetic: bool


@dataclass(slots=True)
class LearningMetrics:
    tenant_id: uuid.UUID
    computed_at: datetime
    n_feedback_events: int
    n_synthetic_feedback_events: int
    alignment_pct: float | None
    alignment_trend: list[AlignmentPoint] = field(default_factory=list)
    detector_precision_trend: list[DetectorPrecisionPoint] = field(default_factory=list)


def _alignment_trend(
    feedback_rows: list[tuple[uuid.UUID, bool, datetime]], synthetic_ids: set[uuid.UUID]
) -> list[AlignmentPoint]:
    if not feedback_rows:
        return []
    epoch = min(ts for _, _, ts in feedback_rows)
    buckets: dict[datetime, list[tuple[bool, bool]]] = {}
    for feedback_id, agrees, ts in feedback_rows:
        bucket = _bucket_start(ts, epoch)
        buckets.setdefault(bucket, []).append((agrees, feedback_id in synthetic_ids))

    points: list[AlignmentPoint] = []
    for bucket in sorted(buckets):
        entries = buckets[bucket]
        n = len(entries)
        alignment = sum(1 for agrees, _ in entries if agrees) / n
        all_synthetic = all(is_synth for _, is_synth in entries)
        points.append(
            AlignmentPoint(
                period_start=bucket,
                period_end=bucket + _TREND_BUCKET,
                alignment_pct=alignment,
                n=n,
                synthetic=all_synthetic,
            )
        )
    return points


def _detector_precision_trend(
    examples: list[LabeledExample], synthetic_ids: set[uuid.UUID]
) -> list[DetectorPrecisionPoint]:
    if not examples:
        return []
    epoch = min(e.created_at for e in examples)
    buckets: dict[tuple[str, datetime], list[LabeledExample]] = {}
    for ex in examples:
        bucket = _bucket_start(ex.created_at, epoch)
        buckets.setdefault((ex.detector_key, bucket), []).append(ex)

    points: list[DetectorPrecisionPoint] = []
    for (detector_key, bucket), exs in sorted(buckets.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        tp = sum(1 for e in exs if e.label == 1)
        n = len(exs)
        all_synthetic = all(e.feedback_id in synthetic_ids for e in exs)
        points.append(
            DetectorPrecisionPoint(
                detector_key=detector_key,
                period_start=bucket,
                period_end=bucket + _TREND_BUCKET,
                precision=tp / n if n else None,
                n=n,
                synthetic=all_synthetic,
            )
        )
    return points


def compute_learning_metrics(session: Session, tenant_id: uuid.UUID) -> LearningMetrics:
    synthetic_ids = synthetic_feedback_ids(session, tenant_id)

    with tenant_scope(session, tenant_id):
        # The join through `triage_verdicts` -> `incidents` is what makes this tenant-scoped, and
        # it is not optional. `analyst_feedback` carries no `tenant_id` column and no
        # `TenantScopedMixin` (docs/02: it is isolated transitively, the same way
        # `app.learning.feedback_data.labeled_examples` and `app.learning.classifier` already do
        # it) — so a bare `select(AnalystFeedback)` inside `tenant_scope` receives no loader
        # criteria at all and silently returns *every tenant's* feedback. That is what this query
        # used to do: on a single-tenant database it looked correct, and it took a database
        # holding several tenants' rows for `GET /api/learning/metrics` to start reporting a
        # cross-tenant count and alignment percentage.
        feedback_rows = [
            (feedback.id, feedback.agrees, feedback.created_at)
            for feedback, _verdict, _incident in session.execute(
                select(AnalystFeedback, TriageVerdict, Incident)
                .join(TriageVerdict, AnalystFeedback.verdict_id == TriageVerdict.id)
                .join(Incident, TriageVerdict.incident_id == Incident.id)
            ).all()
        ]

    examples = labeled_examples(session, tenant_id)

    n_feedback = len(feedback_rows)
    n_synthetic = sum(1 for fid, _, _ in feedback_rows if fid in synthetic_ids)
    alignment_pct = (
        sum(1 for _, agrees, _ in feedback_rows if agrees) / n_feedback if n_feedback else None
    )

    return LearningMetrics(
        tenant_id=tenant_id,
        computed_at=datetime.now(UTC),
        n_feedback_events=n_feedback,
        n_synthetic_feedback_events=n_synthetic,
        alignment_pct=alignment_pct,
        alignment_trend=_alignment_trend(feedback_rows, synthetic_ids),
        detector_precision_trend=_detector_precision_trend(examples, synthetic_ids),
    )
