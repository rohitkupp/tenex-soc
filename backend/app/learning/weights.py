"""Consumer 2 — Detector weight tuning (docs/08 Part 2, §2). No retraining.

```
precision_d = TP_d / (TP_d + FP_d)
fusion_weight_d = clamp(precision_d / prior_precision, 0.25, 1.5)
```

Written to `detector_stats` (docs/02). A detector analysts consistently dismiss gets
down-weighted in fusion; a detector analysts consistently confirm gets up-weighted, capped at
1.5x so no single detector can dominate `fused = 1 - Π(1 - w_d * c_d)` (docs/04 "Fusion &
calibration") on the strength of a handful of lucky early confirmations. This is real SOC
detection tuning, and the numbers behind every weight change must be visible and explainable —
`WeightTuningResult` below carries `true_positives`/`false_positives`/`precision` alongside the
weight itself for exactly that reason; `GET /api/learning/metrics` renders all of it, not just
the final multiplier.

`detector_stats.detector_key` is `docs/02`'s own primary key (no `tenant_id` in the uniqueness
constraint, matched exactly — see `app.models.detector_stats`'s docstring). In this single-tenant
demo deployment that is transparent; a genuinely multi-tenant deployment would need docs/02
extended with a composite key, which is out of this milestone's scope to redesign (`docs/02-DATA-
MODEL.md` is explicitly off limits here) — flagged here rather than silently worked around.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.feedback_data import LabeledExample, labeled_examples
from app.models.base import tenant_scope
from app.models.detector_stats import DetectorStats

__all__ = [
    "MAX_FUSION_WEIGHT",
    "MIN_FUSION_WEIGHT",
    "DetectorWeightChange",
    "WeightTuningResult",
    "retune_detector_weights",
]

MIN_FUSION_WEIGHT = 0.25
MAX_FUSION_WEIGHT = 1.5


@dataclass(slots=True)
class DetectorWeightChange:
    detector_key: str
    true_positives: int
    false_positives: int
    precision: float | None
    weight_before: float
    weight_after: float
    changed: bool


@dataclass(slots=True)
class WeightTuningResult:
    tenant_id: uuid.UUID
    tuned_at: datetime
    prior_precision: float | None
    n_feedback_events: int
    detectors: list[DetectorWeightChange]


def _counts_by_detector(examples: list[LabeledExample]) -> dict[str, tuple[int, int]]:
    """`detector_key -> (true_positives, false_positives)`."""
    counts: dict[str, tuple[int, int]] = {}
    for ex in examples:
        tp, fp = counts.get(ex.detector_key, (0, 0))
        if ex.label == 1:
            tp += 1
        else:
            fp += 1
        counts[ex.detector_key] = (tp, fp)
    return counts


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def retune_detector_weights(
    session: Session, tenant_id: uuid.UUID, *, persist: bool = True
) -> WeightTuningResult:
    """Recompute `precision_d` and `fusion_weight_d` for every detector with at least one labeled
    feedback event, and upsert `detector_stats`. `prior_precision` is the pooled precision across
    *all* detectors with any labeled feedback — the fleet-wide baseline every individual
    detector's weight is measured against, so a detector performing exactly at the fleet average
    lands at `fusion_weight = 1.0` (no adjustment), one performing worse gets down-weighted, and
    one performing better gets up-weighted, both clamped to `[0.25, 1.5]`.
    """
    examples = labeled_examples(session, tenant_id)
    counts = _counts_by_detector(examples)

    total_tp = sum(tp for tp, _ in counts.values())
    total_fp = sum(fp for _, fp in counts.values())
    prior_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else None

    changes: list[DetectorWeightChange] = []
    with tenant_scope(session, tenant_id):
        existing = {
            row.detector_key: row for row in session.execute(select(DetectorStats)).scalars().all()
        }

        for detector_key, (tp, fp) in sorted(counts.items()):
            precision = tp / (tp + fp) if (tp + fp) > 0 else None
            row = existing.get(detector_key)
            weight_before = row.fusion_weight if row is not None else 1.0

            if precision is None or prior_precision is None or prior_precision == 0:
                weight_after = weight_before
            else:
                weight_after = _clamp(
                    precision / prior_precision, MIN_FUSION_WEIGHT, MAX_FUSION_WEIGHT
                )

            changes.append(
                DetectorWeightChange(
                    detector_key=detector_key,
                    true_positives=tp,
                    false_positives=fp,
                    precision=precision,
                    weight_before=weight_before,
                    weight_after=weight_after,
                    changed=abs(weight_after - weight_before) > 1e-9,
                )
            )

            if not persist:
                continue
            if row is None:
                session.add(
                    DetectorStats(
                        detector_key=detector_key,
                        tenant_id=tenant_id,
                        true_positives=tp,
                        false_positives=fp,
                        fusion_weight=weight_after,
                    )
                )
            else:
                row.true_positives = tp
                row.false_positives = fp
                row.fusion_weight = weight_after
        if persist:
            # Flush only -- commit is the caller's responsibility (the request-scoped session
            # from `app.core.db.get_db` commits once at end of request; `app/scripts/
            # seed_feedback.py` commits explicitly on its own schedule). Matches
            # `app.learning.suppression`/`app.learning.benign_corpus`, which do the same.
            session.flush()

    return WeightTuningResult(
        tenant_id=tenant_id,
        tuned_at=datetime.now(UTC),
        prior_precision=prior_precision,
        n_feedback_events=len({e.feedback_id for e in examples}),
        detectors=changes,
    )
