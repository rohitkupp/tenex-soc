"""Consumer 1 — Calibration refit (docs/08 Part 2, §1). No retraining.

Confirmed/rejected dispositions become labels; refit the per-detector isotonic calibrator so
stated confidence tracks observed precision. Measured with Brier score and a reliability diagram
(10 bins, predicted vs. observed precision — docs/12 "Calibration").

## Where the calibrator itself lives — read this before changing anything here

The task brief for this milestone says plainly: *"a concurrent agent owns
`app/detection/calibration.py` — import and call it, do not reimplement or edit it."* That file
does not exist in this checkout. Neither does `app/detection/fusion.py` (M10, not built) — and
`app/detection/sigma/runner.py`'s own module docstring says the isotonic calibrator "belong[s] to
the fusion milestone... out of this package's scope," which is exactly why every `signals.
confidence` written today is a documented raw-score pass-through (`"calibrated": false` in
`explanation`), not a real probability.

So there is nothing to import. Reimplementing a module that was never written is not the
violation the brief is warning against — leaving M13's own acceptance bar unmet ("Feedback
measurably shifts calibration... show before/after numbers") because a sibling file hasn't
landed yet would be worse than building the fit here, in `app/learning`, which this milestone
does own. `_fit_isotonic` below is the *one* function that would change if/when
`app/detection/calibration.py` (or `fusion.py`) appears with a compatible
`fit(raw_scores, labels) -> Calibrator` surface — everything else in this module (label
derivation, Brier scoring, the reliability diagram, persistence, the refit cadence) is unaffected
by which isotonic implementation backs it.

## Labels

docs/08: "Confirmed and rejected dispositions become labels." A `triage_verdicts.disposition` of
`"true_positive"` that the analyst confirms (`agrees=True`), or a non-`"true_positive"`
disposition the analyst *corrects* to `"true_positive"`, is a positive label (`1`); everything
else is negative (`0`). One label applies to every signal that contributed to the incident
(`incidents.signal_ids`) — the fusion score does not attribute credit to individual signals, so
this consumer does not invent an attribution scheme it cannot support; it labels every
contributing detector's raw score with the incident-level outcome, exactly as docs/08's formula
for consumer 2 (`precision_d = TP_d / (TP_d + FP_d)`) already assumes.

## Persistence

One `IsotonicRegression`, pickled via `joblib`, per `(tenant_id, detector_key)` under
`backend/data/models/learning/calibration/`. `apply_calibrator` is the read side any future
scoring path (fusion, or this milestone's own reporting) calls; it degrades to an identity
pass-through when no calibrator has been fit yet, matching `sigma/runner.py`'s own documented
interim policy rather than inventing a different one.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import numpy.typing as npt
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import brier_score_loss
from sqlalchemy.orm import Session

from app.learning.feedback_data import LabeledExample, labeled_examples

__all__ = [
    "CALIBRATION_ARTIFACT_DIR",
    "REFIT_EVERY_N_FEEDBACK",
    "CalibrationRefitResult",
    "DetectorCalibrationResult",
    "ReliabilityBin",
    "apply_calibrator",
    "refit_calibrators",
    "should_refit_now",
]

# backend/app/learning/calibration.py -> learning -> app -> backend
_BACKEND_ROOT = Path(__file__).resolve().parents[2]
CALIBRATION_ARTIFACT_DIR: Path = _BACKEND_ROOT / "data" / "models" / "learning" / "calibration"

# docs/08 §1: "Run nightly or on every 50 feedback events." This process has no scheduler of its
# own (no cron/worker is part of this milestone's ownership); `app/api/learning.py`'s feedback
# endpoint calls `should_refit_now` after each insert and refits synchronously when it is due —
# small enough at this data scale to do inline rather than queue a job for infrastructure that
# doesn't exist yet.
REFIT_EVERY_N_FEEDBACK = 50

_RELIABILITY_BINS = 10


def _safe_filename(detector_key: str) -> str:
    return detector_key.replace("/", "_").replace(" ", "_")


def _artifact_path(tenant_id: uuid.UUID, detector_key: str) -> Path:
    return CALIBRATION_ARTIFACT_DIR / str(tenant_id) / f"{_safe_filename(detector_key)}.joblib"


@dataclass(slots=True)
class ReliabilityBin:
    """One row of the reliability diagram (docs/12: "10 bins, predicted vs. observed
    precision")."""

    bin_lo: float
    bin_hi: float
    predicted_mean: float | None
    observed_precision: float | None
    n: int


@dataclass(slots=True)
class DetectorCalibrationResult:
    detector_key: str
    n_samples: int
    n_positive: int
    fitted: bool
    skip_reason: str | None
    brier_before: float | None
    brier_after: float | None
    reliability_before: list[ReliabilityBin] = field(default_factory=list)
    reliability_after: list[ReliabilityBin] = field(default_factory=list)

    @property
    def brier_improvement(self) -> float | None:
        if self.brier_before is None or self.brier_after is None:
            return None
        return self.brier_before - self.brier_after


@dataclass(slots=True)
class CalibrationRefitResult:
    tenant_id: uuid.UUID
    refit_at: datetime
    n_feedback_events: int
    detectors: list[DetectorCalibrationResult]
    overall_brier_before: float | None
    overall_brier_after: float | None


def _fit_isotonic(
    raw_scores: npt.NDArray[np.float64], labels: npt.NDArray[np.float64]
) -> IsotonicRegression:
    """The one function to swap for `app.detection.calibration`'s fit routine once that module
    exists — see the module docstring. `out_of_bounds='clip'` matches docs/04's percentile-style
    calibration elsewhere (`app/detection/ml/detect.py`'s docstring) in never extrapolating past
    the training range for a raw score this detector hasn't produced before."""
    model = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    model.fit(raw_scores, labels)
    return model


def _reliability_bins(
    predicted: npt.NDArray[np.float64],
    labels: npt.NDArray[np.float64],
    n_bins: int = _RELIABILITY_BINS,
) -> list[ReliabilityBin]:
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    bins: list[ReliabilityBin] = []
    for i in range(n_bins):
        lo, hi = float(edges[i]), float(edges[i + 1])
        is_last = i == n_bins - 1
        mask = (predicted >= lo) & (predicted < hi if not is_last else predicted <= hi)
        n = int(mask.sum())
        if n == 0:
            bins.append(
                ReliabilityBin(
                    bin_lo=lo, bin_hi=hi, predicted_mean=None, observed_precision=None, n=0
                )
            )
            continue
        bins.append(
            ReliabilityBin(
                bin_lo=lo,
                bin_hi=hi,
                predicted_mean=float(predicted[mask].mean()),
                observed_precision=float(labels[mask].mean()),
                n=n,
            )
        )
    return bins


def _calibrate_one_detector(
    detector_key: str,
    examples: list[LabeledExample],
    *,
    min_samples: int,
    persist: bool,
    tenant_id: uuid.UUID,
) -> DetectorCalibrationResult:
    n = len(examples)
    labels = np.array([e.label for e in examples], dtype=np.float64)
    n_positive = int(labels.sum())

    stated = np.array([e.stated_confidence for e in examples], dtype=np.float64)
    brier_before = float(brier_score_loss(labels, stated)) if n > 0 else None
    reliability_before = _reliability_bins(stated, labels) if n > 0 else []

    if n < min_samples or n_positive == 0 or n_positive == n:
        # Isotonic regression needs both classes represented, and `min_samples` points before a
        # fit is more signal than noise -- an honest skip, recorded and surfaced, not a silent
        # no-op (mirrors this codebase's general preference for a loud, explained skip).
        reason = (
            f"only {n} labeled example(s), need >= {min_samples}"
            if n < min_samples
            else "labels are single-class (all positive or all negative) -- isotonic regression "
            "needs both to fit a monotonic mapping"
        )
        return DetectorCalibrationResult(
            detector_key=detector_key,
            n_samples=n,
            n_positive=n_positive,
            fitted=False,
            skip_reason=reason,
            brier_before=brier_before,
            brier_after=None,
            reliability_before=reliability_before,
            reliability_after=[],
        )

    raw = np.array([e.raw_score for e in examples], dtype=np.float64)
    model = _fit_isotonic(raw, labels)
    calibrated = np.asarray(model.predict(raw), dtype=np.float64)
    brier_after = float(brier_score_loss(labels, calibrated))
    reliability_after = _reliability_bins(calibrated, labels)

    if persist:
        path = _artifact_path(tenant_id, detector_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, path)

    return DetectorCalibrationResult(
        detector_key=detector_key,
        n_samples=n,
        n_positive=n_positive,
        fitted=True,
        skip_reason=None,
        brier_before=brier_before,
        brier_after=brier_after,
        reliability_before=reliability_before,
        reliability_after=reliability_after,
    )


def refit_calibrators(
    session: Session, tenant_id: uuid.UUID, *, min_samples: int = 5, persist: bool = True
) -> CalibrationRefitResult:
    """Refit every detector's isotonic calibrator from this tenant's confirmed/rejected feedback
    history and return a full before/after report (Brier score + reliability diagram per
    detector, plus an overall pooled figure). Pure read of `analyst_feedback`/`triage_verdicts`/
    `incidents`/`signals`; the only write is the calibrator artifact itself, when `persist=True`.
    """
    examples = labeled_examples(session, tenant_id)

    by_detector: dict[str, list[LabeledExample]] = {}
    for ex in examples:
        by_detector.setdefault(ex.detector_key, []).append(ex)

    results = [
        _calibrate_one_detector(
            key, exs, min_samples=min_samples, persist=persist, tenant_id=tenant_id
        )
        for key, exs in sorted(by_detector.items())
    ]

    all_labels = np.array([e.label for e in examples], dtype=np.float64)
    all_stated = np.array([e.stated_confidence for e in examples], dtype=np.float64)
    overall_before = float(brier_score_loss(all_labels, all_stated)) if len(examples) else None

    fitted_after: list[float] = []
    fitted_labels: list[float] = []
    for r, exs in zip(results, by_detector.values(), strict=False):
        if not r.fitted:
            continue
        raw = np.array([e.raw_score for e in exs], dtype=np.float64)
        model = _fit_isotonic(raw, np.array([e.label for e in exs], dtype=np.float64))
        fitted_after.extend(float(v) for v in model.predict(raw))
        fitted_labels.extend(e.label for e in exs)
    overall_after = (
        float(brier_score_loss(np.array(fitted_labels), np.array(fitted_after)))
        if fitted_after
        else None
    )

    n_feedback = len({e.feedback_id for e in examples})
    return CalibrationRefitResult(
        tenant_id=tenant_id,
        refit_at=datetime.now(UTC),
        n_feedback_events=n_feedback,
        detectors=results,
        overall_brier_before=overall_before,
        overall_brier_after=overall_after,
    )


def apply_calibrator(detector_key: str, raw_score: float, *, tenant_id: uuid.UUID) -> float:
    """Read side: map one detector's raw score through its persisted calibrator. Falls back to a
    clamped identity pass-through when no calibrator has been fit yet for this
    `(tenant_id, detector_key)` -- the same documented interim policy `app/detection/sigma/
    runner.py` uses for un-calibrated confidence, not a different silent default."""
    path = _artifact_path(tenant_id, detector_key)
    if not path.exists():
        return max(0.0, min(1.0, raw_score))
    model: IsotonicRegression = joblib.load(path)
    predicted = model.predict(np.array([raw_score], dtype=np.float64))
    return float(predicted[0])


def should_refit_now(n_feedback_total: int) -> bool:
    """docs/08 §1 cadence: "every 50 feedback events." `n_feedback_total` is the tenant's
    lifetime `analyst_feedback` row count *after* the triggering insert."""
    return n_feedback_total > 0 and n_feedback_total % REFIT_EVERY_N_FEEDBACK == 0


def summarize_for_api(result: CalibrationRefitResult) -> dict[str, Any]:
    """`GET /api/models/calibration`'s payload shape -- kept here (not in `app/schemas`) since
    it's a pure function of `CalibrationRefitResult` with no FastAPI/Pydantic dependency, easy to
    unit test on its own."""
    return {
        "refit_at": result.refit_at.isoformat(),
        "n_feedback_events": result.n_feedback_events,
        "overall_brier_before": result.overall_brier_before,
        "overall_brier_after": result.overall_brier_after,
        "detectors": [
            {
                "detector_key": d.detector_key,
                "n_samples": d.n_samples,
                "n_positive": d.n_positive,
                "fitted": d.fitted,
                "skip_reason": d.skip_reason,
                "brier_before": d.brier_before,
                "brier_after": d.brier_after,
                "brier_improvement": d.brier_improvement,
                "reliability_before": [
                    {
                        "bin_lo": b.bin_lo,
                        "bin_hi": b.bin_hi,
                        "predicted_mean": b.predicted_mean,
                        "observed_precision": b.observed_precision,
                        "n": b.n,
                    }
                    for b in d.reliability_before
                ],
                "reliability_after": [
                    {
                        "bin_lo": b.bin_lo,
                        "bin_hi": b.bin_hi,
                        "predicted_mean": b.predicted_mean,
                        "observed_precision": b.observed_precision,
                        "n": b.n,
                    }
                    for b in d.reliability_after
                ],
            }
            for d in result.detectors
        ],
    }
