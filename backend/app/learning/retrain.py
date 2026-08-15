"""Consumer 6 (gate half) — the retrain gate (docs/08 "Retrain gate", docs/12 "Regression gate").

```
train candidate -> run golden dataset -> compare to live model
  if precision, recall, citation_validity, or injection_resistance regress -> reject
  else -> write model_versions row, promote
```

The incumbent stays live on rejection. **Every** attempt is recorded, promoted or not — the
rejection history is the evidence the gate works (docs/08).

## `evaluate_candidate` is deliberately dependency-free

It takes two plain `dict[str, float]`s and a tolerance table; it does not know or care whether
the scores came from a real LightGBM fit, a recorded eval run, or a hand-built dict in a test.
That is what lets this milestone's acceptance bar — *"construct a deliberately worse candidate
model and show the rejection with the metric that tripped it"* — be demonstrated without needing
a working local `lightgbm` install (`app/learning/classifier.py`'s docstring explains why that
matters on at least one development machine) and without needing M10's full detection pipeline or
M11's agent to exist. `run_classifier_retrain` is the integration of this gate with a real
training run; `evaluate_candidate` is the part that "actually bites."

## Metric mapping — read before changing a tolerance

docs/12's regression-gate table is written for the *full-system* eval (`evals/run.py`, M16, not
built in this checkout): `detection_f1`, `incident_recall`, `disposition_accuracy`,
`hallucination_rate`, `injection_resistance`, `brier_score`. `app/learning/classifier.py`'s
LightGBM candidate reports `accuracy`/`macro_precision`/`macro_recall`/`macro_f1` — a classifier's
own metrics, not the full pipeline's. `CLASSIFIER_GATE_METRICS` maps the closest documented
tolerance to each (`accuracy` -> `disposition_accuracy`'s -0.05; the three macro-averaged
detection metrics -> `detection_f1`'s -0.02, docs/12's only aggregate-F1-shaped tolerance) rather
than inventing an unstated number. `DOCS12_TOLERANCES` is kept in full (including
`hallucination_rate`, `citation_validity`'s stand-in, and `injection_resistance`'s hard floor at
1.0) so a future caller gating an agent or full-pipeline retrain has the real table to reuse
instead of re-deriving it.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.classifier import (
    MIN_TRAINING_ROWS,
    TrainingRow,
    TrainResult,
    build_training_rows,
    train_and_evaluate,
)
from app.models.model_version import ModelVersion

__all__ = [
    "CLASSIFIER_GATE_METRICS",
    "CLASSIFIER_MODEL_KEY",
    "DOCS12_TOLERANCES",
    "LEARNING_MODELS_DIR",
    "GateResult",
    "MetricComparison",
    "MetricTolerance",
    "RetrainAttempt",
    "evaluate_candidate",
    "run_classifier_retrain",
]

CLASSIFIER_MODEL_KEY = "lightgbm"

# backend/app/learning/retrain.py -> learning -> app -> backend
_BACKEND_ROOT = Path(__file__).resolve().parents[2]
# One subdirectory per `model_key` (`.../learning/lightgbm/`, `.../learning/<test-key>/`, ...) --
# see `run_classifier_retrain`'s docstring for why `model_key` is a parameter, not always the
# `CLASSIFIER_MODEL_KEY` constant.
LEARNING_MODELS_DIR: Path = _BACKEND_ROOT / "data" / "models" / "learning"


@dataclass(frozen=True, slots=True)
class MetricTolerance:
    direction: Literal["higher_is_better", "lower_is_better"]
    max_regression: float  # magnitude of allowed drift in the unfavorable direction
    hard_floor: float | None = None  # e.g. injection_resistance must never drop below this


# docs/12 "Regression gate" table, transcribed verbatim.
DOCS12_TOLERANCES: dict[str, MetricTolerance] = {
    "detection_f1": MetricTolerance("higher_is_better", 0.02),
    "incident_recall": MetricTolerance("higher_is_better", 0.02),
    "disposition_accuracy": MetricTolerance("higher_is_better", 0.05),
    "hallucination_rate": MetricTolerance("lower_is_better", 0.01),
    "brier_score": MetricTolerance("lower_is_better", 0.02),
    "injection_resistance": MetricTolerance("higher_is_better", 0.0, hard_floor=1.0),
}

# See module docstring, "Metric mapping".
CLASSIFIER_GATE_METRICS: dict[str, MetricTolerance] = {
    "accuracy": DOCS12_TOLERANCES["disposition_accuracy"],
    "macro_precision": DOCS12_TOLERANCES["detection_f1"],
    "macro_recall": DOCS12_TOLERANCES["detection_f1"],
    "macro_f1": DOCS12_TOLERANCES["detection_f1"],
}


@dataclass(frozen=True, slots=True)
class MetricComparison:
    metric: str
    baseline: float
    candidate: float
    delta: float
    regressed: bool


@dataclass(frozen=True, slots=True)
class GateResult:
    passed: bool
    comparisons: list[MetricComparison] = field(default_factory=list)
    failed_metric: str | None = None
    reason: str = ""


def evaluate_candidate(
    candidate_scores: dict[str, float],
    baseline_scores: dict[str, float] | None,
    *,
    tolerances: dict[str, MetricTolerance] = CLASSIFIER_GATE_METRICS,
) -> GateResult:
    """The gate itself. `baseline_scores=None` means there is no incumbent to regress against
    (the very first model of its kind) — that case always passes, matching real promotion
    semantics: a first model has nothing to lose to. Otherwise every metric present in *both*
    dicts and named in `tolerances` is compared; the first regression found is reported as
    `failed_metric` (comparisons for every checked metric are still returned in full, not just
    the failing one, so a caller can show the whole picture, not only the trigger)."""
    if baseline_scores is None:
        return GateResult(
            passed=True, reason="no incumbent of this kind yet; promoting first model"
        )

    comparisons: list[MetricComparison] = []
    failed_metric: str | None = None
    for metric, tolerance in tolerances.items():
        if metric not in candidate_scores or metric not in baseline_scores:
            continue
        baseline_value = baseline_scores[metric]
        candidate_value = candidate_scores[metric]
        delta = candidate_value - baseline_value

        if tolerance.direction == "higher_is_better":
            regressed = delta < -tolerance.max_regression
            if tolerance.hard_floor is not None and candidate_value < tolerance.hard_floor:
                regressed = True
        else:
            regressed = delta > tolerance.max_regression

        comparisons.append(
            MetricComparison(
                metric=metric,
                baseline=baseline_value,
                candidate=candidate_value,
                delta=delta,
                regressed=regressed,
            )
        )
        if regressed and failed_metric is None:
            failed_metric = metric

    passed = failed_metric is None
    reason = "" if passed else f"{failed_metric} regressed beyond tolerance"
    return GateResult(
        passed=passed, comparisons=comparisons, failed_metric=failed_metric, reason=reason
    )


@dataclass(frozen=True, slots=True)
class RetrainAttempt:
    attempted_at: datetime
    skipped: bool
    skip_reason: str | None
    n_training_rows: int
    model_version_id: uuid.UUID | None
    version: int | None
    promoted: bool
    gate: GateResult | None
    eval_scores: dict[str, float] | None
    baseline_version: int | None


def _latest_promoted(session: Session, model_key: str) -> ModelVersion | None:
    """`model_versions` is not tenant-scoped (docs/02, matched exactly — see
    `app.models.model_version`'s docstring: models are versioned globally). The "live model" the
    gate compares against is the highest-versioned *promoted* row for this `model_key`."""
    return session.execute(
        select(ModelVersion)
        .where(ModelVersion.model_key == model_key, ModelVersion.promoted.is_(True))
        .order_by(ModelVersion.version.desc())
        .limit(1)
    ).scalar_one_or_none()


def _next_version(session: Session, model_key: str) -> int:
    latest = session.execute(
        select(ModelVersion)
        .where(ModelVersion.model_key == model_key)
        .order_by(ModelVersion.version.desc())
        .limit(1)
    ).scalar_one_or_none()
    return (latest.version + 1) if latest is not None else 1


def run_classifier_retrain(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    train_fn: Callable[[list[TrainingRow]], TrainResult] = train_and_evaluate,
    min_rows: int = MIN_TRAINING_ROWS,
    persist: bool = True,
    model_key: str = CLASSIFIER_MODEL_KEY,
) -> RetrainAttempt:
    """docs/08 §6 + "Retrain gate", end to end: build the training set from feedback, train a
    candidate, compare it to the current live model via `evaluate_candidate`, and write a
    `model_versions` row for the attempt regardless of outcome (`persist=True`, the default) —
    "record every attempt, promoted or not."

    `train_fn` defaults to `app.learning.classifier.train_and_evaluate` (real LightGBM); tests
    inject a lightweight stand-in so the gate is exercised without depending on a working local
    `lightgbm` install (see that module's docstring).

    `model_key` defaults to `CLASSIFIER_MODEL_KEY` ("lightgbm") -- the only key production code
    ever passes. It exists as a parameter (not a hardcoded reference) because `model_versions` is
    not tenant-scoped (docs/02: models are versioned globally, see `app.models.model_version`'s
    docstring) — every tenant's classifier shares one global `(model_key, version)` sequence by
    design, which means `tests/test_learning_retrain.py`'s own retrain attempts would otherwise
    collide with `app/scripts/seed_feedback.py`'s real seeded version history under the same key.
    Tests pass a run-unique key; nothing else should.
    """
    rows = build_training_rows(session, tenant_id)

    def _skip(reason: str) -> RetrainAttempt:
        return RetrainAttempt(
            attempted_at=datetime.now(UTC),
            skipped=True,
            skip_reason=reason,
            n_training_rows=len(rows),
            model_version_id=None,
            version=None,
            promoted=False,
            gate=None,
            eval_scores=None,
            baseline_version=None,
        )

    if len(rows) < min_rows:
        return _skip(f"only {len(rows)} labeled row(s), need >= {min_rows}")

    # A multiclass objective needs at least two classes to be defined at all; LightGBM raises
    # "Number of classes should be specified and greater than 1" rather than training a degenerate
    # model. This is the ordinary early state of a real tenant, not an error — an analyst who has
    # agreed with every verdict so far has produced a perfectly valid, entirely single-class
    # feedback history. Report it the same way as "not enough rows" so the learning page can say
    # *why* nothing retrained, instead of the feedback endpoint returning a 500.
    distinct_labels = {row.label for row in rows}
    if len(distinct_labels) < 2:
        only = next(iter(distinct_labels))
        return _skip(
            f"all {len(rows)} labeled row(s) share one label ({only!r}); "
            f"multiclass training needs >= 2 distinct labels"
        )

    result = train_fn(rows)
    baseline = _latest_promoted(session, model_key)
    gate = evaluate_candidate(
        result.eval_scores, baseline.eval_scores if baseline is not None else None
    )

    version_id: uuid.UUID | None = None
    version_number: int | None = None
    if persist:
        version_number = _next_version(session, model_key)
        artifact_path = LEARNING_MODELS_DIR / model_key / f"v{version_number}.txt"
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_bytes(result.model_bytes)

        row = ModelVersion(
            model_key=model_key,
            version=version_number,
            artifact_ref=str(artifact_path.relative_to(_BACKEND_ROOT)),
            trained_at=datetime.now(UTC),
            eval_scores={
                **result.eval_scores,
                "label_classes": list(result.label_classes),
                "n_train": result.n_train,
                "n_held_out": result.n_held_out,
                "gate": {
                    "passed": gate.passed,
                    "failed_metric": gate.failed_metric,
                    "reason": gate.reason,
                    "comparisons": [
                        {
                            "metric": c.metric,
                            "baseline": c.baseline,
                            "candidate": c.candidate,
                            "delta": c.delta,
                            "regressed": c.regressed,
                        }
                        for c in gate.comparisons
                    ],
                },
                "baseline_version": baseline.version if baseline is not None else None,
            },
            promoted=gate.passed,
        )
        session.add(row)
        # Flush only -- commit is the caller's responsibility, same convention as
        # `app.learning.weights.retune_detector_weights`; see that function's comment.
        session.flush()
        version_id = row.id

    return RetrainAttempt(
        attempted_at=datetime.now(UTC),
        skipped=False,
        skip_reason=None,
        n_training_rows=len(rows),
        model_version_id=version_id,
        version=version_number,
        promoted=gate.passed,
        gate=gate,
        eval_scores=result.eval_scores,
        baseline_version=baseline.version if baseline is not None else None,
    )
