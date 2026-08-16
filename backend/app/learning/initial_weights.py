"""Initial (pre-feedback) `detector_stats.fusion_weight` for the shipped ML detectors — docs/12
change 4 ("Audit and set initial fusion weights"), and a companion to consumer 2
(`app.learning.weights`, docs/08 Part 2 §2), not a seventh mechanism.

## The gap this closes

`app.pipeline.stages.correlate._fusion_weight` (and `app.graph.pipeline_demo`'s own read-only
copy, out of this package's ownership) resolve a detector's fusion weight from `detector_stats`,
falling back to a bare `1.0` whenever no row exists yet — which is every detector, for every
tenant, until an analyst has confirmed or dismissed enough alerts for mechanism 2
(`app.learning.weights.retune_detector_weights`) to run at least once. A uniform 1.0 fuses EIF
(measured pooled precision ≈0.2 on this corpus) and LOF (≈0.003, roughly 320 false alarms per true
detection) with identical authority in `fuse_signals` — LOF's volume dominates the fused score
before a single analyst click has happened.

## The fix, and why it is "the same clamp mechanism 2 uses"

`derive_initial_weights` is `clamp(precision_d / prior_precision, MIN_FUSION_WEIGHT,
MAX_FUSION_WEIGHT)` — `app.learning.weights.clamp_fusion_weight`/`pooled_precision`, imported
rather than re-implemented, so a detector's seeded weight and its later analyst-feedback-learned
weight (mechanism 2) live on the exact same scale: mechanism 2's next real retune, whenever it
first runs, moves the weight *from* this benchmark-informed prior, not from an artificial 1.0.
The only substitution is the counts `precision_d`/`prior_precision` are measured from: benchmark
TP/FP (`app.detection.ml.evaluate.evaluate()`'s pooled confusion matrix, docs/12 change 2) instead
of analyst-confirmed/rejected feedback — there is no feedback yet, by construction, for a weight
this function is ever asked to seed.

## Why this is a file, not a synchronous benchmark call

Fusion weight is read on the hot path of the `correlate` pipeline stage, once per contributing
signal. Re-running the ~8-scenario, tens-of-thousands-of-events L3 benchmark on every incident is
not viable, and importing `evals`/`datagen` from `app/**` is a dependency direction this codebase
never takes (`app.detection.ml` "never imports datagen" — every sibling module docstring in this
package restates the same rule). `evals/run.py` (`make eval`, which already runs the real L3
benchmark against production `app.detection.ml.artifacts.MODELS_DIR`) calls
`compute_shipped_initial_weights` and `save_initial_fusion_weights` once per run and writes the
result next to every other regenerable ML artifact under `MODELS_DIR` — this module owns the pure
math and the load path only, never the benchmark run itself, so `app/learning` still never
imports `evals`.

`load_initial_fusion_weights` never raises: a missing or unreadable artifact (a fresh checkout
that has not run `make eval` yet) is logged and treated as "no informed prior available yet," and
callers fall back to the pre-existing neutral 1.0 themselves for any key this returns nothing for
— fusion weight is a tuning input, not a correctness-critical artifact the way a missing scaler or
model file is (`app.detection.ml`'s own "fail loudly" policy is deliberately not mirrored here).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.logging import get_logger
from app.detection.ml.artifacts import MODELS_DIR
from app.detection.ml.detect import SHIPPED_MODEL_FIELDS
from app.learning.weights import clamp_fusion_weight, pooled_precision

log = get_logger(__name__)

__all__ = [
    "INITIAL_FUSION_WEIGHTS_FILENAME",
    "compute_shipped_initial_weights",
    "derive_initial_weights",
    "load_initial_fusion_weights",
    "save_initial_fusion_weights",
]

INITIAL_FUSION_WEIGHTS_FILENAME = "initial_fusion_weights.json"


def derive_initial_weights(counts_by_detector: dict[str, tuple[int, int]]) -> dict[str, float]:
    """`{detector_key: clamp(precision_d / prior_precision, MIN_FUSION_WEIGHT,
    MAX_FUSION_WEIGHT)}`. `counts_by_detector` values are `(true_positives, false_positives)` —
    measured however the caller likes (here, always the L3 benchmark's pooled counts); this
    function itself is agnostic to the source, which is what makes it directly unit-testable
    against hand-built counts rather than a live benchmark run. `prior_precision` is the pooled
    precision across every detector passed in (`app.learning.weights.pooled_precision` — the
    *identical* formula `retune_detector_weights` uses for its own prior), so a detector performing
    exactly at the pooled average would seed at 1.0, same as mechanism 2's own convention. A
    detector with no measured positives or false positives at all (never fired — `tp + fp == 0`)
    is left at the neutral 1.0: no evidence yet to move it either way, the same edge case
    `retune_detector_weights` falls back to when `precision is None`."""
    prior = pooled_precision(counts_by_detector.values())
    weights: dict[str, float] = {}
    for key, (tp, fp) in counts_by_detector.items():
        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        if precision is None or prior is None or prior == 0:
            weights[key] = 1.0
        else:
            weights[key] = clamp_fusion_weight(precision / prior)
    return weights


def compute_shipped_initial_weights(pooled_metrics: dict[str, dict[str, Any]]) -> dict[str, float]:
    """`pooled_metrics`: `app.detection.ml.evaluate.evaluate()`'s `"pooled"` key (docs/12 change
    2 — all six benchmarked models' pooled TP/FP/FN). Narrowed here to
    `app.detection.ml.detect.SHIPPED_MODEL_FIELDS` (EIF / kth-NN / LOF) — the only detector_keys
    `_fusion_weight`'s `detector_stats` lookup is ever resolved against, since only shipped models
    ever write a live `Signal` row (migration change 19). The three benchmark-only baselines
    (iForest, Mahalanobis, ECOD) are deliberately excluded from both the weight computation and its
    `prior_precision` — seeding a weight for a detector that can never appear in `fuse_signals`
    would be inert, and folding their (very different) precision profiles into the pooled prior
    would distort the prior the three shipped models actually need."""
    counts = {
        key: (int(pooled_metrics[key]["tp"]), int(pooled_metrics[key]["fp"]))
        for key in SHIPPED_MODEL_FIELDS
        if key in pooled_metrics
    }
    return derive_initial_weights(counts)


def _artifact_path(models_dir: Path) -> Path:
    return models_dir / INITIAL_FUSION_WEIGHTS_FILENAME


def save_initial_fusion_weights(
    weights: dict[str, float], *, source: dict[str, Any], models_dir: Path = MODELS_DIR
) -> Path:
    """Write the derived weights, plus their provenance (`source` — e.g. the pooled TP/FP counts,
    prior precision, and eval seed they were computed from), to `models_dir` for
    `load_initial_fusion_weights` to read at fusion time. Called by `evals/run.py` (`make eval`)
    after every benchmark run — never by live request-serving code, which only ever reads."""
    path = _artifact_path(models_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"weights": weights, "source": source}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    log.info("initial_weights.saved", path=str(path), weights=weights)
    return path


def load_initial_fusion_weights(models_dir: Path = MODELS_DIR) -> dict[str, float]:
    """`{detector_key: fusion_weight}` for the shipped models, or `{}` if `make eval` has never
    been run against this `models_dir` yet. Callers must fall back to the neutral 1.0 themselves
    for any key not present here — exactly the same shape of fallback they already apply for a
    detector with no `detector_stats` row at all. Never raises; see module docstring."""
    path = _artifact_path(models_dir)
    if not path.exists():
        log.warning("initial_weights.artifact_missing", path=str(path))
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        weights = payload["weights"]
        return {str(k): float(v) for k, v in weights.items()}
    except Exception:
        log.warning("initial_weights.artifact_unreadable", path=str(path), exc_info=True)
        return {}
