"""The three pre-registered predictions (docs/12), evaluated against measured results and
reported CONFIRMED or FALSIFIED by the stated rule alone — never reframed after seeing the
numbers.

Predictions 1 and 2, and the L3 half of prediction 3, are already computed by
`app.detection.ml.evaluate.evaluate()` (that module's own `_pre_registered_predictions`, called
here against the SAME golden scenario files this harness uses everywhere else — see
`run_l3_benchmark`'s docstring for why that reuse is safe). Prediction 3's other half — whether
`signal.stl_residual` itself detects scenario 6 — is this harness's own job (docs/12: "L2's own
half ... is measured by a separate L2 harness this module does not own the input rows for");
`evals/metrics/detection.py`'s per-scenario detector rows already have that answer.
"""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.detection.ml import evaluate as ml_evaluate
from evals.config import EVAL_SEED, GOLDEN_DIR, SEASONAL_SCENARIO
from evals.metrics.detection import DetectorScenarioRow

log = get_logger(__name__)

_STL_DETECTOR_KEY = "signal.stl_residual"


def run_l3_benchmark() -> dict[str, Any]:
    """The docs/12 "L3 unsupervised" headline table (F1, AUC-PR, per-scenario recall for all five
    models) — `app.detection.ml.evaluate.evaluate()`, called against this harness's own frozen
    `evals/golden/<key>/` files rather than letting it generate a fresh, separate 50k-event/
    scenario set: `evaluate.py`'s own scenario loader (`_generate_eval_scenarios`) skips
    generation whenever a `.labels.json` already exists at `eval_dir/<key>/` — exactly this
    harness's own golden-set layout — so this call scores the *same* frozen bytes as everything
    else in `results.md`, at zero extra generation cost, instead of a second, differently-scaled
    L3-only dataset that would makes the two halves of the report harder to reconcile."""
    return ml_evaluate.evaluate(eval_seed=EVAL_SEED, eval_dir=GOLDEN_DIR)


def build_report(
    l3_result: dict[str, Any], detection_rows: list[DetectorScenarioRow]
) -> dict[str, Any]:
    predictions = {k: dict(v) for k, v in l3_result["pre_registered_predictions"].items()}

    stl_rows = [
        r
        for r in detection_rows
        if r.scenario == SEASONAL_SCENARIO and r.detector_key == _STL_DETECTOR_KEY
    ]
    stl_detected = bool(stl_rows and stl_rows[0].detected)
    entry = predictions.get("3_seasonal_stl_not_l3", {})
    l3_falsifies = bool(entry.get("l3_falsifies_prediction"))
    prediction_3_confirmed = stl_detected and not l3_falsifies
    entry["stl_detected"] = stl_detected
    entry["outcome"] = "CONFIRMED" if prediction_3_confirmed else "FALSIFIED"
    if not stl_detected:
        entry["note"] = (
            (entry.get("note") or "")
            + " signal.stl_residual did not detect scenario 6 in this run — the STL half of the "
            "prediction did not hold, independent of what the five L3 models did."
        ).strip()
    predictions["3_seasonal_stl_not_l3"] = entry

    return predictions
