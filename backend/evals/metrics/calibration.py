"""Calibration metrics (docs/12): a 10-bin reliability diagram (predicted vs. observed precision)
and Brier score. "A confidence score that is not calibrated is a number, not a probability."

Pools every `(calibrated confidence, label)` sample this harness produced — one per raw signal
(rule/signal/ml/graph, all four layers together) across all eight golden scenarios plus the
pure-benign corpus — and hands them to `app.detection.calibration.reliability_diagram`, the same
function `app.graph.pipeline_demo`'s own M10 verification (`full-report`) uses, so this harness's
numbers are computed the identical way, not a second independent implementation of the same math.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING, Any

import numpy as np

from app.detection.calibration import reliability_diagram

if TYPE_CHECKING:
    from evals.pipeline import BenignPureRun, ScenarioRun  # see detection.py's identical note


def build_report(runs: dict[str, ScenarioRun], benign_pure: BenignPureRun) -> dict[str, Any]:
    samples: list[tuple[float, int]] = []
    for run in runs.values():
        samples.extend(run.result.reliability_samples)
    samples.extend(benign_pure.reliability_samples)

    if not samples:
        return {"brier_score": None, "n_samples": 0, "n_positive": 0, "bins": []}

    confidences = np.array([c for c, _ in samples], dtype=np.float64)
    labels = np.array([lbl for _, lbl in samples], dtype=np.int64)
    report = reliability_diagram(confidences, labels, n_bins=10)
    return {
        "brier_score": report.brier_score,
        "n_samples": len(samples),
        "n_positive": int(labels.sum()),
        "bins": [asdict(b) for b in report.bins],
    }
