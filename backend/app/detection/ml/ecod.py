"""`ml.ecod` — Empirical Cumulative Distribution-based Outlier Detection (docs/04 §L3 model
table, `pyod.models.ecod`).

## The hypothesis this model tests

"Per-feature tail probability suffices" — docs/04. ECOD estimates each feature's empirical CDF
(no kernel, no neighbor count, no covariance to fit, no contamination guess to tune) and
aggregates per-feature tail probability into one score. Parameter-free and deterministic: unlike
`ml.iforest` (seeded random partitioning) or `ml.autoencoder` (seeded weight init + SGD), the same
input matrix always produces the same ECOD score, because there is nothing stochastic in an
empirical-CDF estimate.

Whether this is *sufficient* — whether an attack that only shows up in the joint distribution,
never in any single marginal, defeats it — is exactly what scenario 4 (`docs/11`, low-and-slow
exfil) and pre-registered prediction #1 (`docs/12`) test. `evals/results.md` reports the measured
answer plainly, including if ECOD also detects it (which would mean the autoencoder has no
remaining justification on that scenario — docs/12 states this explicitly).

## Sign convention and calibration

pyod's own convention already matches this package's: `decision_function` returns higher-is-more-
anomalous scores, no sign flip needed (unlike `ml.iforest`, which negates sklearn's opposite
convention). `confidence` reuses the same percentile-rank-against-benign-calibration interim
policy every other model in this package uses (`IsolationForestArtifact`'s own docstring explains
why this is honestly a percentile, not yet an M10 isotonic-calibrated probability).

## `explain_row` — ECOD's own per-dimension breakdown, not a post-hoc attribution

Every other model in this package needs a separate attribution mechanism bolted on (SHAP for
`ml.iforest`, a quadratic-form decomposition for `ml.mahalanobis`, per-feature reconstruction
error for `ml.autoencoder`). ECOD does not: after `decision_function` runs, `self.O` (pyod's own
attribute name) already holds the per-dimension outlier score for every scored row, and
`self.O.sum(axis=1) == decision_scores_` by construction — the *native* decomposition docs/04
credits when it says ECOD's "output is already close to a probability rather than an unnormalized
[score]." `explain_row` reports that decomposition directly rather than approximating it.

## Why `decision_function` recomputes against `X_train` every call

pyod's ECOD is transductive by design for new data: `decision_function` on new rows concatenates
them with the stored training matrix and recomputes the empirical CDF over the union before
returning only the new rows' scores (`pyod.models.ecod.ECOD.decision_function`, verified directly
against the installed package). This is not a bug to work around — an empirical-CDF method's
"empirical" *is* the training population, so a genuinely new point's tail probability is only
well-defined relative to that population. Measured directly against this project's own corpus
scale (`~59k`-row train, `~23k`-row eval matrix, 53 features): a full-matrix call completes in
well under a second, so this is not a practical cost at the scale this benchmark runs at.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import numpy.typing as npt
from pyod.models.ecod import ECOD

from app.detection.ml.features import ENTITY_WINDOW_MODEL_FEATURES, sanitize_scores

__all__ = ["ECOD_ARTIFACT_FILENAME", "ECODArtifact"]

ECOD_ARTIFACT_FILENAME = "ecod.joblib"

_TOP_K_EXPLANATION = 10


@dataclass(slots=True)
class ECODArtifact:
    """A fitted `pyod.models.ecod.ECOD` plus the same benign calibration sample every other L3
    model in this package carries (`IsolationForestArtifact`'s docstring: the interim,
    pre-M10 percentile-rank substitute for isotonic calibration).
    """

    model: ECOD
    feature_names: tuple[str, ...]
    calibration_scores: npt.NDArray[np.float64]
    fit_seconds: float

    @classmethod
    def fit(
        cls,
        x_train: npt.NDArray[np.float64],
        x_calibration: npt.NDArray[np.float64],
        *,
        feature_names: tuple[str, ...] = ENTITY_WINDOW_MODEL_FEATURES,
    ) -> ECODArtifact:
        t0 = time.perf_counter()
        model = ECOD()
        model.fit(x_train)
        fit_seconds = time.perf_counter() - t0

        calib_scores = np.sort(_raw_scores(model, x_calibration))
        return cls(
            model=model,
            feature_names=feature_names,
            calibration_scores=calib_scores,
            fit_seconds=fit_seconds,
        )

    def raw_scores(self, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
        return _raw_scores(self.model, x)

    def confidence(self, raw_scores: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
        """Percentile rank of each score against `calibration_scores` — see class docstring."""
        n = len(self.calibration_scores)
        if n == 0:
            return np.zeros_like(raw_scores)
        ranks = np.searchsorted(self.calibration_scores, raw_scores, side="right")
        return np.clip(ranks / n, 0.0, 1.0)

    def explain_row(self, x_row: npt.NDArray[np.float64]) -> dict[str, Any]:
        """`{total_score, per_feature: [{feature, contribution}, ...]}` — `contribution` is
        ECOD's own per-dimension outlier score (`self.O`, module docstring), not a post-hoc
        approximation; `sum(per_feature contributions) == total_score` up to which rows survive
        the top-`_TOP_K_EXPLANATION` cap.
        """
        self.model.decision_function(x_row.reshape(1, -1))
        per_dim = self.model.O[-1]
        order = np.argsort(-per_dim)[:_TOP_K_EXPLANATION]
        per_feature = [
            {"feature": self.feature_names[i], "contribution": float(per_dim[i])} for i in order
        ]
        return {
            "total_score": float(per_dim.sum()),
            "per_feature": per_feature,
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "feature_names": self.feature_names,
                "calibration_scores": self.calibration_scores,
                "fit_seconds": self.fit_seconds,
            },
            path,
        )

    @classmethod
    def load(cls, path: Path) -> ECODArtifact:
        payload = joblib.load(path)
        return cls(
            model=payload["model"],
            feature_names=tuple(payload["feature_names"]),
            calibration_scores=payload["calibration_scores"],
            fit_seconds=payload["fit_seconds"],
        )


def _raw_scores(model: ECOD, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
    """Higher = more anomalous — pyod's own convention already matches this package's, no sign
    flip needed (module docstring). `sanitize_scores` is cheap defense-in-depth (matches
    `ml.mahalanobis`/`ml.iforest`); ECOD's `-log(ecdf)` terms are bounded by the training
    population size so this is not expected to fire in practice."""
    scores: npt.NDArray[np.float64] = sanitize_scores(model.decision_function(x))
    return scores
