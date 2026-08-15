"""`ml.iforest` — Isolation Forest baseline (docs/04 §L3 model table).

`n_estimators=200`, `contamination='auto'`, seeded — exactly the config docs/04 specifies. This
is the benchmark's *baseline*, deliberately: axis-aligned random partitioning finds points that
are extreme on some combination of individual feature thresholds cheaply, which is a strong,
fast detector for the marginal/threshold-shaped attacks (volumetric bursts, huge transfers) but
structurally weaker than a true joint-covariance model at the correlation-only anomalies scenario
8 (docs/11) is built to test — see `evals/results.md` for whether that theoretical weakness
actually shows up on real numbers.

## Sign convention

Every model in this package reports `raw_score` on the same axis: **higher means more
anomalous.** `sklearn.IsolationForest.score_samples` uses the opposite convention (higher means
more normal, since it is proportional to average isolation path length), so `raw_scores` negates
it. SHAP's `TreeExplainer` attributes *that same signed internal score*
(`base_value + sum(shap_values) == score_samples`, verified against a synthetic outlier/inlier
pair while building this module), so a per-feature SHAP value is negated too before it is
reported — the sign flip means a *positive* reported contribution is "this feature's value pushed
the row toward being flagged," which is what an analyst reading `explanation.per_feature` expects,
rather than raw SHAP's "pushed the model's internal normality score down."
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import numpy.typing as npt
import shap
from sklearn.ensemble import IsolationForest

from app.detection.ml.features import ENTITY_WINDOW_MODEL_FEATURES, sanitize_scores

__all__ = ["IFOREST_ARTIFACT_FILENAME", "IsolationForestArtifact"]

IFOREST_ARTIFACT_FILENAME = "iforest.joblib"

N_ESTIMATORS = 200
CONTAMINATION = "auto"
RANDOM_STATE = 42
_TOP_K_EXPLANATION = 10


@dataclass(slots=True)
class IsolationForestArtifact:
    """A fitted Isolation Forest plus everything `detect.py` needs to score and explain a row
    without recomputing anything sklearn/SHAP-specific.

    `calibration_scores` is a sorted (ascending) sample of `raw_scores` on held-out benign data —
    the interim, pre-M10 substitute for isotonic calibration (docs/04 "Fusion & calibration" is
    M10, not built yet; `app.detection.signal.drafts` states the same interim-confidence policy
    for L2). `confidence(x)` is `x`'s percentile rank in that sample: "this row's anomaly score is
    higher than N% of ordinary benign entity-windows," which is honestly a percentile, not yet a
    calibrated probability, and is documented as exactly that everywhere it is used.
    """

    model: IsolationForest
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
        random_state: int = RANDOM_STATE,
    ) -> IsolationForestArtifact:
        t0 = time.perf_counter()
        model = IsolationForest(
            n_estimators=N_ESTIMATORS,
            contamination=CONTAMINATION,
            random_state=random_state,
            n_jobs=-1,
        )
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
        """`{total_score, per_feature: [{feature, contribution}, ...]}`, `per_feature` sorted by
        `|contribution|` descending, capped to the top `_TOP_K_EXPLANATION` — SHAP attribution
        for one row (docs/04: "SHAP for attribution"). See module docstring for the sign
        convention: positive `contribution` pushed this row toward being flagged.
        """
        explainer = shap.TreeExplainer(self.model)
        shap_values = -np.asarray(explainer.shap_values(x_row.reshape(1, -1)))[0]
        order = np.argsort(-np.abs(shap_values))[:_TOP_K_EXPLANATION]
        per_feature = [
            {"feature": self.feature_names[i], "contribution": float(shap_values[i])} for i in order
        ]
        return {
            "total_score": float(_raw_scores(self.model, x_row.reshape(1, -1))[0]),
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
    def load(cls, path: Path) -> IsolationForestArtifact:
        payload = joblib.load(path)
        return cls(
            model=payload["model"],
            feature_names=tuple(payload["feature_names"]),
            calibration_scores=payload["calibration_scores"],
            fit_seconds=payload["fit_seconds"],
        )


def _raw_scores(model: IsolationForest, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
    """Higher = more anomalous — see module docstring for the sign flip vs. sklearn's own
    `score_samples`. `sanitize_scores` is cheap defense-in-depth (matches `ml.mahalanobis`);
    isolation depth itself is bounded, so this is not expected to ever fire in practice."""
    scores: npt.NDArray[np.float64] = sanitize_scores(-model.score_samples(x))
    return scores
