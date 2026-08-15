"""`ml.mahalanobis` — robust covariance / Minimum Covariance Determinant (docs/04 §L3 model
table: "Mahalanobis / RPCA — robust covariance (MCD) — Linear correlation structure; what
commercial UEBA ships").

MCD (not a plain sample covariance) for the same reason `datagen/scenarios/s08_low_and_slow_
exfil.py`'s own acceptance gate uses one (that module's docstring: "the same reason docs/04
specifies a *robust* covariance ... rather than a plain sample covariance"): a handful of
genuinely wild benign hours (a large legitimate download, a real off-hours incident-response
session) would otherwise inflate the sample covariance's scale on those dimensions and mask a
correlation-only anomaly that lives at ordinary marginal magnitude.

This is the model whose entire premise is scoring the *joint* distribution — the correlation
structure between features, not any one feature's own extremity — which is exactly the property
scenario 8 (docs/11) is built to require. `ml.iforest` partitions on individual feature
thresholds; `ml.mahalanobis` scores a point by how far it sits from the benign population in the
metric defined by that population's own (robust) covariance, which is a linear model of exactly
that joint structure.
"""

from __future__ import annotations

import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import numpy.typing as npt
from sklearn.covariance import MinCovDet

from app.detection.ml.features import ENTITY_WINDOW_MODEL_FEATURES, sanitize_scores

__all__ = ["MAHALANOBIS_ARTIFACT_FILENAME", "MahalanobisArtifact"]

MAHALANOBIS_ARTIFACT_FILENAME = "mahalanobis.joblib"

# Assume no more than 25% contamination resistance needed (the benign training corpus is
# uncontaminated by construction -- docs/11 -- so this only guards against the corpus's own
# natural heavy-tailed hours, not injected attacks). Also keeps FastMCD's sub-sampling search
# numerically stable at 50 dimensions and fast at tens of thousands of rows (verified directly:
# the low default support fraction produced frequent singular-subset warnings and ran markedly
# slower during this module's own development).
SUPPORT_FRACTION = 0.75
RANDOM_STATE = 42
# FastMCD's own row cap for tractability at this feature count; a training matrix larger than
# this is subsampled (seeded) before fitting -- see `fit`'s docstring.
_MAX_FIT_ROWS = 50_000
_TOP_K_EXPLANATION = 10


@dataclass(slots=True)
class MahalanobisArtifact:
    """A fitted `MinCovDet` plus a benign calibration sample for the same interim percentile
    confidence `IsolationForestArtifact` uses (see that class's docstring) — kept structurally
    identical across all three L3 models so `detect.py` and the eval harness treat them
    uniformly.
    """

    model: MinCovDet
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
    ) -> MahalanobisArtifact:
        """Subsamples `x_train` to `_MAX_FIT_ROWS` (seeded, so reproducible) before fitting —
        FastMCD's sub-sampling search cost grows with row count, and the benign corpus's own
        distribution is already well represented by tens of thousands of rows without needing
        every one."""
        rng = np.random.default_rng(random_state)
        fit_rows = x_train
        if x_train.shape[0] > _MAX_FIT_ROWS:
            idx = rng.choice(x_train.shape[0], size=_MAX_FIT_ROWS, replace=False)
            fit_rows = x_train[idx]

        t0 = time.perf_counter()
        with warnings.catch_warnings():
            # FastMCD's C-step can hit near-singular sub-samples while searching -- expected,
            # not a fit failure; the search moves on and converges. Suppressed here rather than
            # silently ignored everywhere: this is the one place in the codebase that calls MCD.
            warnings.filterwarnings("ignore", category=RuntimeWarning)
            model = MinCovDet(random_state=random_state, support_fraction=SUPPORT_FRACTION)
            model.fit(fit_rows)
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
        n = len(self.calibration_scores)
        if n == 0:
            return np.zeros_like(raw_scores)
        ranks = np.searchsorted(self.calibration_scores, raw_scores, side="right")
        return np.clip(ranks / n, 0.0, 1.0)

    def explain_row(self, x_row: npt.NDArray[np.float64]) -> dict[str, Any]:
        """`{total_score, per_feature: [{feature, contribution}, ...]}`.

        `distance^2 = z^T P z` (`P` the fitted precision/inverse-covariance matrix, `z` the
        row's deviation from the robust location) expands exactly into
        `sum_i z_i * (P @ z)_i` — each term is that feature's own additive share of the total
        squared distance, so `per_feature` contributions sum to `total_score` (up to floating
        point) rather than being a post-hoc approximation. A negative term means that feature's
        deviation, combined with the others via their fitted correlation, pulled the point
        *back toward* the benign population on net; still reported (sorted by magnitude, not
        clipped at zero) since a large negative term is itself informative about which
        correlations this row broke.
        """
        z = x_row - self.model.location_
        contributions = z * (self.model.precision_ @ z)
        order = np.argsort(-np.abs(contributions))[:_TOP_K_EXPLANATION]
        per_feature = [
            {"feature": self.feature_names[i], "contribution": float(contributions[i])}
            for i in order
        ]
        return {
            "total_score": float(contributions.sum()),
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
    def load(cls, path: Path) -> MahalanobisArtifact:
        payload = joblib.load(path)
        return cls(
            model=payload["model"],
            feature_names=tuple(payload["feature_names"]),
            calibration_scores=payload["calibration_scores"],
            fit_seconds=payload["fit_seconds"],
        )


def _raw_scores(model: MinCovDet, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
    """Squared robust Mahalanobis distance — already "higher means more anomalous" (docs/04's
    own convention for this family of model), no sign flip needed unlike `ml.iforest`.

    `sanitize_scores` guards against float64 overflow in the `z^T P z` quadratic form for a
    genuinely extreme row (50 correlated, wide-dynamic-range features can produce a poorly
    conditioned precision matrix) — see that function's docstring in `features.py`.
    """
    scores: npt.NDArray[np.float64] = sanitize_scores(model.mahalanobis(x))
    return scores
