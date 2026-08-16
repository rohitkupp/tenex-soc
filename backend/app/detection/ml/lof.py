"""`ml.peer_group` — Local Outlier Factor (docs/04 §L3 model table, `pyod.models.lof`, which
wraps `sklearn.neighbors.LocalOutlierFactor(novelty=True)`).

## Why the detector key is `ml.peer_group`, not `ml.lof`

docs/04 §L3 "Peer-group cohorts": "LOF is, in effect, a formalization of the `ml.peer_group`
model this design gestured at but never built ... it is now a first-class model in the table
below rather than a forward reference." `datagen.types.ML_PEER_GROUP = "ml.peer_group"` is the
literal string `datagen/scenarios/s03_insider_mass_download.py` and
`s05_peer_group_deviation.py` already put in `expected_detectors` — the eval harness matches
`signals.detector_key` by string equality, so this model ships under that name, and `detect.py`
declares the constant independently (matching every other `ML_*`/`SIGNAL_*` constant in this
package — see that module's own docstring on why).

## The hypothesis this model tests

"Peer-relative anomalies exist that global methods miss" — docs/04. Every other L3 model
(`ml.iforest`, `ml.mahalanobis`, `ml.ecod`, `ml.autoencoder`) scores a row against one
population-wide notion of "normal." LOF instead scores a row against the density of its own
k-nearest neighbors *in the full feature space* — department unlabeled, an *emergent* local
neighborhood rather than the department-cohort features' *explicit* one (docs/04's own
distinction, restated in `features.py`'s module docstring). A window can sit comfortably inside
the org-wide distribution and still be locally anomalous relative to its neighbors — scenario 5
(`docs/11`, peer-group deviation) is built specifically so a global model cannot separate it
(criterion (b) of that scenario's own acceptance gate) while the department-cohort-relative
features (which LOF's input vector already carries — `n_events_z_vs_cohort`,
`bytes_out_sum_z_vs_cohort`, `rare_domain_ratio_z_vs_cohort`, `features.py`) give LOF's local
neighborhoods a real, informative dimension to separate on: those features read near-zero for a
genuine member of a department (ordinary relative to their own cohort) and sharply nonzero for a
victim whose behavior no longer matches their own department's cohort, whatever department's
*content* it now resembles.

## Sign convention and calibration

pyod's `LOF.decision_function` already inverts `sklearn`'s own `negative_outlier_factor_`
internally (pyod's `invert_order`), so — like `ml.ecod` and unlike `ml.iforest` — no further sign
flip is needed here: higher already means more anomalous. `confidence` reuses the same
percentile-rank-against-benign-calibration interim policy as every other model in this package.

## `explain_row` — neighbor-relative deviation, not a global attribution

LOF's premise is inherently local, so a global SHAP/quadratic-form attribution would misrepresent
*why* a row is locally dense or sparse. Instead: find this row's `n_neighbors` nearest points in
the fitted training population (`sklearn.neighbors.LocalOutlierFactor.kneighbors`, available
because pyod fits it with `novelty=True`) and report, per feature, how far this row sits from the
*mean of those specific neighbors* — the same "deviation from the population this row is actually
being compared against" idea `ml.mahalanobis`'s quadratic decomposition uses, just with the
population narrowed to this row's own local neighborhood instead of the whole training set.

## Full-space vs. PCA (migration change 25's test plan; see `dimensionality.py`)

LOF is this package's other *distance*-based model (alongside `ml.kth_nn`) — both are density/
distance measures over the fitted feature space, so both get the same recorded-choice PCA path
(`space`, `dimensionality.fit_pca_reduction`). `explain_row` reports the neighbor-mean deviation in
original feature units regardless of which space chose the neighbors, for the same reason
`knn.py`'s own `explain_row` does: an analyst needs raw-feature deviation, not a PCA loading.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import numpy.typing as npt
from pyod.models.lof import LOF

from app.detection.ml.dimensionality import FeatureSpace, PCAReduction, fit_pca_reduction
from app.detection.ml.features import ENTITY_WINDOW_MODEL_FEATURES, sanitize_scores

__all__ = ["LOF_ARTIFACT_FILENAME", "LOF_PCA_ARTIFACT_FILENAME", "LOFArtifact"]

LOF_ARTIFACT_FILENAME = "lof.joblib"
LOF_PCA_ARTIFACT_FILENAME = "lof_pca.joblib"

# pyod/sklearn default -- docs/04 does not specify a neighbor count for LOF, and 20 is the
# standard default from the original LOF paper's own worked examples, not tuned against this
# corpus (CLAUDE.md: thresholds/hyperparameters are load-bearing choices, stated plainly, not
# tuned after seeing a result).
N_NEIGHBORS = 20
_TOP_K_EXPLANATION = 10


@dataclass(slots=True)
class LOFArtifact:
    """A fitted `pyod.models.lof.LOF` (`novelty=True` under the hood) plus the same benign
    calibration sample every other L3 model in this package carries, plus the recorded full-space/
    PCA choice — module docstring "Full-space vs. PCA".
    """

    model: LOF
    feature_names: tuple[str, ...]
    calibration_scores: npt.NDArray[np.float64]
    fit_seconds: float
    space: FeatureSpace = "full"
    pca: PCAReduction | None = None
    # Only populated when `space == "pca"` — `explain_row` needs the original feature values to
    # report an interpretable neighbor-mean deviation even when neighbors were chosen in PCA
    # space (same reasoning as `knn.py`'s `KNNArtifact.train_x_full`).
    train_x_full: npt.NDArray[np.float64] | None = None

    @classmethod
    def fit(
        cls,
        x_train: npt.NDArray[np.float64],
        x_calibration: npt.NDArray[np.float64],
        *,
        feature_names: tuple[str, ...] = ENTITY_WINDOW_MODEL_FEATURES,
        n_neighbors: int = N_NEIGHBORS,
        space: FeatureSpace = "full",
        random_state: int = 42,
    ) -> LOFArtifact:
        t0 = time.perf_counter()
        pca_reduction: PCAReduction | None = None
        fit_x = x_train
        train_x_full: npt.NDArray[np.float64] | None = None
        if space == "pca":
            pca_reduction = fit_pca_reduction(x_train, random_state=random_state)
            fit_x = pca_reduction.transform(x_train)
            train_x_full = x_train

        model = LOF(n_neighbors=n_neighbors, novelty=True)
        model.fit(fit_x)
        fit_seconds = time.perf_counter() - t0

        calib_input = pca_reduction.transform(x_calibration) if pca_reduction else x_calibration
        calib_scores = np.sort(_raw_scores(model, calib_input))
        return cls(
            model=model,
            feature_names=feature_names,
            calibration_scores=calib_scores,
            fit_seconds=fit_seconds,
            space=space,
            pca=pca_reduction,
            train_x_full=train_x_full,
        )

    def _project(self, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
        return self.pca.transform(x) if self.pca is not None else x

    def raw_scores(self, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
        return _raw_scores(self.model, self._project(x))

    def confidence(self, raw_scores: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
        n = len(self.calibration_scores)
        if n == 0:
            return np.zeros_like(raw_scores)
        ranks = np.searchsorted(self.calibration_scores, raw_scores, side="right")
        return np.clip(ranks / n, 0.0, 1.0)

    def explain_row(self, x_row: npt.NDArray[np.float64]) -> dict[str, Any]:
        """`{total_score, per_feature: [{feature, contribution}, ...]}` — `contribution` is this
        row's deviation from the *mean of its own k nearest training-set neighbors* on that
        feature (module docstring), sorted by `|contribution|` descending, capped to the top
        `_TOP_K_EXPLANATION`. Always reported in original feature units, even when `space ==
        "pca"` selected the neighbors by PCA-space distance (module docstring "Full-space vs.
        PCA"). Unlike `ml.mahalanobis`'s quadratic decomposition, these terms are not guaranteed
        to sum to `total_score` (the LOF density ratio is not an additive function of per-feature
        deviations) — `total_score` is the model's own raw LOF score, reported alongside as the
        actual operating quantity, not implied by the per-feature list.
        """
        query = self._project(x_row.reshape(1, -1))
        _, neighbor_idx = self.model.detector_.kneighbors(query, n_neighbors=N_NEIGHBORS)
        reference = (
            self.train_x_full if self.train_x_full is not None else self.model.detector_._fit_X
        )
        neighbor_mean = np.asarray(reference)[neighbor_idx[0]].mean(axis=0)
        deviation = x_row - np.asarray(neighbor_mean)
        order = np.argsort(-np.abs(deviation))[:_TOP_K_EXPLANATION]
        per_feature = [
            {"feature": self.feature_names[i], "contribution": float(deviation[i])} for i in order
        ]
        return {
            "total_score": float(_raw_scores(self.model, query)[0]),
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
                "space": self.space,
                "pca": self.pca,
                "train_x_full": self.train_x_full,
            },
            path,
        )

    @classmethod
    def load(cls, path: Path) -> LOFArtifact:
        payload = joblib.load(path)
        return cls(
            model=payload["model"],
            feature_names=tuple(payload["feature_names"]),
            calibration_scores=payload["calibration_scores"],
            fit_seconds=payload["fit_seconds"],
            space=payload.get("space", "full"),
            pca=payload.get("pca"),
            train_x_full=payload.get("train_x_full"),
        )


def _raw_scores(model: LOF, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
    """Higher = more anomalous — pyod's `LOF.decision_function` already inverts sklearn's own
    `negative_outlier_factor_` convention internally (module docstring), no sign flip needed
    here. `sanitize_scores` is cheap defense-in-depth, matching every other model in this
    package."""
    scores: npt.NDArray[np.float64] = sanitize_scores(model.decision_function(x))
    return scores
