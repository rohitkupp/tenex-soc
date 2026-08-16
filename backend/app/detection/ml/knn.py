"""`ml.kth_nn` — kth-nearest-neighbor distance (docs/04 §L3 model table; migration change 19's
post-migration roster: "kth-NN | instance-based | global distance, handles multimodality",
`docs/v2_migration/MIGRATION-01-evidence-first.md`).

Wraps `pyod.models.knn.KNN(method="largest")` directly — "kth-NN distance" *is* what that method
computes (pyod's own docstring: `"largest": use the distance to the kth neighbor as the outlier
score`), so there is nothing to hand-roll here. Contrast `ml.eif`, which *is* hand-rolled, because
CLAUDE.md forbids a new dependency and the closest PyPI package for that algorithm is lightly
maintained — `pyod` is already a stack dependency (`ml.ecod`, `ml.peer_group`) and already
implements this one exactly.

## The hypothesis this model tests

`ml.mahalanobis` assumes one global elliptical (Gaussian-shaped) population. `ml.ecod` assumes
per-feature tail probability is independently informative. Neither assumption holds when benign
behavior is genuinely *multimodal* — several distinct, legitimate clusters (e.g. an engineering
cohort's traffic profile and a sales cohort's, both ordinary, both far apart in feature space) with
low density in between. A point sitting between two dense benign clusters is not extreme relative
to either cluster and is not far from the population mean in any single feature's marginal, but a
distance-to-neighbors measure sees it immediately: its nearest neighbors are all further away than
a point genuinely embedded in either cluster's own density. kth-NN's raw distance direct to its
k-th neighbor makes no distributional-shape assumption at all — it is exactly the non-parametric,
multimodality-tolerant complement `ml.mahalanobis`'s single-covariance assumption and `ml.ecod`'s
per-feature independence assumption both lack. `ml.peer_group` (LOF) is also instance-based and
local, but normalizes by neighborhood *density ratio* (locally relative); kth-NN's raw distance is
global (not normalized against the neighbors' own density), which is the second half of the
roster's stated role: "global distance, handles multimodality."

## Sign convention

pyod's `KNN.decision_function` already reports "the higher, the more abnormal" (pyod's own
docstring) — larger kth-neighbor distance means more anomalous, already on this package's own
higher-is-more-anomalous axis. No sign flip needed, matching `ml.ecod`/`ml.peer_group` and unlike
`ml.iforest`.

## Full-space vs. PCA (migration change 25's test plan; see `dimensionality.py`)

`space` records which feature space produced this artifact's neighbor distances —
`fit_pca_reduction` retains ~95% variance. Whichever space is active, `explain_row` still reports
per-feature deviation in the *original* (scaled) feature space, not PCA component units: even when
neighbor *selection* happens in PCA space, an analyst reading `explain_row`'s output needs "which
raw features differ from the neighbor," not a loading on an unlabeled component. `train_x_full`
carries the original training rows (index-aligned with the PCA-space fitted model) purely so
`explain_row` can look up the *same* neighbor's original feature values when `space == "pca"`; it
is `None` for the (default) full-space artifact, which already has its neighbors' original values
directly on `model.neigh_._fit_X`.

## `explain_row` — deviation from the k-th neighbour itself

Unlike `ml.peer_group`'s explanation (deviation from the *mean* of its k neighbors — LOF's premise
is a local density ratio over the whole neighborhood), kth-NN's own raw score is specifically the
distance to its single k-th (farthest-of-the-k) neighbor, so its explanation reports deviation from
that *same* point — the one point that actually determines this row's score — rather than an
average that would explain a different number than `total_score`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import numpy.typing as npt
from pyod.models.knn import KNN

from app.detection.ml.dimensionality import FeatureSpace, PCAReduction, fit_pca_reduction
from app.detection.ml.features import ENTITY_WINDOW_MODEL_FEATURES, sanitize_scores

__all__ = ["KNN_ARTIFACT_FILENAME", "KNN_PCA_ARTIFACT_FILENAME", "KNNArtifact"]

KNN_ARTIFACT_FILENAME = "knn.joblib"
KNN_PCA_ARTIFACT_FILENAME = "knn_pca.joblib"

# Same "pyod/sklearn default, not tuned against this corpus" reasoning `ml.peer_group` (LOF)
# states for its own `N_NEIGHBORS` (`lof.py`) — reused verbatim here rather than re-derived, since
# both models share the same "k nearest neighbors" primitive and there is no basis yet (no eval
# run against this corpus) for the two to disagree on k.
N_NEIGHBORS = 20
RANDOM_STATE = 42
_TOP_K_EXPLANATION = 10


@dataclass(slots=True)
class KNNArtifact:
    """A fitted `pyod.models.knn.KNN` plus the same benign calibration sample every other L3
    model in this package carries, plus the recorded full-space/PCA choice — module docstring."""

    model: KNN
    feature_names: tuple[str, ...]
    calibration_scores: npt.NDArray[np.float64]
    fit_seconds: float
    space: FeatureSpace = "full"
    pca: PCAReduction | None = None
    # Only populated when `space == "pca"` — see module docstring "Full-space vs. PCA".
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
        random_state: int = RANDOM_STATE,
    ) -> KNNArtifact:
        t0 = time.perf_counter()
        pca_reduction: PCAReduction | None = None
        fit_x = x_train
        train_x_full: npt.NDArray[np.float64] | None = None
        if space == "pca":
            pca_reduction = fit_pca_reduction(x_train, random_state=random_state)
            fit_x = pca_reduction.transform(x_train)
            train_x_full = x_train

        model = KNN(n_neighbors=n_neighbors, method="largest")
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
        row's deviation from its own k-th nearest neighbor (module docstring), always reported in
        original feature units even when `space == "pca"` selected that neighbor by PCA-space
        distance."""
        query = self._project(x_row.reshape(1, -1))
        k = self.model.n_neighbors
        _, neighbor_idx = self.model.neigh_.kneighbors(query, n_neighbors=k, return_distance=True)
        kth_idx = int(neighbor_idx[0, -1])
        if self.train_x_full is not None:
            kth_neighbor = self.train_x_full[kth_idx]
        else:
            kth_neighbor = np.asarray(self.model.neigh_._fit_X[kth_idx])
        deviation = x_row - kth_neighbor
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
    def load(cls, path: Path) -> KNNArtifact:
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


def _raw_scores(model: KNN, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
    """Higher = more anomalous — pyod's own convention already matches this package's, no sign
    flip needed (module docstring)."""
    scores: npt.NDArray[np.float64] = sanitize_scores(model.decision_function(x))
    return scores
