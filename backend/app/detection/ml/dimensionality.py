"""Shared PCA-reduction path for this package's *distance*-based L3 models (`ml.kth_nn`,
`ml.peer_group`/LOF) — migration change 25's test plan (`docs/v2_migration/MIGRATION-01-evidence-
first.md`, "Model" row: "distance methods full-space vs. PCA").

## Why this exists as its own module rather than living inside `knn.py`

Both distance methods need the identical capability (fit once, transform consistently, record how
many components survived), and duplicating it would risk the two copies drifting — e.g. one using
`svd_solver="full"` and the other not, silently changing which model's "PCA variant" is actually
comparable to the other's. One fit function, imported by both `knn.py` and `lof.py`.

## Why the reduction is a recorded, explicit choice, not an implicit default

A k-NN/LOF distance computed over 50 raw features and one computed over ~20-40 PCA components
answer different questions (raw feature-space proximity vs. proximity in the directions of
greatest population variance) — silently defaulting to one would hide which question the shipped
model is actually answering. `KNNArtifact`/`LOFArtifact` both carry a `space: FeatureSpace` field
recorded at fit time (`"full"` or `"pca"`), and `train.py` picks the shipped instance's space via
a named module-level constant rather than an unstated default value buried in a function
signature — see that module's own comment on why `"full"` is the current shipped choice.

## Component count — retain ~95% variance, record it

`PCA_VARIANCE_RETAINED = 0.95` (docs/v2_migration change 25: "retain enough components for ~95%
variance and record the component count in the artifact"). `sklearn.decomposition.PCA` accepts a
variance fraction directly as `n_components` when `svd_solver="full"`; the resulting
`pca.n_components_` is exactly "how many components it took," which `fit_pca_reduction` surfaces
as `PCAReduction.n_components` for the artifact (and, downstream, `evals/results.md`) to record.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

import numpy as np
import numpy.typing as npt
from sklearn.decomposition import PCA

__all__ = ["PCA_VARIANCE_RETAINED", "FeatureSpace", "PCAReduction", "fit_pca_reduction"]

FeatureSpace = Literal["full", "pca"]

PCA_VARIANCE_RETAINED: Final[float] = 0.95


@dataclass(slots=True)
class PCAReduction:
    """A fitted `PCA` plus the component count it settled on for `PCA_VARIANCE_RETAINED` — the
    "recorded component count" the migration's test plan asks for."""

    pca: PCA
    n_components: int

    def transform(self, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
        transformed: npt.NDArray[np.float64] = self.pca.transform(x)
        return transformed


def fit_pca_reduction(
    x_train: npt.NDArray[np.float64],
    *,
    variance_retained: float = PCA_VARIANCE_RETAINED,
    random_state: int = 42,
) -> PCAReduction:
    """Fit on `x_train` alone (the same split every other L3 model's `.fit(x_train, x_calibration)`
    fits against — never on calibration or eval data, which would leak population structure the
    shipped model is not supposed to have seen)."""
    pca = PCA(n_components=variance_retained, svd_solver="full", random_state=random_state)
    pca.fit(x_train)
    n_components = int(pca.n_components_)
    return PCAReduction(pca=pca, n_components=n_components)
