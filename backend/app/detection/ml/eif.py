"""`ml.eif` — Extended Isolation Forest (docs/04 §L3 model table; migration change 19's
post-migration roster: "EIF | fitted trees | global entity anomaly, oblique splits",
`docs/v2_migration/MIGRATION-01-evidence-first.md`).

## Hand-rolled, deliberately

CLAUDE.md forbids adding a library not already in the stack table without asking. The `eif`
package on PyPI is lightly maintained (the reference implementation from Hariri, Kind & Brunner,
"Extended Isolation Forest," IEEE TKDE 2019/2021), and the algorithm is a small, well-specified
delta on top of ordinary Isolation Forest — a random *hyperplane* split instead of a random
*axis-aligned threshold* split, with everything else (subsampling, path length, the `c(n)`
normalisation, `2^(-E[h]/c(n))`) unchanged. Small enough to implement directly rather than pull in
a dependency for.

## The hypothesis this model tests

Ordinary Isolation Forest (`ml.iforest`, this package's baseline) partitions on one feature at a
time: `x[j] < t`. A joint-distribution anomaly that sits off any single feature's tail but off the
population's *diagonal* correlation structure — the exact shape `ml.mahalanobis` is built to catch
via a linear metric — is expensive for axis-parallel splits to isolate: carving a diagonal boundary
out of a series of orthogonal cuts takes many more cuts than carving it with one cut that is already
diagonal, which inflates the anomaly's average path length and weakens its isolation score even
though it *is* globally anomalous. Migration change 19's own words: this is exactly the job the
autoencoder used to do ("joint-distribution anomalies where no single feature is in a tail") before
being cut on the architectural bet that "if EIF matches the autoencoder, the autoencoder is cut" —
docs/04. Each node instead splits on a random hyperplane: draw a random normal vector `n` and an
intercept point `p`, branch on `(x - p) · n <= 0`. A single oblique cut can isolate a point that is
extreme only along a direction no single axis matches.

## `extension_level` — the knob that makes "does obliqueness help" answerable

`extension_level=0` restricts every split's random normal to exactly one non-zero component —
axis-parallel, structurally equivalent to standard Isolation Forest (a different concrete
implementation than `sklearn.IsolationForest`, but the same splitting rule: one feature, one
threshold, per node). `extension_level=d-1` (the default — `None` resolves to this) leaves every
component of `n` non-zero: fully oblique, splitting on an arbitrary direction through the data.
Values in between interpolate. Benchmarking the same model architecture at `extension_level=0`
against `extension_level=d-1` isolates *obliqueness itself* as the only variable — unlike comparing
EIF against `ml.iforest`, which would also be comparing two different implementations.

## Sign convention

Every model in this package reports `raw_score` on the same axis: higher means more anomalous.
`2^(-E[h(x)]/c(psi))` (this module's own score, not sklearn's) is already on that axis by
construction — short average path length (fast isolation) produces a score near 1; long average
path length (hard to isolate, i.e. typical) produces a score near 0. No sign flip needed, unlike
`ml.iforest`, which negates `sklearn.IsolationForest.score_samples`'s opposite convention.

## `explain_row` — path-projection attribution, honestly not SHAP

There is no natural per-feature attribution for an oblique split the way there is for an
axis-parallel one (`ml.iforest`'s SHAP) or a quadratic form (`ml.mahalanobis`). What *is* available
is the row's own root-to-leaf path in every tree: at each internal node the row passed through, the
hyperplane projection `(x - p) · n` decomposes exactly into per-feature terms
`n_i * (x_i - p_i)`, since a dot product is a sum. `explain_row` accumulates those per-feature terms
along the row's path in every tree, weighted `1 / (depth + 1)` — nodes near the root get more
weight than nodes near the leaf, because a short average path length (the thing that makes the
score anomalous) is dominated by *how quickly* the row separates from the rest of the subsample,
and the earliest splits on its path are what drove that. This is a real, inspectable quantity (this
row's own contribution to its own hyperplane crossings, not a synthetic proxy), but it is a
heuristic path-based attribution, not a game-theoretic (SHAP) or algebraically exact (Mahalanobis's
`z^T P z`) decomposition: the terms are not guaranteed to sum to `total_score`, which is reported
separately as the model's own raw score, the same honesty `ml.peer_group` (LOF) states about its
own neighbor-deviation explanation for the same underlying reason (a locally/structurally defined
score has no exact linear per-feature decomposition).
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import joblib
import numpy as np
import numpy.typing as npt

from app.detection.ml.features import ENTITY_WINDOW_MODEL_FEATURES, sanitize_scores

__all__ = ["EIF_ARTIFACT_FILENAME", "EIFArtifact", "ExtendedIsolationForest"]

EIF_ARTIFACT_FILENAME = "eif.joblib"

# Matches `ml.iforest`'s own `N_ESTIMATORS` (`iforest.py`) — equal tree count is what makes an
# EIF-vs-iForest benchmark comparison a test of obliqueness, not of ensemble size.
N_ESTIMATORS: Final[int] = 200
# The original Isolation Forest paper's (Liu, Ting & Zhou, 2008) own finding: 256 is enough
# subsample per tree regardless of total corpus size, and the Extended Isolation Forest paper
# reuses it unchanged. Not tuned against this corpus (CLAUDE.md: hyperparameters are load-bearing
# choices, stated plainly, not tuned after seeing a result).
SAMPLE_SIZE: Final[int] = 256
RANDOM_STATE: Final[int] = 42
_TOP_K_EXPLANATION: Final[int] = 10
# Euler-Mascheroni constant, used by `_average_path_length`'s harmonic-number approximation —
# same closed form the original Isolation Forest paper uses for `c(n)`.
_EULER_GAMMA: Final[float] = 0.5772156649015328606


# ---------------------------------------------------------------------------- tree structure
#
# A tagged union (`_LeafNode | _InternalNode`) rather than one node class with optional fields —
# lets every consumer below narrow via `isinstance` under `mypy --strict` instead of asserting
# away `X | None` at every access.


@dataclass(slots=True)
class _LeafNode:
    size: int


@dataclass(slots=True)
class _InternalNode:
    normal: npt.NDArray[np.float64]
    point: npt.NDArray[np.float64]
    left: _EIFNode
    right: _EIFNode


_EIFNode = _LeafNode | _InternalNode


def _average_path_length(n: int) -> float:
    """`c(n)` — Liu, Ting & Zhou (2008)'s average unsuccessful-BST-search path length, the
    normalisation both ordinary Isolation Forest and Extended Isolation Forest use to turn a raw
    average path length into a bounded `2^(-E[h]/c(n))` score."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1) + _EULER_GAMMA) - 2.0 * (n - 1) / n


def _build_node(
    x: npt.NDArray[np.float64],
    height: int,
    height_limit: int,
    extension_level: int,
    rng: np.random.Generator,
) -> _EIFNode:
    """One tree, recursively. `x` is already this tree's own subsample (or a partition of it).

    Split: draw a standard-normal vector `n` (dimension `d`), zero out `d - 1 - extension_level`
    of its components (uniformly chosen) so exactly `extension_level + 1` remain non-zero — module
    docstring's "the knob" — then draw an intercept point `p` uniformly within this subset's own
    per-feature range and branch on `(x - p) · n <= 0`.
    """
    n, d = x.shape
    if height >= height_limit or n <= 1:
        return _LeafNode(size=n)

    # `d: int` explicit -- `x.shape`'s unpacked element type resolves to `Any` under this
    # project's numpy stub version, which makes `rng.normal(size=d)` ambiguous between numpy's
    # scalar-returning and array-returning overloads (mypy picks the former without this).
    n_features: int = d
    normal = rng.normal(size=n_features)
    n_zero = d - 1 - extension_level
    if n_zero > 0:
        zero_idx = rng.choice(d, size=n_zero, replace=False)
        normal[zero_idx] = 0.0

    mins = x.min(axis=0)
    maxs = x.max(axis=0)
    point = rng.uniform(mins, maxs)

    proj = (x - point) @ normal
    left_mask = proj <= 0.0
    if not left_mask.any() or left_mask.all():
        # The random hyperplane failed to separate this subsample — every remaining point is
        # identical on every dimension the hyperplane's non-zero components touch (the fully
        # degenerate case: identical on *every* dimension). Stop here rather than recursing
        # forever on an unchanged partition; a single failed attempt, not a retry loop, because a
        # continuous random draw landing exactly on a non-separating hyperplane by chance (rather
        # than because the data genuinely cannot be separated) has probability zero.
        return _LeafNode(size=n)

    left = _build_node(x[left_mask], height + 1, height_limit, extension_level, rng)
    right = _build_node(x[~left_mask], height + 1, height_limit, extension_level, rng)
    return _InternalNode(normal=normal, point=point, left=left, right=right)


def _accumulate_path_lengths(
    x: npt.NDArray[np.float64],
    node: _EIFNode,
    height: int,
    idx: npt.NDArray[np.intp],
    out: npt.NDArray[np.float64],
) -> None:
    """Batch traversal: `idx` is the subset of `x`'s row indices still live at `node`. Vectorised
    per node (one boolean mask over however many rows are still active), not per row per node —
    `n_estimators * n_rows` individual Python-level tree walks would be needlessly slow at eval
    scale."""
    if isinstance(node, _LeafNode):
        out[idx] += height + _average_path_length(node.size)
        return
    diff = x[idx] - node.point
    proj = diff @ node.normal
    left_idx = idx[proj <= 0.0]
    right_idx = idx[proj > 0.0]
    if left_idx.size:
        _accumulate_path_lengths(x, node.left, height + 1, left_idx, out)
    if right_idx.size:
        _accumulate_path_lengths(x, node.right, height + 1, right_idx, out)


def _row_path_contributions(
    x_row: npt.NDArray[np.float64],
    node: _EIFNode,
    height: int,
    contributions: npt.NDArray[np.float64],
) -> None:
    """One row's own root-to-leaf walk in one tree, accumulating `explain_row`'s per-feature
    projection terms in place — module docstring, "path-projection attribution"."""
    while isinstance(node, _InternalNode):
        terms = node.normal * (x_row - node.point)
        weight = 1.0 / (height + 1.0)
        contributions += weight * terms
        node = node.left if float(terms.sum()) <= 0.0 else node.right
        height += 1


class ExtendedIsolationForest:
    """Seeded, dependency-free Extended Isolation Forest (module docstring). Mirrors the
    constructor/`fit`/`decision_function` shape of the sklearn/pyod estimators every sibling
    model in this package wraps, so `EIFArtifact` below follows the exact same pattern as
    `ECODArtifact`/`LOFArtifact` even though there is no third-party estimator underneath it.
    """

    def __init__(
        self,
        *,
        n_estimators: int = N_ESTIMATORS,
        sample_size: int = SAMPLE_SIZE,
        extension_level: int | None = None,
        random_state: int = RANDOM_STATE,
    ) -> None:
        self.n_estimators = n_estimators
        self.sample_size = sample_size
        # `None` resolves to fully oblique (`d - 1`) once `d` is known, at `fit` time — module
        # docstring. Kept as the constructor default because it is what the shipped roster entry
        # uses: EIF's whole reason for existing is obliqueness, so the shipped instance should be
        # maximally oblique unless a caller (a test isolating the `extension_level` variable)
        # asks for something else.
        self._extension_level_param = extension_level
        self.random_state = random_state
        self.trees: list[_EIFNode] = []
        self.extension_level: int = 0
        self.psi: int = 0
        self.c_psi: float = 0.0
        self.n_features_: int = 0

    def fit(self, x: npt.NDArray[np.float64]) -> ExtendedIsolationForest:
        n, d = x.shape
        if n < 2:
            raise ValueError("ExtendedIsolationForest.fit needs at least 2 rows")
        self.n_features_ = d
        max_extension = d - 1
        level = (
            max_extension if self._extension_level_param is None else self._extension_level_param
        )
        if not 0 <= level <= max_extension:
            raise ValueError(
                f"extension_level must be between 0 and {max_extension} (d-1) for a "
                f"{d}-feature matrix, got {level}"
            )
        self.extension_level = level
        self.psi = min(self.sample_size, n)
        height_limit = math.ceil(math.log2(max(self.psi, 2)))

        rng = np.random.default_rng(self.random_state)
        self.trees = []
        for _ in range(self.n_estimators):
            sample_idx = rng.choice(n, size=self.psi, replace=False)
            # Independent seed per tree, itself deterministically derived from the forest's own
            # seeded generator -- reproducible across runs and processes without every tree
            # sharing one generator's advancing state.
            tree_rng = np.random.default_rng(int(rng.integers(0, 2**32 - 1)))
            self.trees.append(
                _build_node(x[sample_idx], 0, height_limit, self.extension_level, tree_rng)
            )
        self.c_psi = _average_path_length(self.psi)
        return self

    def path_lengths(self, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
        """`E[h(x)]` — mean path length across every tree, for every row in `x`."""
        n = x.shape[0]
        totals = np.zeros(n, dtype=np.float64)
        idx_all = np.arange(n)
        for tree in self.trees:
            _accumulate_path_lengths(x, tree, 0, idx_all, totals)
        result: npt.NDArray[np.float64] = totals / max(len(self.trees), 1)
        return result

    def decision_function(self, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
        """`2^(-E[h(x)]/c(psi))` — see module docstring "Sign convention"."""
        if self.c_psi <= 0.0 or not self.trees:
            return np.zeros(x.shape[0], dtype=np.float64)
        avg_path = self.path_lengths(x)
        scores: npt.NDArray[np.float64] = np.exp2(-avg_path / self.c_psi)
        return scores

    def row_contributions(self, x_row: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
        """`explain_row`'s per-feature accumulation for one row, averaged over trees."""
        contributions = np.zeros(self.n_features_, dtype=np.float64)
        for tree in self.trees:
            _row_path_contributions(x_row, tree, 0, contributions)
        if self.trees:
            contributions /= len(self.trees)
        return contributions


@dataclass(slots=True)
class EIFArtifact:
    """A fitted `ExtendedIsolationForest` plus the same benign calibration sample every other L3
    model in this package carries (`IsolationForestArtifact`'s docstring: the interim, pre-M10
    percentile-rank substitute for isotonic calibration)."""

    model: ExtendedIsolationForest
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
        extension_level: int | None = None,
        n_estimators: int = N_ESTIMATORS,
        sample_size: int = SAMPLE_SIZE,
        random_state: int = RANDOM_STATE,
    ) -> EIFArtifact:
        t0 = time.perf_counter()
        model = ExtendedIsolationForest(
            n_estimators=n_estimators,
            sample_size=sample_size,
            extension_level=extension_level,
            random_state=random_state,
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

    @property
    def extension_level(self) -> int:
        """The resolved `extension_level` this artifact was actually fit with (`None` at
        `fit()`-call time resolves to `d - 1` — module docstring)."""
        return self.model.extension_level

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
        """`{total_score, per_feature: [{feature, contribution}, ...]}` — see module docstring
        "explain_row" for what `contribution` means here and why it is honestly not SHAP:
        `per_feature` terms are not guaranteed to sum to `total_score`, which is reported
        separately as this row's actual `raw_score`."""
        contributions = self.model.row_contributions(x_row)
        order = np.argsort(-np.abs(contributions))[:_TOP_K_EXPLANATION]
        per_feature = [
            {"feature": self.feature_names[i], "contribution": float(contributions[i])}
            for i in order
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
    def load(cls, path: Path) -> EIFArtifact:
        payload = joblib.load(path)
        return cls(
            model=payload["model"],
            feature_names=tuple(payload["feature_names"]),
            calibration_scores=payload["calibration_scores"],
            fit_seconds=payload["fit_seconds"],
        )


def _raw_scores(
    model: ExtendedIsolationForest, x: npt.NDArray[np.float64]
) -> npt.NDArray[np.float64]:
    """Higher = more anomalous — see module docstring "Sign convention." `sanitize_scores` is
    cheap defense-in-depth (matches every other model in this package); `2^(-E[h]/c(psi))` is
    bounded in `[0, ~1]` by construction so this is not expected to fire in practice."""
    scores: npt.NDArray[np.float64] = sanitize_scores(model.decision_function(x))
    return scores
