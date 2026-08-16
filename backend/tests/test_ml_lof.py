"""Unit tests for `app.detection.ml.lof` (`pyod.models.lof.LOF`, shipped as `ml.peer_group` --
see that module's docstring for why). Same shape as `test_ml_iforest.py`, plus a fixture proving
the model's actual selling point: a point that is *not* a global outlier but *is* locally sparse
relative to its own neighborhood, and a full-space-vs-PCA fixture (migration change 25's test
plan; see `test_ml_knn.py`'s own copy of this fixture for the sibling distance model).
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from app.detection.ml.lof import LOFArtifact

_N_FEATURES = 50


def _benign_matrix(n: int = 2000, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.normal(size=(n, _N_FEATURES))


def _correlated_matrix(n: int, seed: int, rank: int = 10) -> np.ndarray:
    """A matrix whose true rank (`rank`) is well below `_N_FEATURES` -- see `test_ml_knn.py`'s
    identical helper for why this shape (not plain `_benign_matrix`) is what exercises PCA
    meaningfully."""
    rng = np.random.default_rng(seed)
    base = rng.normal(size=(n, rank))
    mixing = rng.normal(size=(rank, _N_FEATURES - rank))
    extra = base @ mixing * 0.1 + rng.normal(scale=0.01, size=(n, _N_FEATURES - rank))
    return np.hstack([base, extra])


def test_global_outlier_scores_higher_than_inlier() -> None:
    x_train = _benign_matrix(seed=1)
    x_calib = _benign_matrix(n=300, seed=2)
    artifact = LOFArtifact.fit(x_train, x_calib)

    inlier = np.zeros((1, _N_FEATURES))
    outlier = np.full((1, _N_FEATURES), 12.0)

    inlier_score = artifact.raw_scores(inlier)[0]
    outlier_score = artifact.raw_scores(outlier)[0]
    assert outlier_score > inlier_score


def test_locally_sparse_point_between_two_dense_clusters_scores_higher_than_either_cluster_center() -> (
    None
):
    """LOF's own premise (docs/04: "peer-relative anomalies exist that global methods miss"): two
    tight, well-separated benign clusters, and a point placed exactly between them. That midpoint
    is not a global outlier by any coarse population-wide measure (it sits well within the overall
    span the two clusters cover) but has far fewer near neighbors than a point at either cluster's
    own center -- the density-ratio signal LOF is built to catch and a global covariance/partition
    model is not.
    """
    rng = np.random.default_rng(9)
    cluster_a = rng.normal(loc=0.0, scale=0.3, size=(500, _N_FEATURES))
    cluster_b = rng.normal(loc=10.0, scale=0.3, size=(500, _N_FEATURES))
    x_train = np.vstack([cluster_a, cluster_b])
    x_calib = _benign_matrix(n=200, seed=10)
    artifact = LOFArtifact.fit(x_train, x_calib)

    cluster_center = np.zeros((1, _N_FEATURES))
    midpoint = np.full((1, _N_FEATURES), 5.0)

    center_score = artifact.raw_scores(cluster_center)[0]
    midpoint_score = artifact.raw_scores(midpoint)[0]
    assert midpoint_score > center_score


def test_explain_row_shape() -> None:
    x_train = _benign_matrix(seed=5)
    x_calib = _benign_matrix(n=200, seed=6)
    artifact = LOFArtifact.fit(x_train, x_calib)

    outlier = np.full(_N_FEATURES, 10.0)
    explanation = artifact.explain_row(outlier)

    assert "total_score" in explanation
    assert "per_feature" in explanation
    assert len(explanation["per_feature"]) <= 10
    for entry in explanation["per_feature"]:
        assert set(entry) == {"feature", "contribution"}
    contributions = [abs(e["contribution"]) for e in explanation["per_feature"]]
    assert contributions == sorted(contributions, reverse=True)


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    x_train = _benign_matrix(n=500, seed=7)
    x_calib = _benign_matrix(n=100, seed=8)
    artifact = LOFArtifact.fit(x_train, x_calib)

    path = tmp_path / "lof.joblib"
    artifact.save(path)
    loaded = LOFArtifact.load(path)

    row = np.full((1, _N_FEATURES), 5.0)
    np.testing.assert_allclose(artifact.raw_scores(row), loaded.raw_scores(row))
    assert loaded.feature_names == artifact.feature_names
    assert loaded.space == artifact.space == "full"


def test_pca_variant_fits_scores_and_records_component_count() -> None:
    """Migration change 25's test plan: "distance methods full-space vs. PCA" -- LOF is the
    second of the two distance methods (`ml.kth_nn` is the other, `test_ml_knn.py`)."""
    x_train = _correlated_matrix(1000, seed=1)
    x_calib = _correlated_matrix(200, seed=2)

    full = LOFArtifact.fit(x_train, x_calib, space="full")
    pca = LOFArtifact.fit(x_train, x_calib, space="pca")

    assert full.pca is None
    assert pca.pca is not None
    assert 0 < pca.pca.n_components < _N_FEATURES

    row = np.full((1, _N_FEATURES), 3.0)
    assert np.isfinite(full.raw_scores(row)[0])
    assert np.isfinite(pca.raw_scores(row)[0])

    explanation = pca.explain_row(row[0])
    assert len(explanation["per_feature"]) <= 10
    assert set(explanation["per_feature"][0]) == {"feature", "contribution"}
