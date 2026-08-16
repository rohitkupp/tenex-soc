"""Unit tests for `app.detection.ml.knn` (`pyod.models.knn.KNN(method="largest")`, shipped as
`ml.kth_nn` -- see that module's docstring for why). Same shape as `test_ml_ecod.py`/
`test_ml_lof.py`, plus the fixture that is kth-NN's actual reason for existing on this roster
(docs/v2_migration change 19: "global distance, handles multimodality") -- a point sitting between
two well-separated benign clusters, anomalous even though it sits near the population's global
mean, which a single-Gaussian model (`ml.mahalanobis`) or per-feature model (`ml.ecod`) has no
principled way to flag.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from app.detection.ml.knn import KNNArtifact

_N_FEATURES = 50


def _benign_matrix(n: int = 2000, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.normal(size=(n, _N_FEATURES))


def _two_cluster_matrix(n: int, seed: int) -> np.ndarray:
    """Two tight, well-separated benign clusters (`n` rows total, split evenly) -- same shape
    `test_ml_lof.py` uses for its own local-density fixture, reused here because kth-NN's
    multimodality claim needs the identical setup: a genuinely bimodal population, not a single
    Gaussian with a wide tail."""
    rng = np.random.default_rng(seed)
    half = n // 2
    cluster_a = rng.normal(loc=-5.0, scale=0.3, size=(half, _N_FEATURES))
    cluster_b = rng.normal(loc=5.0, scale=0.3, size=(n - half, _N_FEATURES))
    return np.vstack([cluster_a, cluster_b])


def _correlated_matrix(n: int, seed: int, rank: int = 10) -> np.ndarray:
    """A matrix whose true rank (`rank`) is well below `_N_FEATURES` -- redundant, correlated
    columns for `fit_pca_reduction` to actually compress, so the PCA-variant test is exercising a
    real dimensionality reduction rather than retaining every component trivially."""
    rng = np.random.default_rng(seed)
    base = rng.normal(size=(n, rank))
    mixing = rng.normal(size=(rank, _N_FEATURES - rank))
    extra = base @ mixing * 0.1 + rng.normal(scale=0.01, size=(n, _N_FEATURES - rank))
    return np.hstack([base, extra])


def test_distant_point_scores_higher_than_dense_cluster_point() -> None:
    x_train = _benign_matrix(seed=1)
    x_calib = _benign_matrix(n=300, seed=2)
    artifact = KNNArtifact.fit(x_train, x_calib)

    dense_point = np.zeros((1, _N_FEATURES))
    distant_point = np.full((1, _N_FEATURES), 12.0)

    dense_score = artifact.raw_scores(dense_point)[0]
    distant_score = artifact.raw_scores(distant_point)[0]
    assert distant_score > dense_score


def test_ordinary_row_gets_low_confidence_and_distant_row_gets_high_confidence() -> None:
    x_train = _benign_matrix(seed=3)
    x_calib = _benign_matrix(n=500, seed=4)
    artifact = KNNArtifact.fit(x_train, x_calib)

    ordinary = np.zeros((1, _N_FEATURES))
    extreme = np.full((1, _N_FEATURES), 15.0)

    ordinary_conf = artifact.confidence(artifact.raw_scores(ordinary))[0]
    extreme_conf = artifact.confidence(artifact.raw_scores(extreme))[0]
    assert ordinary_conf < 0.9
    assert extreme_conf > 0.99


def test_multimodality_point_between_clusters_is_anomalous_despite_near_global_mean() -> None:
    """kth-NN's own reason for being on the roster (module docstring). The midpoint sits at
    (approximately) the population's global mean -- a global single-Gaussian distance measure has
    no basis to flag it -- but is far from *every* actual point in either cluster, which is
    exactly what a k-th-nearest-neighbor distance measures directly."""
    x_train = _two_cluster_matrix(1000, seed=9)
    x_calib = _two_cluster_matrix(200, seed=10)
    artifact = KNNArtifact.fit(x_train, x_calib)

    assert abs(float(x_train.mean())) < 0.5  # the two clusters are symmetric around ~0

    midpoint = np.zeros((1, _N_FEATURES))  # near the global mean, between the two clusters
    cluster_center = np.full((1, _N_FEATURES), -5.0)  # embedded in a real cluster's own density

    midpoint_score = artifact.raw_scores(midpoint)[0]
    center_score = artifact.raw_scores(cluster_center)[0]
    assert midpoint_score > center_score

    midpoint_conf = artifact.confidence(artifact.raw_scores(midpoint))[0]
    center_conf = artifact.confidence(artifact.raw_scores(cluster_center))[0]
    assert midpoint_conf > 0.99
    assert center_conf < 0.1


def test_explain_row_shape_and_deviation_from_kth_neighbor() -> None:
    x_train = _benign_matrix(seed=5)
    x_calib = _benign_matrix(n=200, seed=6)
    artifact = KNNArtifact.fit(x_train, x_calib)

    outlier = np.full(_N_FEATURES, 10.0)
    explanation = artifact.explain_row(outlier)

    assert "total_score" in explanation
    assert "per_feature" in explanation
    assert len(explanation["per_feature"]) <= 10
    for entry in explanation["per_feature"]:
        assert set(entry) == {"feature", "contribution"}
    contributions = [abs(e["contribution"]) for e in explanation["per_feature"]]
    assert contributions == sorted(contributions, reverse=True)
    # The row is uniformly extreme (every feature at 10.0, benign population ~N(0,1)) -- its k-th
    # neighbor should be far away on most features, so every reported deviation should be sizable.
    assert all(abs(c) > 1.0 for c in contributions)


def test_pca_variant_fits_scores_and_records_component_count() -> None:
    """Migration change 25's test plan: "distance methods full-space vs. PCA" -- the PCA variant
    must fit, score, and record how many components it retained (`dimensionality.py`)."""
    x_train = _correlated_matrix(1000, seed=1)
    x_calib = _correlated_matrix(200, seed=2)

    full = KNNArtifact.fit(x_train, x_calib, space="full")
    pca = KNNArtifact.fit(x_train, x_calib, space="pca")

    assert full.space == "full"
    assert full.pca is None
    assert pca.space == "pca"
    assert pca.pca is not None
    # The synthetic matrix's true rank is 10 (well below _N_FEATURES=50) -- PCA at ~95% variance
    # should compress it down meaningfully, not retain (almost) everything.
    assert 0 < pca.pca.n_components < _N_FEATURES

    row = np.full((1, _N_FEATURES), 3.0)
    full_score = full.raw_scores(row)[0]
    pca_score = pca.raw_scores(row)[0]
    assert np.isfinite(full_score)
    assert np.isfinite(pca_score)

    # explain_row still reports deviation in original feature units even though neighbor
    # *selection* happened in PCA space (module docstring "Full-space vs. PCA").
    explanation = pca.explain_row(row[0])
    assert len(explanation["per_feature"]) <= 10
    assert set(explanation["per_feature"][0]) == {"feature", "contribution"}


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    x_train = _benign_matrix(n=500, seed=7)
    x_calib = _benign_matrix(n=100, seed=8)
    artifact = KNNArtifact.fit(x_train, x_calib)

    path = tmp_path / "knn.joblib"
    artifact.save(path)
    loaded = KNNArtifact.load(path)

    row = np.full((1, _N_FEATURES), 5.0)
    np.testing.assert_allclose(artifact.raw_scores(row), loaded.raw_scores(row))
    assert loaded.feature_names == artifact.feature_names
    assert loaded.space == artifact.space


def test_save_and_load_round_trip_pca_variant(tmp_path: Path) -> None:
    x_train = _correlated_matrix(500, seed=3)
    x_calib = _correlated_matrix(100, seed=4)
    artifact = KNNArtifact.fit(x_train, x_calib, space="pca")

    path = tmp_path / "knn_pca.joblib"
    artifact.save(path)
    loaded = KNNArtifact.load(path)

    row = np.full((1, _N_FEATURES), 3.0)
    np.testing.assert_allclose(artifact.raw_scores(row), loaded.raw_scores(row))
    assert loaded.space == "pca"
    assert loaded.pca is not None
    assert loaded.pca.n_components == artifact.pca.n_components  # type: ignore[union-attr]
