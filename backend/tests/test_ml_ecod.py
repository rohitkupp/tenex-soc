"""Unit tests for `app.detection.ml.ecod` (`pyod.models.ecod.ECOD`). Same shape as
`test_ml_iforest.py` -- CLAUDE.md's "every detector needs a synthetic fixture that must fire and
one that must not" -- plus a determinism check specific to ECOD's own pre-registered claim
(docs/04: "parameter-free ... deterministic").
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from app.detection.ml.ecod import ECODArtifact

_N_FEATURES = 50


def _benign_matrix(n: int = 2000, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.normal(size=(n, _N_FEATURES))


def test_marginal_outlier_scores_higher_than_inlier() -> None:
    # ECOD aggregates per-feature tail probability -- a row extreme on every marginal feature is
    # exactly the shape it is built to catch.
    x_train = _benign_matrix(seed=1)
    x_calib = _benign_matrix(n=300, seed=2)
    artifact = ECODArtifact.fit(x_train, x_calib)

    inlier = np.zeros((1, _N_FEATURES))
    outlier = np.full((1, _N_FEATURES), 12.0)

    inlier_score = artifact.raw_scores(inlier)[0]
    outlier_score = artifact.raw_scores(outlier)[0]
    assert outlier_score > inlier_score


def test_ordinary_row_gets_low_confidence_and_extreme_row_gets_high_confidence() -> None:
    x_train = _benign_matrix(seed=3)
    x_calib = _benign_matrix(n=500, seed=4)
    artifact = ECODArtifact.fit(x_train, x_calib)

    ordinary = np.zeros((1, _N_FEATURES))
    extreme = np.full((1, _N_FEATURES), 15.0)

    ordinary_conf = artifact.confidence(artifact.raw_scores(ordinary))[0]
    extreme_conf = artifact.confidence(artifact.raw_scores(extreme))[0]
    assert ordinary_conf < 0.9
    assert extreme_conf > 0.99


def test_raw_scores_are_deterministic_across_repeated_calls() -> None:
    """docs/04's own claim for ECOD: parameter-free and deterministic, unlike `ml.iforest`
    (seeded random partitioning) or `ml.autoencoder` (seeded weight init + SGD)."""
    x_train = _benign_matrix(seed=5)
    x_calib = _benign_matrix(n=200, seed=6)
    artifact = ECODArtifact.fit(x_train, x_calib)

    row = np.full((1, _N_FEATURES), 7.0)
    first = artifact.raw_scores(row)
    second = artifact.raw_scores(row)
    np.testing.assert_array_equal(first, second)


def test_explain_row_shape_and_decomposition_sums_to_total() -> None:
    x_train = _benign_matrix(seed=5)
    x_calib = _benign_matrix(n=200, seed=6)
    artifact = ECODArtifact.fit(x_train, x_calib)

    outlier = np.full(_N_FEATURES, 10.0)
    explanation = artifact.explain_row(outlier)

    assert "total_score" in explanation
    assert "per_feature" in explanation
    assert len(explanation["per_feature"]) <= 10
    for entry in explanation["per_feature"]:
        assert set(entry) == {"feature", "contribution"}
        assert entry["contribution"] >= 0.0  # ECOD's per-dimension tail scores are non-negative
    contributions = [e["contribution"] for e in explanation["per_feature"]]
    assert contributions == sorted(contributions, reverse=True)


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    x_train = _benign_matrix(n=500, seed=7)
    x_calib = _benign_matrix(n=100, seed=8)
    artifact = ECODArtifact.fit(x_train, x_calib)

    path = tmp_path / "ecod.joblib"
    artifact.save(path)
    loaded = ECODArtifact.load(path)

    row = np.full((1, _N_FEATURES), 5.0)
    np.testing.assert_allclose(artifact.raw_scores(row), loaded.raw_scores(row))
    assert loaded.feature_names == artifact.feature_names
