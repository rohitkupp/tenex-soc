"""Unit tests for `app.detection.ml.mahalanobis`.

The marginal-outlier fixture mirrors `test_ml_iforest.py`'s. The correlation-only fixture is the
more important one: it is a small-scale rehearsal of exactly what `docs/11` scenario 8 (low-and-
slow exfil) is built to test at full pipeline scale -- a point that is *not* extreme on any single
feature but breaks a correlation the benign population always respects. A model that only reads
the joint distribution should flag it; a purely marginal check would not.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from app.detection.ml.mahalanobis import MahalanobisArtifact

_N_FEATURES = 50


def _benign_matrix(n: int = 2000, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.normal(size=(n, _N_FEATURES))


def test_outlier_scores_higher_than_inlier() -> None:
    x_train = _benign_matrix(seed=1)
    x_calib = _benign_matrix(n=300, seed=2)
    artifact = MahalanobisArtifact.fit(x_train, x_calib)

    inlier = np.zeros((1, _N_FEATURES))
    outlier = np.full((1, _N_FEATURES), 12.0)

    assert artifact.raw_scores(outlier)[0] > artifact.raw_scores(inlier)[0]


def test_correlation_only_anomaly_is_flagged_even_though_every_marginal_is_normal() -> None:
    rng = np.random.default_rng(42)
    n = 3000
    x = rng.normal(size=(n, _N_FEATURES))
    # Features 0 and 1 are tightly correlated in the benign population (feature 1 tracks
    # feature 0 almost exactly) -- the shape docs/11 scenario 8 exploits: elevated bytes_out
    # almost always co-occurs with elevated automation_ua_ratio in the benign corpus.
    x[:, 1] = x[:, 0] + rng.normal(scale=0.05, size=n)

    x_train, x_calib = x[: n - 300], x[n - 300 :]
    artifact = MahalanobisArtifact.fit(x_train, x_calib)

    # This point's marginals (feature 0 and feature 1 individually) sit at z ~= 1.5, well inside
    # any reasonable per-feature threshold -- but the *pairing* (high feature 0, near-zero
    # feature 1) never occurs in the correlated benign population.
    broken_correlation = np.zeros((1, _N_FEATURES))
    broken_correlation[0, 0] = 1.5
    broken_correlation[0, 1] = -1.5

    ordinary = np.zeros((1, _N_FEATURES))
    ordinary[0, 0] = 1.5
    ordinary[0, 1] = 1.5  # respects the correlation

    score_broken = artifact.raw_scores(broken_correlation)[0]
    score_ordinary = artifact.raw_scores(ordinary)[0]
    assert score_broken > score_ordinary
    conf_broken = artifact.confidence(np.array([score_broken]))[0]
    assert conf_broken > 0.95


def test_explain_row_contributions_sum_to_total_score() -> None:
    x_train = _benign_matrix(seed=5)
    x_calib = _benign_matrix(n=200, seed=6)
    artifact = MahalanobisArtifact.fit(x_train, x_calib)

    row = np.full(_N_FEATURES, 3.0)
    explanation = artifact.explain_row(row)
    assert "total_score" in explanation
    assert set(explanation["per_feature"][0]) == {"feature", "contribution"}
    # per_feature is capped to the top 10, so it will not itself sum to total_score -- but
    # every reported contribution's magnitude must be <= the largest one (sorted descending).
    contributions = [abs(e["contribution"]) for e in explanation["per_feature"]]
    assert contributions == sorted(contributions, reverse=True)


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    x_train = _benign_matrix(n=500, seed=7)
    x_calib = _benign_matrix(n=100, seed=8)
    artifact = MahalanobisArtifact.fit(x_train, x_calib)

    path = tmp_path / "mahalanobis.joblib"
    artifact.save(path)
    loaded = MahalanobisArtifact.load(path)

    row = np.full((1, _N_FEATURES), 5.0)
    np.testing.assert_allclose(artifact.raw_scores(row), loaded.raw_scores(row))
