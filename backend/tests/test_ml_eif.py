"""Unit tests for `app.detection.ml.eif` (`ExtendedIsolationForest`/`EIFArtifact`, hand-rolled --
see that module's docstring for why there is no third-party package underneath it). Same shape as
`test_ml_iforest.py`/`test_ml_ecod.py` for the baseline fire/no-fire + determinism fixtures, plus
two fixtures specific to *why EIF exists at all* (docs/v2_migration change 19's post-migration
roster): the `extension_level=0` axis-parallel-equivalence knob, and a correlation-only anomaly
that axis-parallel splitting structurally struggles with but a single oblique cut isolates easily.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from app.detection.ml.eif import EIFArtifact, _InternalNode, _LeafNode

_N_FEATURES = 50


def _benign_matrix(n: int = 2000, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.normal(size=(n, _N_FEATURES))


def _diagonal_benign_matrix(n: int, seed: int, n_features: int = 20) -> np.ndarray:
    """A population that lives almost entirely on the `x0 == x1` diagonal (small orthogonal
    noise), with every other feature uninformative noise. Anomalous points *off* that diagonal
    are not marginally extreme in `x0` or `x1` individually (both stay within a few ordinary
    standard deviations of their own marginal distribution) but sit far outside the population in
    the direction orthogonal to the diagonal -- the joint-distribution shape EIF's oblique splits
    exist to catch and axis-parallel splitting is structurally slow to isolate."""
    rng = np.random.default_rng(seed)
    t = rng.normal(scale=3.0, size=n)
    x = np.zeros((n, n_features))
    x[:, 0] = t + rng.normal(scale=0.3, size=n)
    x[:, 1] = t + rng.normal(scale=0.3, size=n)
    x[:, 2:] = rng.normal(scale=1.0, size=(n, n_features - 2))
    return x


def _count_normal_nonzero(node: object, counts: list[int]) -> None:
    """Walk every internal node of a fitted tree, recording how many non-zero components its
    splitting hyperplane's normal vector has."""
    if isinstance(node, _InternalNode):
        counts.append(int(np.count_nonzero(node.normal)))
        _count_normal_nonzero(node.left, counts)
        _count_normal_nonzero(node.right, counts)
    elif not isinstance(node, _LeafNode):  # pragma: no cover - defensive, should be unreachable
        raise TypeError(f"unexpected node type {type(node)!r}")


def test_marginal_outlier_scores_higher_than_inlier() -> None:
    x_train = _benign_matrix(seed=1)
    x_calib = _benign_matrix(n=300, seed=2)
    artifact = EIFArtifact.fit(x_train, x_calib)

    inlier = np.zeros((1, _N_FEATURES))
    outlier = np.full((1, _N_FEATURES), 12.0)

    inlier_score = artifact.raw_scores(inlier)[0]
    outlier_score = artifact.raw_scores(outlier)[0]
    assert outlier_score > inlier_score


def test_ordinary_row_gets_low_confidence_and_extreme_row_gets_high_confidence() -> None:
    x_train = _benign_matrix(seed=3)
    x_calib = _benign_matrix(n=500, seed=4)
    artifact = EIFArtifact.fit(x_train, x_calib)

    ordinary = np.zeros((1, _N_FEATURES))
    extreme = np.full((1, _N_FEATURES), 15.0)

    ordinary_conf = artifact.confidence(artifact.raw_scores(ordinary))[0]
    extreme_conf = artifact.confidence(artifact.raw_scores(extreme))[0]
    assert ordinary_conf < 0.9
    assert extreme_conf > 0.99


def test_raw_scores_are_deterministic_across_repeated_fits() -> None:
    """Seeded end-to-end: refitting from scratch on the same data with the same `random_state`
    must reproduce the same scores (CLAUDE.md: "the same input file must produce the same
    signals") -- unlike `ml.ecod` (parameter-free, no seed at all), EIF's subsampling and random
    hyperplanes make this a real determinism claim to verify, not a vacuous one."""
    x_train = _benign_matrix(seed=5)
    x_calib = _benign_matrix(n=200, seed=6)
    row = np.full((1, _N_FEATURES), 7.0)

    first = EIFArtifact.fit(x_train, x_calib)
    second = EIFArtifact.fit(x_train, x_calib)

    np.testing.assert_array_equal(first.raw_scores(row), second.raw_scores(row))


def test_extension_level_zero_splits_exactly_one_feature_per_node() -> None:
    """docs/v2_migration change 19's "does obliqueness help" knob: `extension_level=0` must
    restrict every split to exactly one non-zero hyperplane component -- structurally equivalent
    to axis-parallel (ordinary) isolation, not merely "happens to score similarly" on one input.
    """
    x_train = _benign_matrix(n=500, seed=7)
    x_calib = _benign_matrix(n=100, seed=8)
    artifact = EIFArtifact.fit(x_train, x_calib, extension_level=0)

    assert artifact.extension_level == 0
    nonzero_counts: list[int] = []
    for tree in artifact.model.trees:
        _count_normal_nonzero(tree, nonzero_counts)

    assert nonzero_counts  # the fitted forest actually has internal (non-leaf) nodes to check
    assert all(count == 1 for count in nonzero_counts)


def test_extension_level_fully_oblique_uses_every_feature_by_default() -> None:
    """The complementary check: leaving `extension_level` unset resolves to `d - 1` (fully
    oblique, module docstring) -- most internal nodes' hyperplanes should use more than one
    feature, the opposite of the axis-parallel case above."""
    x_train = _benign_matrix(n=500, seed=9)
    x_calib = _benign_matrix(n=100, seed=10)
    artifact = EIFArtifact.fit(x_train, x_calib)

    assert artifact.extension_level == _N_FEATURES - 1
    nonzero_counts: list[int] = []
    for tree in artifact.model.trees:
        _count_normal_nonzero(tree, nonzero_counts)

    assert nonzero_counts
    # Every non-zero draw from a 50-dim standard normal is non-zero with probability 1 in exact
    # arithmetic; floating point never lands exactly on zero either, so every count should be the
    # full feature count at extension_level = d - 1.
    assert all(count == _N_FEATURES for count in nonzero_counts)


def test_oblique_splits_detect_a_diagonal_anomaly_axis_parallel_misses() -> None:
    """The case that justifies EIF existing at all (docs/v2_migration change 19; docs/04's own
    "if EIF matches the autoencoder, the autoencoder is cut" bet): a point anomalous only in the
    direction orthogonal to a diagonal (correlated) benign population, not marginally extreme in
    any single feature. Same architecture, same training population, same seed -- the only
    variable is `extension_level` -- so a score difference is attributable to obliqueness itself.
    """
    n_features = 20
    x_train = _diagonal_benign_matrix(2000, seed=100, n_features=n_features)
    x_calib = _diagonal_benign_matrix(400, seed=101, n_features=n_features)

    anomaly = np.zeros((1, n_features))
    anomaly[0, 0] = 6.0
    anomaly[0, 1] = -6.0
    # Confirm the anomaly is *not* a marginal outlier in either individual feature -- it must be
    # the joint (off-diagonal) combination doing the work, not a single feature's own tail.
    assert (x_train[:, 0] < anomaly[0, 0]).mean() < 0.99
    assert (x_train[:, 1] > anomaly[0, 1]).mean() < 0.99

    axis_parallel = EIFArtifact.fit(x_train, x_calib, extension_level=0, random_state=42)
    fully_oblique = EIFArtifact.fit(
        x_train, x_calib, extension_level=n_features - 1, random_state=42
    )

    axis_conf = axis_parallel.confidence(axis_parallel.raw_scores(anomaly))[0]
    oblique_conf = fully_oblique.confidence(fully_oblique.raw_scores(anomaly))[0]
    axis_score = axis_parallel.raw_scores(anomaly)[0]
    oblique_score = fully_oblique.raw_scores(anomaly)[0]

    assert oblique_score > axis_score
    assert oblique_conf > 0.9  # fully oblique flags it, well above the operating threshold
    assert axis_conf < 0.1  # axis-parallel splitting is structurally slow to isolate it


def test_explain_row_shape() -> None:
    x_train = _benign_matrix(seed=5)
    x_calib = _benign_matrix(n=200, seed=6)
    artifact = EIFArtifact.fit(x_train, x_calib)

    outlier = np.full(_N_FEATURES, 10.0)
    explanation = artifact.explain_row(outlier)

    assert "total_score" in explanation
    assert "per_feature" in explanation
    assert len(explanation["per_feature"]) <= 10
    for entry in explanation["per_feature"]:
        assert set(entry) == {"feature", "contribution"}
    contributions = [abs(e["contribution"]) for e in explanation["per_feature"]]
    assert contributions == sorted(contributions, reverse=True)
    # Honestly not SHAP (module docstring) -- no claim that per-feature terms sum to total_score.
    assert isinstance(explanation["total_score"], float)


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    x_train = _benign_matrix(n=500, seed=7)
    x_calib = _benign_matrix(n=100, seed=8)
    # Fewer trees than the shipped default -- this test is about save/load correctness, not
    # detection quality, and a full 200-tree forest serializes tens of thousands of small
    # per-node numpy arrays (`normal`/`point`), which is needless joblib overhead here.
    artifact = EIFArtifact.fit(x_train, x_calib, n_estimators=20)

    path = tmp_path / "eif.joblib"
    artifact.save(path)
    loaded = EIFArtifact.load(path)

    row = np.full((1, _N_FEATURES), 5.0)
    np.testing.assert_allclose(artifact.raw_scores(row), loaded.raw_scores(row))
    assert loaded.feature_names == artifact.feature_names
    assert loaded.extension_level == artifact.extension_level


def test_invalid_extension_level_rejected() -> None:
    x_train = _benign_matrix(n=200, seed=11)
    x_calib = _benign_matrix(n=50, seed=12)
    try:
        EIFArtifact.fit(x_train, x_calib, extension_level=_N_FEATURES)
    except ValueError:
        pass
    else:
        raise AssertionError("extension_level == d should be rejected (max is d - 1)")
