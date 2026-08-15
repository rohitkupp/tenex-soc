"""Unit tests for `app.detection.ml.autoencoder`. Uses a tiny Optuna trial budget (2-3 trials,
few epochs) -- these tests check wiring and contract shape, not tuning quality; `evals/results.md`
is where real-scale tuning quality is reported against the full benchmark.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from app.detection.ml.autoencoder import (
    AutoencoderConfig,
    _Autoencoder,
    _train_loop,
    tune_and_train,
)

_N_FEATURES = 50


def _benign_matrix(n: int, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.normal(size=(n, _N_FEATURES)).astype(np.float64)


def test_default_config_reproduces_docs04_architecture_shape() -> None:
    config = AutoencoderConfig()  # latent_dim=8, depth=3 -- docs/04's 50->32->16->8->16->32->50
    model = _Autoencoder(config, input_dim=_N_FEATURES)
    encoder_linears = [m for m in model.encoder if hasattr(m, "out_features")]
    sizes = [layer.out_features for layer in encoder_linears]
    assert sizes == [32, 16, 8]


def test_training_reduces_reconstruction_loss() -> None:
    x = _benign_matrix(1000, seed=1)
    config = AutoencoderConfig(epochs=5, batch_size=128)
    model = _Autoencoder(config, input_dim=_N_FEATURES)

    import torch

    with torch.no_grad():
        x_tensor = torch.as_tensor(x, dtype=torch.float32)
        loss_before = float(((x_tensor - model(x_tensor)) ** 2).mean())

    _train_loop(model, x, config)

    with torch.no_grad():
        loss_after = float(((x_tensor - model(x_tensor)) ** 2).mean())

    assert loss_after < loss_before


def test_tune_and_train_end_to_end_with_a_labeled_validation_set() -> None:
    rng = np.random.default_rng(2)
    x_train = _benign_matrix(600, seed=3)
    x_calib = _benign_matrix(150, seed=4)

    # A small labeled tuning-validation set: mostly benign, a handful of clear outliers.
    n_val = 100
    x_val = rng.normal(size=(n_val, _N_FEATURES)).astype(np.float64)
    y_val = np.zeros(n_val, dtype=np.int64)
    x_val[:10] = 10.0  # obvious outliers
    y_val[:10] = 1

    artifact, optuna_result = tune_and_train(x_train, x_calib, x_val, y_val, n_trials=3)

    assert optuna_result.n_trials == 3
    assert 0.0 <= optuna_result.best_value <= 1.0
    assert artifact.thresholds.shape == (_N_FEATURES,)
    assert artifact.fit_seconds >= 0.0


def test_explain_row_shape_matches_docs04_spec() -> None:
    x_train = _benign_matrix(500, seed=5)
    x_calib = _benign_matrix(120, seed=6)
    x_val = _benign_matrix(60, seed=7)
    y_val = np.zeros(60, dtype=np.int64)
    y_val[:6] = 1
    x_val[:6] = 8.0

    artifact, _ = tune_and_train(x_train, x_calib, x_val, y_val, n_trials=2)

    outlier_row = np.full(_N_FEATURES, 8.0)
    explanation = artifact.explain_row(outlier_row)

    assert set(explanation) == {"total_recon_error", "per_feature"}
    assert len(explanation["per_feature"]) <= 10
    for entry in explanation["per_feature"]:
        assert set(entry) == {"feature", "error", "threshold", "exceeded"}
        assert entry["exceeded"] == (entry["error"] > entry["threshold"])
    errors = [e["error"] for e in explanation["per_feature"]]
    assert errors == sorted(errors, reverse=True)  # sorted descending, per docs/04


def test_outlier_has_higher_reconstruction_error_than_typical_benign_row() -> None:
    x_train = _benign_matrix(800, seed=8)
    x_calib = _benign_matrix(150, seed=9)
    x_val = _benign_matrix(80, seed=10)
    y_val = np.zeros(80, dtype=np.int64)
    y_val[:8] = 1
    x_val[:8] = 9.0

    artifact, _ = tune_and_train(x_train, x_calib, x_val, y_val, n_trials=2)

    typical = np.zeros((1, _N_FEATURES))
    outlier = np.full((1, _N_FEATURES), 9.0)
    assert artifact.raw_scores(outlier)[0] > artifact.raw_scores(typical)[0]


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    x_train = _benign_matrix(400, seed=11)
    x_calib = _benign_matrix(100, seed=12)
    x_val = _benign_matrix(50, seed=13)
    y_val = np.zeros(50, dtype=np.int64)
    y_val[:5] = 1
    x_val[:5] = 7.0

    artifact, _ = tune_and_train(x_train, x_calib, x_val, y_val, n_trials=2)
    path = tmp_path / "autoencoder.pt"
    artifact.save(path)

    from app.detection.ml.autoencoder import AutoencoderArtifact

    loaded = AutoencoderArtifact.load(path)
    row = np.full((1, _N_FEATURES), 4.0)
    np.testing.assert_allclose(artifact.raw_scores(row), loaded.raw_scores(row), rtol=1e-5)
    np.testing.assert_array_equal(artifact.thresholds, loaded.thresholds)
