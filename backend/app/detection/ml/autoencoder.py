"""`ml.autoencoder` — PyTorch reconstruction-error model (docs/04 §L3 model table).

`50 -> 32 -> 16 -> 8 -> 16 -> 32 -> 50`, ReLU, MSE, is the doc's specified default shape — the
depth/latent-dim search space `tune` explores (see `_HIDDEN_SIZES_BY_DEPTH`) is centered on
exactly that shape (`depth=3, latent_dim=8` reproduces it verbatim) rather than a shape unrelated
to it. `StandardScaler` (fit on the benign training split only) is persisted with the model, per
docs/04, so a future load never risks scoring raw-scale features through weights fit on
standardized ones.

## Why the nonlinear model here, specifically

The other two L3 models are linear in a real sense — `ml.iforest` partitions on individual
feature thresholds, `ml.mahalanobis` scores distance under a single fixed covariance matrix.
Reconstruction error under a bottlenecked nonlinear encoder/decoder can, in principle, capture
correlation structure a linear covariance model cannot (a manifold, not just an ellipsoid) — which
is the entire justification for training a neural net at all here rather than shipping two models.
Whether that theoretical edge shows up as a real win on `evals/results.md`'s numbers is exactly
what this milestone benchmarks; CLAUDE.md is explicit that losing is a valid, reportable outcome.

## Optuna objective — a labeled *tuning* validation set, deliberately separate from the eval set

docs/04: "Optuna over: latent dim, depth, dropout, LR, batch size, epochs. 50 trials, objective =
val AUC on held-out labeled scenarios." Reconstruction-error MSE alone (the model's own training
loss) cannot select hyperparameters for *detection* quality — a model that reconstructs
everything perfectly, benign and attack alike, has zero loss and zero discriminative power. Optuna
therefore needs labeled anomalies to score against. Using the *final* eval scenarios
(`evals/results.md`'s benchmark set) for that would let hyperparameter search overfit to the exact
data the benchmark reports on — the tuning validation set `train.py` builds is a separate,
smaller, differently-seeded labeled corpus, generated and used only inside `tune`, never touched
by `evaluate.py`. See `train.py`'s module docstring for the concrete seed/org split.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import numpy.typing as npt
import optuna
import torch
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler
from torch import nn

from app.detection.ml.features import ENTITY_WINDOW_MODEL_FEATURES, sanitize_scores

__all__ = [
    "AUTOENCODER_ARTIFACT_FILENAME",
    "SCALER_ARTIFACT_FILENAME",
    "AutoencoderArtifact",
    "AutoencoderConfig",
    "OptunaResult",
    "tune_and_train",
]

AUTOENCODER_ARTIFACT_FILENAME = "autoencoder.pt"
SCALER_ARTIFACT_FILENAME = "scaler.joblib"

_INPUT_DIM = len(ENTITY_WINDOW_MODEL_FEATURES)
_THRESHOLD_PERCENTILE = 99.5
_TOP_K_EXPLANATION = 10
_OPTUNA_N_TRIALS = 50
# Optuna's own search trains on a bounded subsample for speed (module docstring); the *final*
# artifact is retrained on the full benign training split afterward (`tune_and_train`).
_TUNE_SUBSAMPLE_ROWS = 15_000
_RANDOM_STATE = 42

# Encoder hidden-layer sizes leading into the tuned latent dimension, keyed by `depth`.
# `depth=3` with the default `latent_dim=8` reproduces docs/04's `50->32->16->8->...` exactly;
# the other depths are bounded perturbations of the same shape, not an unrelated architecture.
_HIDDEN_SIZES_BY_DEPTH: dict[int, tuple[int, ...]] = {
    2: (32,),
    3: (32, 16),
    4: (32, 24, 16),
}

torch.manual_seed(_RANDOM_STATE)


@dataclass(frozen=True, slots=True)
class AutoencoderConfig:
    latent_dim: int = 8
    depth: int = 3
    dropout: float = 0.1
    lr: float = 1e-3
    batch_size: int = 256
    epochs: int = 40
    weight_decay: float = 1e-5

    def to_dict(self) -> dict[str, float]:
        return {
            "latent_dim": self.latent_dim,
            "depth": self.depth,
            "dropout": self.dropout,
            "lr": self.lr,
            "batch_size": self.batch_size,
            "epochs": self.epochs,
            "weight_decay": self.weight_decay,
        }


class _Autoencoder(nn.Module):
    """Symmetric encoder/decoder, ReLU activations, dropout between hidden layers, linear
    (unbounded) output layer — the reconstruction target is standardized features, which are
    not bounded to `[0, 1]`."""

    def __init__(self, config: AutoencoderConfig, input_dim: int = _INPUT_DIM) -> None:
        super().__init__()
        hidden = [*list(_HIDDEN_SIZES_BY_DEPTH[config.depth]), config.latent_dim]

        encoder_layers: list[nn.Module] = []
        prev = input_dim
        for size in hidden:
            encoder_layers += [nn.Linear(prev, size), nn.ReLU(), nn.Dropout(config.dropout)]
            prev = size
        self.encoder = nn.Sequential(*encoder_layers)

        decoder_sizes = [*list(reversed(hidden[:-1])), input_dim]
        decoder_layers: list[nn.Module] = []
        prev = config.latent_dim
        for i, size in enumerate(decoder_sizes):
            decoder_layers.append(nn.Linear(prev, size))
            if i < len(decoder_sizes) - 1:
                decoder_layers += [nn.ReLU(), nn.Dropout(config.dropout)]
            prev = size
        self.decoder = nn.Sequential(*decoder_layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out: torch.Tensor = self.decoder(self.encoder(x))
        return out


def _train_loop(
    model: _Autoencoder, x_train: npt.NDArray[np.float64], config: AutoencoderConfig
) -> None:
    model.train()
    x_tensor = torch.as_tensor(x_train, dtype=torch.float32)
    optimizer = torch.optim.Adam(model.parameters(), lr=config.lr, weight_decay=config.weight_decay)
    loss_fn = nn.MSELoss()
    n = x_tensor.shape[0]
    generator = torch.Generator().manual_seed(_RANDOM_STATE)
    for _epoch in range(config.epochs):
        perm = torch.randperm(n, generator=generator)
        for start in range(0, n, config.batch_size):
            batch = x_tensor[perm[start : start + config.batch_size]]
            optimizer.zero_grad()
            loss = loss_fn(model(batch), batch)
            loss.backward()
            optimizer.step()


def _reconstruction_errors(
    model: _Autoencoder, x: npt.NDArray[np.float64]
) -> npt.NDArray[np.float64]:
    """Per-row, per-feature squared error (not yet summed) — `(n_rows, n_features)`."""
    model.eval()
    with torch.no_grad():
        x_tensor = torch.as_tensor(x, dtype=torch.float32)
        recon = model(x_tensor)
        errors: npt.NDArray[np.float64] = ((x_tensor - recon) ** 2).numpy().astype(np.float64)
    return errors


@dataclass(frozen=True, slots=True)
class OptunaResult:
    """Reported verbatim in `evals/results.md` (task brief: "Report ... Optuna's best trial")."""

    best_value: float
    best_params: dict[str, Any]
    n_trials: int
    search_seconds: float


def _objective(
    trial: optuna.Trial,
    x_train_tune: npt.NDArray[np.float64],
    x_val: npt.NDArray[np.float64],
    y_val: npt.NDArray[np.int64],
) -> float:
    config = AutoencoderConfig(
        latent_dim=trial.suggest_categorical("latent_dim", [4, 8, 16]),
        depth=trial.suggest_categorical("depth", [2, 3, 4]),
        dropout=trial.suggest_float("dropout", 0.0, 0.3),
        lr=trial.suggest_float("lr", 1e-4, 1e-2, log=True),
        batch_size=trial.suggest_categorical("batch_size", [128, 256, 512]),
        epochs=trial.suggest_int("epochs", 10, 50),
        weight_decay=trial.suggest_float("weight_decay", 1e-6, 1e-3, log=True),
    )
    model = _Autoencoder(config)
    _train_loop(model, x_train_tune, config)
    errors = _reconstruction_errors(model, x_val).sum(axis=1)
    if len(np.unique(y_val)) < 2:
        return 0.0
    auc: float = roc_auc_score(y_val, errors)
    return auc


def tune_and_train(
    x_train: npt.NDArray[np.float64],
    x_calibration: npt.NDArray[np.float64],
    x_val_labeled: npt.NDArray[np.float64],
    y_val_labeled: npt.NDArray[np.int64],
    *,
    feature_names: tuple[str, ...] = ENTITY_WINDOW_MODEL_FEATURES,
    n_trials: int = _OPTUNA_N_TRIALS,
    random_state: int = _RANDOM_STATE,
) -> tuple[AutoencoderArtifact, OptunaResult]:
    """Run the Optuna search (module docstring), then retrain the winning config on the *full*
    `x_train` (the search itself subsamples for speed — see `_TUNE_SUBSAMPLE_ROWS`) before
    computing per-feature thresholds and benign calibration scores.
    """
    rng = np.random.default_rng(random_state)
    tune_rows = x_train
    if x_train.shape[0] > _TUNE_SUBSAMPLE_ROWS:
        idx = rng.choice(x_train.shape[0], size=_TUNE_SUBSAMPLE_ROWS, replace=False)
        tune_rows = x_train[idx]

    sampler = optuna.samplers.TPESampler(seed=random_state)
    study = optuna.create_study(direction="maximize", sampler=sampler)
    t0 = time.perf_counter()
    study.optimize(
        lambda trial: _objective(trial, tune_rows, x_val_labeled, y_val_labeled),
        n_trials=n_trials,
        show_progress_bar=False,
    )
    search_seconds = time.perf_counter() - t0

    best_config = AutoencoderConfig(
        latent_dim=study.best_params["latent_dim"],
        depth=study.best_params["depth"],
        dropout=study.best_params["dropout"],
        lr=study.best_params["lr"],
        batch_size=study.best_params["batch_size"],
        epochs=study.best_params["epochs"],
        weight_decay=study.best_params["weight_decay"],
    )
    optuna_result = OptunaResult(
        best_value=study.best_value,
        best_params=dict(study.best_params),
        n_trials=len(study.trials),
        search_seconds=search_seconds,
    )

    t1 = time.perf_counter()
    final_model = _Autoencoder(best_config)
    _train_loop(final_model, x_train, best_config)
    fit_seconds = time.perf_counter() - t1

    calib_errors = _reconstruction_errors(final_model, x_calibration)
    per_feature_errors = np.abs(x_calibration - _reconstruct(final_model, x_calibration))
    thresholds = np.percentile(per_feature_errors, _THRESHOLD_PERCENTILE, axis=0)
    calibration_scores = np.sort(calib_errors.sum(axis=1))

    artifact = AutoencoderArtifact(
        model=final_model,
        config=best_config,
        feature_names=feature_names,
        thresholds=thresholds,
        calibration_scores=calibration_scores,
        fit_seconds=fit_seconds,
    )
    return artifact, optuna_result


def _reconstruct(model: _Autoencoder, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
    model.eval()
    with torch.no_grad():
        recon: npt.NDArray[np.float64] = (
            model(torch.as_tensor(x, dtype=torch.float32)).numpy().astype(np.float64)
        )
    return recon


@dataclass(slots=True)
class AutoencoderArtifact:
    model: _Autoencoder
    config: AutoencoderConfig
    feature_names: tuple[str, ...]
    thresholds: npt.NDArray[np.float64]
    calibration_scores: npt.NDArray[np.float64]
    fit_seconds: float

    def raw_scores(self, x: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
        """Total reconstruction error (summed squared per-feature error) per row — higher means
        more anomalous, matching the sign convention every model in this package uses.
        `sanitize_scores` is cheap defense-in-depth (matches `ml.mahalanobis`)."""
        result: npt.NDArray[np.float64] = sanitize_scores(
            _reconstruction_errors(self.model, x).sum(axis=1)
        )
        return result

    def confidence(self, raw_scores: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
        n = len(self.calibration_scores)
        if n == 0:
            return np.zeros_like(raw_scores)
        ranks = np.searchsorted(self.calibration_scores, raw_scores, side="right")
        return np.clip(ranks / n, 0.0, 1.0)

    def explain_row(self, x_row: npt.NDArray[np.float64]) -> dict[str, Any]:
        """`{total_recon_error, per_feature: [{feature, error, threshold, exceeded}]}`, sorted
        by `error` descending — the exact shape docs/04 specifies: "this is what the UI renders
        as 'why this was flagged'."
        """
        recon = _reconstruct(self.model, x_row.reshape(1, -1))[0]
        errors = np.abs(x_row - recon)
        order = np.argsort(-errors)
        per_feature = [
            {
                "feature": self.feature_names[i],
                "error": float(errors[i]),
                "threshold": float(self.thresholds[i]),
                "exceeded": bool(errors[i] > self.thresholds[i]),
            }
            for i in order
        ][:_TOP_K_EXPLANATION]
        return {
            "total_recon_error": float((errors**2).sum()),
            "per_feature": per_feature,
        }

    def save(self, model_path: Path) -> None:
        model_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "state_dict": self.model.state_dict(),
                "config": self.config.to_dict(),
                "feature_names": self.feature_names,
                "thresholds": self.thresholds,
                "calibration_scores": self.calibration_scores,
                "fit_seconds": self.fit_seconds,
            },
            model_path,
        )

    @classmethod
    def load(cls, model_path: Path) -> AutoencoderArtifact:
        payload = torch.load(model_path, weights_only=False)
        config = AutoencoderConfig(**payload["config"])
        model = _Autoencoder(config)
        model.load_state_dict(payload["state_dict"])
        model.eval()
        return cls(
            model=model,
            config=config,
            feature_names=tuple(payload["feature_names"]),
            thresholds=payload["thresholds"],
            calibration_scores=payload["calibration_scores"],
            fit_seconds=payload["fit_seconds"],
        )


def save_scaler(scaler: StandardScaler, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, path)


def load_scaler(path: Path) -> StandardScaler:
    scaler: StandardScaler = joblib.load(path)
    return scaler
