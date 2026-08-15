"""Train all three L3 models on the clean benign corpus (docs/13 M8 acceptance: "All three
trained and benchmarked").

    python -m app.detection.ml.train \\
        --corpus-seed 42 --corpus-events 400000 --corpus-dir /tmp/m8_corpus

## Data provenance — CLI invocation, never a Python import of `datagen`

Every log file this script scores comes from shelling out to `python -m datagen ...` with
`subprocess.run`, using `sys.executable` so the invocation always uses the same interpreter this
script itself is running under. `app.detection.ml` never imports `datagen` as a Python package
(`events.py`'s and `features.py`'s module docstrings both state why); this is that boundary held
even at the one point in this package that must, by design, produce synthetic data to train on.

## Three data splits, three purposes — do not conflate them

1. **Training corpus** (`--corpus-seed`, default 42) — the clean benign corpus (docs/11), split
   by *time* (not randomly) into a training slice and a calibration slice, in that order. Time
   order, not a random shuffle, so the calibration slice is genuinely "what this corpus looks
   like a bit later," not a leak of adjacent hours from the same entity back into its own
   baseline population.
2. **Tuning validation set** (`--tuning-seed`, default 1009) — a small, separately-seeded labeled
   scenario set used *only* inside the autoencoder's Optuna objective (`autoencoder.py`'s module
   docstring explains why MSE alone cannot select hyperparameters for detection quality). Built
   from a subset of scenario keys at reduced volume, purely for speed; never touched by
   `evaluate.py`.
3. **Final eval scenarios** — built separately by `evaluate.py` with its own seed (default 7),
   never referenced here. This script has no knowledge of what `evaluate.py` will score against.

`corpus_seed`, `tuning_seed`, and `evaluate.py`'s own eval seed are three different integers by
construction (asserted below) — on top of `datagen.corpus.role_seed`'s own namespacing
(`"benign"` vs `"eval"` roles), which already makes same-seed reuse produce distinct orgs. Both
guarantees hold independently; this script does not rely on only one of them.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from app.core.logging import configure_logging, get_logger
from app.detection.ml.artifacts import MODELS_DIR, write_feature_manifest
from app.detection.ml.autoencoder import (
    AUTOENCODER_ARTIFACT_FILENAME,
    SCALER_ARTIFACT_FILENAME,
    save_scaler,
    tune_and_train,
)
from app.detection.ml.events import load_ml_events
from app.detection.ml.features import build_entity_window_features, to_feature_matrix
from app.detection.ml.iforest import IFOREST_ARTIFACT_FILENAME, IsolationForestArtifact
from app.detection.ml.mahalanobis import MAHALANOBIS_ARTIFACT_FILENAME, MahalanobisArtifact

log = get_logger(__name__)

# docs/11's ten scenarios; a small, cheap-to-generate subset covering distinct attack shapes
# (volumetric burst, correlation-only, ordering-only-so-expected-to-look-benign-here, cross-
# source) is enough signal for Optuna's val-AUC objective without paying to generate and featurize
# all ten at tuning time. `evaluate.py` still benchmarks against all ten independently.
_TUNING_SCENARIO_KEYS: tuple[str, ...] = (
    "c2_beaconing",
    "data_exfiltration",
    "low_and_slow_exfil",
    "insider_mass_download",
)
_TUNING_SCENARIO_EVENTS = 15_000
_TRAIN_CALIBRATION_SPLIT = 0.9  # fraction of the (time-sorted) corpus rows used for training


def _run_datagen(args: list[str]) -> None:
    # `sys.executable` (not a bare "python" looked up on PATH) and a fixed, hardcoded `-m
    # datagen` module name -- the only variable part of `cmd` is `args`, which every caller in
    # this file builds from this script's own CLI flags (seeds, event counts, output paths),
    # never from unsanitized external input.
    cmd = [sys.executable, "-m", "datagen", *args]
    log.info("datagen.invoke", cmd=cmd)
    subprocess.run(cmd, check=True, cwd=Path(__file__).resolve().parents[3])  # noqa: S603


def _load_corpus_features(corpus_dir: Path) -> pd.DataFrame:
    paths: dict[str, Path] = {}
    zscaler = corpus_dir / "benign_zscaler.log"
    if zscaler.exists():
        paths["zscaler"] = zscaler
    events = load_ml_events(paths)
    log.info("corpus.events_loaded", n_events=len(events))
    df = build_entity_window_features(events)
    log.info("corpus.features_built", n_rows=len(df))
    return df


def _build_tuning_validation(
    tuning_dir: Path, tuning_seed: int, tuning_events: int
) -> tuple[np.ndarray, np.ndarray]:
    """Build the labeled `(X, y)` tuning validation set the Optuna objective scores against.
    `y[i] = 1` iff any of that entity-window's `line_numbers` is malicious per the scenario's own
    `.labels.json`."""
    x_parts: list[np.ndarray] = []
    y_parts: list[np.ndarray] = []
    for key in _TUNING_SCENARIO_KEYS:
        out_dir = tuning_dir / key
        _run_datagen(
            [
                "scenario",
                "--name",
                key,
                "--seed",
                str(tuning_seed),
                "--out",
                str(out_dir),
                "--events",
                str(tuning_events),
            ]
        )
        log_files = sorted(out_dir.glob("*.log"))
        label_files = sorted(out_dir.glob("*.labels.json"))
        malicious_lines: dict[str, set[int]] = {}
        for label_path in label_files:
            payload = json.loads(label_path.read_text(encoding="utf-8"))
            lines = {ln for s in payload["scenarios"] for ln in s["malicious_line_numbers"]}
            malicious_lines[payload["log_file"]] = lines

        paths = {"zscaler": log_files[0]} if log_files else {}
        events = load_ml_events(paths)
        df = build_entity_window_features(events)
        if df.empty:
            continue
        all_malicious = set().union(*malicious_lines.values()) if malicious_lines else set()
        y = df["line_numbers"].apply(lambda lns, mal=all_malicious: any(ln in mal for ln in lns))
        x_parts.append(to_feature_matrix(df))
        y_parts.append(y.to_numpy(dtype=np.int64))

    x = np.concatenate(x_parts, axis=0) if x_parts else np.empty((0, 0))
    y_arr = np.concatenate(y_parts, axis=0) if y_parts else np.empty((0,), dtype=np.int64)
    log.info(
        "tuning_validation.built",
        n_rows=len(y_arr),
        n_positive=int(y_arr.sum()) if len(y_arr) else 0,
    )
    return x, y_arr


def train(
    *,
    corpus_seed: int,
    corpus_events: int,
    corpus_dir: Path,
    tuning_seed: int,
    tuning_dir: Path,
    optuna_trials: int,
    models_dir: Path = MODELS_DIR,
    reuse_corpus: bool = False,
) -> dict[str, Any]:
    assert corpus_seed != tuning_seed, "corpus and tuning-validation seeds must differ"

    t_start = time.perf_counter()

    if not reuse_corpus or not (corpus_dir / "benign_zscaler.log").exists():
        _run_datagen(
            [
                "benign",
                "--events",
                str(corpus_events),
                "--seed",
                str(corpus_seed),
                "--out",
                str(corpus_dir),
            ]
        )

    df = _load_corpus_features(corpus_dir)
    df = df.sort_values("window_start").reset_index(drop=True)
    split_idx = int(len(df) * _TRAIN_CALIBRATION_SPLIT)
    df_train, df_calib = df.iloc[:split_idx], df.iloc[split_idx:]
    log.info("corpus.split", n_train=len(df_train), n_calibration=len(df_calib))

    x_train_raw = to_feature_matrix(df_train)
    x_calib_raw = to_feature_matrix(df_calib)

    scaler = StandardScaler().fit(x_train_raw)
    x_train = scaler.transform(x_train_raw)
    x_calib = scaler.transform(x_calib_raw)

    x_tune_raw, y_tune = _build_tuning_validation(tuning_dir, tuning_seed, _TUNING_SCENARIO_EVENTS)
    x_tune = scaler.transform(x_tune_raw) if len(x_tune_raw) else x_tune_raw

    log.info("iforest.fit.start")
    iforest = IsolationForestArtifact.fit(x_train, x_calib)
    log.info("iforest.fit.done", fit_seconds=round(iforest.fit_seconds, 3))

    log.info("mahalanobis.fit.start")
    mahalanobis = MahalanobisArtifact.fit(x_train, x_calib)
    log.info("mahalanobis.fit.done", fit_seconds=round(mahalanobis.fit_seconds, 3))

    log.info("autoencoder.tune.start", n_trials=optuna_trials)
    autoencoder, optuna_result = tune_and_train(
        x_train, x_calib, x_tune, y_tune, n_trials=optuna_trials
    )
    log.info(
        "autoencoder.tune.done",
        fit_seconds=round(autoencoder.fit_seconds, 3),
        search_seconds=round(optuna_result.search_seconds, 3),
        best_value=round(optuna_result.best_value, 4),
        best_params=optuna_result.best_params,
    )

    models_dir.mkdir(parents=True, exist_ok=True)
    save_scaler(scaler, models_dir / SCALER_ARTIFACT_FILENAME)
    iforest.save(models_dir / IFOREST_ARTIFACT_FILENAME)
    mahalanobis.save(models_dir / MAHALANOBIS_ARTIFACT_FILENAME)
    autoencoder.save(models_dir / AUTOENCODER_ARTIFACT_FILENAME)

    trained_at = datetime.now(UTC).isoformat()
    write_feature_manifest(
        trained_at=trained_at,
        corpus_seed=corpus_seed,
        corpus_n_events=len(df),
        extra={
            "tuning_seed": tuning_seed,
            "n_train_rows": len(df_train),
            "n_calibration_rows": len(df_calib),
            "n_tuning_rows": len(y_tune),
            "iforest_fit_seconds": iforest.fit_seconds,
            "mahalanobis_fit_seconds": mahalanobis.fit_seconds,
            "autoencoder_fit_seconds": autoencoder.fit_seconds,
            "autoencoder_search_seconds": optuna_result.search_seconds,
            "optuna_best_value": optuna_result.best_value,
            "optuna_best_params": optuna_result.best_params,
            "optuna_n_trials": optuna_result.n_trials,
        },
        models_dir=models_dir,
    )

    total_seconds = time.perf_counter() - t_start
    summary = {
        "trained_at": trained_at,
        "corpus_seed": corpus_seed,
        "corpus_events_requested": corpus_events,
        "n_entity_window_rows": len(df),
        "n_train_rows": len(df_train),
        "n_calibration_rows": len(df_calib),
        "tuning_seed": tuning_seed,
        "n_tuning_rows": len(y_tune),
        "n_tuning_positive": int(y_tune.sum()) if len(y_tune) else 0,
        "iforest_fit_seconds": iforest.fit_seconds,
        "mahalanobis_fit_seconds": mahalanobis.fit_seconds,
        "autoencoder_fit_seconds": autoencoder.fit_seconds,
        "autoencoder_search_seconds": optuna_result.search_seconds,
        "optuna_best_value": optuna_result.best_value,
        "optuna_best_params": optuna_result.best_params,
        "optuna_n_trials": optuna_result.n_trials,
        "total_seconds": total_seconds,
    }
    summary_path = models_dir / "train_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    log.info("train.done", total_seconds=round(total_seconds, 2), summary_path=str(summary_path))
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the L3 model bench (docs/04 §L3, M8)")
    parser.add_argument("--corpus-seed", type=int, default=42)
    parser.add_argument("--corpus-events", type=int, default=400_000)
    # Matches the milestone brief's own example invocation verbatim; a scratch directory for a
    # locally-regenerable training corpus is exactly what /tmp is for here, not a security-
    # sensitive temp file.
    parser.add_argument("--corpus-dir", type=Path, default=Path("/tmp/m8_corpus"))  # noqa: S108
    parser.add_argument("--tuning-seed", type=int, default=1009)
    parser.add_argument("--tuning-dir", type=Path, default=Path("/tmp/m8_tuning"))  # noqa: S108
    parser.add_argument("--optuna-trials", type=int, default=50)
    parser.add_argument("--models-dir", type=Path, default=MODELS_DIR)
    parser.add_argument(
        "--reuse-corpus",
        action="store_true",
        help="Skip regenerating the benign corpus if --corpus-dir already has one",
    )
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)
    configure_logging(args.log_level)

    train(
        corpus_seed=args.corpus_seed,
        corpus_events=args.corpus_events,
        corpus_dir=args.corpus_dir,
        tuning_seed=args.tuning_seed,
        tuning_dir=args.tuning_dir,
        optuna_trials=args.optuna_trials,
        models_dir=args.models_dir,
        reuse_corpus=args.reuse_corpus,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
