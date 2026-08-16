"""Train all six L3 models on the clean benign corpus (docs/13 M8/M8b acceptance: "All models
trained and benchmarked"). Was five, and needed a second, separately-seeded labeled "tuning
validation" corpus purely to feed the autoencoder's Optuna hyperparameter search -- migration
change 19 (`docs/v2_migration/MIGRATION-01-evidence-first.md`) removed that model, and the tuning-
validation machinery (`--tuning-seed`/`--tuning-dir`/`--optuna-trials`, `_build_tuning_
validation`) had no other consumer, so it went with it rather than being left as dead code with
nothing left to tune. The other four (now six, with EIF and kth-NN landing per that same
migration's post-migration roster) models fit directly against the benign corpus alone; none of
them needs a second, labeled corpus the way an Optuna val-AUC objective did.

## Full-space vs. PCA — the shipped choice is explicit, recorded here

`ml.kth_nn` and `ml.peer_group` (LOF) are this package's two distance-based models, and migration
change 25's test plan requires them evaluated "full-space vs. PCA" (`dimensionality.py`). This
script fits and saves *both* variants of each: the full-space instance is the one `MLModelBundle`
actually loads and scores with (`detect.py`) — `_SHIPPED_DISTANCE_SPACE` below names that choice
explicitly rather than leaving it an unstated default — and the PCA-space instance is saved
alongside it purely so `evaluate.py` can report the comparison. Neither `detect.py` nor
`MLModelBundle` ever loads the `_pca` artifacts; they exist only for the benchmark.

    python -m app.detection.ml.train \\
        --corpus-seed 42 --corpus-events 400000 --corpus-dir /tmp/m8_corpus

## Data provenance — CLI invocation, never a Python import of `datagen`

Every log file this script scores comes from shelling out to `python -m datagen ...` with
`subprocess.run`, using `sys.executable` so the invocation always uses the same interpreter this
script itself is running under. `app.detection.ml` never imports `datagen` as a Python package
(`events.py`'s and `features.py`'s module docstrings both state why); this is that boundary held
even at the one point in this package that must, by design, produce synthetic data to train on.

## Two data splits, two purposes — do not conflate them

1. **Training corpus** (`--corpus-seed`, default 42) — the clean benign corpus (docs/11), split
   by *time* (not randomly) into a training slice and a calibration slice, in that order. Time
   order, not a random shuffle, so the calibration slice is genuinely "what this corpus looks
   like a bit later," not a leak of adjacent hours from the same entity back into its own
   baseline population.
2. **Final eval scenarios** — built separately by `evaluate.py` with its own seed (default 7),
   never referenced here. This script has no knowledge of what `evaluate.py` will score against.

`corpus_seed` and `evaluate.py`'s own eval seed are different integers by construction (`main`'s
own defaults, 42 vs 7) — on top of `datagen.corpus.role_seed`'s own namespacing (`"benign"` vs
`"eval"` roles), which already makes same-seed reuse produce distinct orgs. Both guarantees hold
independently; this script does not rely on only one of them.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import pandas as pd
from sklearn.preprocessing import StandardScaler

from app.core.logging import configure_logging, get_logger
from app.detection.ml.artifacts import (
    MODELS_DIR,
    SCALER_ARTIFACT_FILENAME,
    save_scaler,
    write_feature_manifest,
)
from app.detection.ml.dimensionality import FeatureSpace
from app.detection.ml.ecod import ECOD_ARTIFACT_FILENAME, ECODArtifact
from app.detection.ml.eif import EIF_ARTIFACT_FILENAME, EIFArtifact
from app.detection.ml.events import load_ml_events
from app.detection.ml.features import build_entity_window_features, to_feature_matrix
from app.detection.ml.iforest import IFOREST_ARTIFACT_FILENAME, IsolationForestArtifact
from app.detection.ml.knn import (
    KNN_ARTIFACT_FILENAME,
    KNN_PCA_ARTIFACT_FILENAME,
    KNNArtifact,
)
from app.detection.ml.lof import (
    LOF_ARTIFACT_FILENAME,
    LOF_PCA_ARTIFACT_FILENAME,
    LOFArtifact,
)
from app.detection.ml.mahalanobis import MAHALANOBIS_ARTIFACT_FILENAME, MahalanobisArtifact

log = get_logger(__name__)

_TRAIN_CALIBRATION_SPLIT = 0.9  # fraction of the (time-sorted) corpus rows used for training

# The explicit, recorded full-space/PCA choice for the shipped `ml.kth_nn`/`ml.peer_group`
# instances that `MLModelBundle` actually loads (module docstring). "full" for now: raw feature
# units stay directly citable in an incident's evidence section (docs/09) without translating a
# PCA loading back into "bytes_out_sum" for an analyst, and there is not yet a benchmark run
# against the real (regenerated) corpus showing PCA-space distance detects anything full-space
# misses that would be worth that interpretability cost. `evaluate.py` scores both spaces so that
# claim is checked, not assumed — see its own "full_vs_pca" result section.
_SHIPPED_DISTANCE_SPACE: Final[FeatureSpace] = "full"


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


def train(
    *,
    corpus_seed: int,
    corpus_events: int,
    corpus_dir: Path,
    models_dir: Path = MODELS_DIR,
    reuse_corpus: bool = False,
) -> dict[str, Any]:
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

    log.info("iforest.fit.start")
    iforest = IsolationForestArtifact.fit(x_train, x_calib)
    log.info("iforest.fit.done", fit_seconds=round(iforest.fit_seconds, 3))

    log.info("mahalanobis.fit.start")
    mahalanobis = MahalanobisArtifact.fit(x_train, x_calib)
    log.info("mahalanobis.fit.done", fit_seconds=round(mahalanobis.fit_seconds, 3))

    log.info("ecod.fit.start")
    ecod = ECODArtifact.fit(x_train, x_calib)
    log.info("ecod.fit.done", fit_seconds=round(ecod.fit_seconds, 3))

    log.info("lof.fit.start")
    lof = LOFArtifact.fit(x_train, x_calib, space=_SHIPPED_DISTANCE_SPACE)
    log.info("lof.fit.done", fit_seconds=round(lof.fit_seconds, 3))

    log.info("eif.fit.start")
    eif = EIFArtifact.fit(x_train, x_calib)
    log.info(
        "eif.fit.done", fit_seconds=round(eif.fit_seconds, 3), extension_level=eif.extension_level
    )

    log.info("kth_nn.fit.start")
    kth_nn = KNNArtifact.fit(x_train, x_calib, space=_SHIPPED_DISTANCE_SPACE)
    log.info("kth_nn.fit.done", fit_seconds=round(kth_nn.fit_seconds, 3))

    # PCA-space variants of the two distance models, fit purely so `evaluate.py` can report
    # "full-space vs. PCA" (module docstring) -- never loaded by `MLModelBundle`/`detect.py`.
    log.info("lof_pca.fit.start")
    lof_pca = LOFArtifact.fit(x_train, x_calib, space="pca")
    log.info(
        "lof_pca.fit.done",
        fit_seconds=round(lof_pca.fit_seconds, 3),
        n_components=lof_pca.pca.n_components if lof_pca.pca else None,
    )

    log.info("kth_nn_pca.fit.start")
    kth_nn_pca = KNNArtifact.fit(x_train, x_calib, space="pca")
    log.info(
        "kth_nn_pca.fit.done",
        fit_seconds=round(kth_nn_pca.fit_seconds, 3),
        n_components=kth_nn_pca.pca.n_components if kth_nn_pca.pca else None,
    )

    models_dir.mkdir(parents=True, exist_ok=True)
    save_scaler(scaler, models_dir / SCALER_ARTIFACT_FILENAME)
    iforest.save(models_dir / IFOREST_ARTIFACT_FILENAME)
    mahalanobis.save(models_dir / MAHALANOBIS_ARTIFACT_FILENAME)
    ecod.save(models_dir / ECOD_ARTIFACT_FILENAME)
    lof.save(models_dir / LOF_ARTIFACT_FILENAME)
    eif.save(models_dir / EIF_ARTIFACT_FILENAME)
    kth_nn.save(models_dir / KNN_ARTIFACT_FILENAME)
    lof_pca.save(models_dir / LOF_PCA_ARTIFACT_FILENAME)
    kth_nn_pca.save(models_dir / KNN_PCA_ARTIFACT_FILENAME)

    trained_at = datetime.now(UTC).isoformat()
    write_feature_manifest(
        trained_at=trained_at,
        corpus_seed=corpus_seed,
        corpus_n_events=len(df),
        extra={
            "n_train_rows": len(df_train),
            "n_calibration_rows": len(df_calib),
            "iforest_fit_seconds": iforest.fit_seconds,
            "mahalanobis_fit_seconds": mahalanobis.fit_seconds,
            "ecod_fit_seconds": ecod.fit_seconds,
            "lof_fit_seconds": lof.fit_seconds,
            "eif_fit_seconds": eif.fit_seconds,
            "eif_extension_level": eif.extension_level,
            "kth_nn_fit_seconds": kth_nn.fit_seconds,
            "shipped_distance_space": _SHIPPED_DISTANCE_SPACE,
            "lof_pca_fit_seconds": lof_pca.fit_seconds,
            "lof_pca_n_components": lof_pca.pca.n_components if lof_pca.pca else None,
            "kth_nn_pca_fit_seconds": kth_nn_pca.fit_seconds,
            "kth_nn_pca_n_components": kth_nn_pca.pca.n_components if kth_nn_pca.pca else None,
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
        "iforest_fit_seconds": iforest.fit_seconds,
        "mahalanobis_fit_seconds": mahalanobis.fit_seconds,
        "ecod_fit_seconds": ecod.fit_seconds,
        "lof_fit_seconds": lof.fit_seconds,
        "eif_fit_seconds": eif.fit_seconds,
        "eif_extension_level": eif.extension_level,
        "kth_nn_fit_seconds": kth_nn.fit_seconds,
        "lof_pca_n_components": lof_pca.pca.n_components if lof_pca.pca else None,
        "kth_nn_pca_n_components": kth_nn_pca.pca.n_components if kth_nn_pca.pca else None,
        "total_seconds": total_seconds,
    }
    summary_path = models_dir / "train_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    log.info("train.done", total_seconds=round(total_seconds, 2), summary_path=str(summary_path))
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the L3 model bench (docs/04 §L3, M8/M8b)")
    parser.add_argument("--corpus-seed", type=int, default=42)
    parser.add_argument("--corpus-events", type=int, default=400_000)
    # Matches the milestone brief's own example invocation verbatim; a scratch directory for a
    # locally-regenerable training corpus is exactly what /tmp is for here, not a security-
    # sensitive temp file.
    parser.add_argument("--corpus-dir", type=Path, default=Path("/tmp/m8_corpus"))  # noqa: S108
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
        models_dir=args.models_dir,
        reuse_corpus=args.reuse_corpus,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
