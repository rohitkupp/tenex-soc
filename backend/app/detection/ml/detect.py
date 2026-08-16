"""Unified scoring surface over all four benchmarked L3 models — `ml.iforest`, `ml.mahalanobis`,
`ml.ecod`, `ml.peer_group` (LOF) (docs/04 §L3 model table), each producing a structured signal in
the shape the task brief specifies: "Signals: detector_key `ml.<model>`, detector_layer `ml`,
structured explanation."

The autoencoder that used to round this bundle out to five models is gone -- migration change 19
(`docs/v2_migration/MIGRATION-01-evidence-first.md`) removed it: its job (joint-distribution
anomalies no single feature's tail exposes) is what EIF's oblique splits are meant to address, and
docs/04 had already committed to "if EIF matches the autoencoder, the autoencoder is cut" before
EIF's own benchmark ran. EIF is a later phase's work, not built here -- this bundle is four models
until it lands.

## Why this is not `app.detection.signal.drafts.SignalDraft`

That dataclass's `to_signal_kwargs()` hardcodes `detector_layer` from
`app.detection.signal.constants.DETECTOR_LAYER`, which is the fixed string `"signal"` (L2's own
layer, not L3's `"ml"`) — reusing it here would silently mislabel every L3 detection as an L2
one. Rather than patch a constant owned by a concurrently-developed sibling package
(`app/detection/signal/**`, explicitly out of this milestone's scope), `MLSignalDraft` below is
this package's own, structurally identical dataclass with `detector_layer` fixed correctly to
`"ml"`.

## Why `evidence_line_numbers`, not `evidence_event_ids`

The live `signals.evidence_event_ids` column (docs/02) references `events.id`, a Postgres
identity assigned when a file is ingested through `app/pipeline`/`app/storage` — out of this
milestone's ownership (see `events.py`'s module docstring). This package's own harness (`train.py`
/ `evaluate.py`) scores plain log files, which have no such ids, only 1-based file line numbers
(the same numbers `GroundTruth.malicious_line_numbers` uses). `evidence_line_numbers` here is
exactly that — a future pipeline integration that persists `signals` rows would map file line
number -> `events.id` via `events.raw_line_no` (docs/02's own hot column for that purpose) at
write time, not something this offline scoring surface can or should do itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import numpy.typing as npt
import pandas as pd
from sklearn.preprocessing import StandardScaler

from app.detection.ml.artifacts import MODELS_DIR, SCALER_ARTIFACT_FILENAME, load_scaler
from app.detection.ml.ecod import ECOD_ARTIFACT_FILENAME, ECODArtifact
from app.detection.ml.features import to_feature_matrix
from app.detection.ml.iforest import IFOREST_ARTIFACT_FILENAME, IsolationForestArtifact
from app.detection.ml.lof import LOF_ARTIFACT_FILENAME, LOFArtifact
from app.detection.ml.mahalanobis import MAHALANOBIS_ARTIFACT_FILENAME, MahalanobisArtifact

__all__ = [
    "DETECTOR_LAYER",
    "ML_ECOD",
    "ML_IFOREST",
    "ML_MAHALANOBIS",
    "ML_PEER_GROUP",
    "SIGNAL_CONFIDENCE_THRESHOLD",
    "MLModelBundle",
    "MLSignalDraft",
    "score_entity_windows",
]

# `datagen.types.ML_IFOREST` / `ML_MAHALANOBIS` / `ML_PEER_GROUP` verbatim (docs/11's scenarios
# already reference these strings in `expected_detectors`) — declared independently here for the
# same reason `app.detection.signal.constants` declares its own `SIGNAL_*` literals rather than
# importing `datagen`: `app/detection/ml/**` must not depend on the synthetic-data generator.
# `tests/test_ml_detect.py` asserts these stay byte-identical to `datagen.types`'s copies.
ML_IFOREST = "ml.iforest"
ML_MAHALANOBIS = "ml.mahalanobis"
# ECOD has no pre-existing forward-referenced name in `datagen.types` to match -- `ml.ecod` is
# this package's own natural key for `pyod.models.ecod`.
ML_ECOD = "ml.ecod"
# LOF ships under `ml.peer_group`, not `ml.lof` -- see `lof.py`'s module docstring for why: this
# is the name docs/04 and the scenario 3/5 ground truth (`datagen.types.ML_PEER_GROUP`) already
# use for "the model LOF formalizes."
ML_PEER_GROUP = "ml.peer_group"
DETECTOR_LAYER = "ml"

# The operating point every model's binary "emit a signal or not" decision uses: this window's
# calibrated confidence (a percentile rank against the benign calibration sample — see each
# model's own docstring) sits above the top 0.5% of ordinary benign entity-windows. docs/04's own
# 99.5th-percentile convention, so every model is held to the same "how unusual is unusual
# enough" bar, deliberately fixed once here rather than tuned per model to flatter one model's F1
# in `evals/results.md`.
SIGNAL_CONFIDENCE_THRESHOLD = 0.995


@dataclass(slots=True)
class MLSignalDraft:
    """One L3 model's finding for one `(entity, hour)` window. See module docstring for why this
    is not `app.detection.signal.drafts.SignalDraft`."""

    detector_key: str
    detector_layer: str
    entity_type: str
    entity_value: str
    raw_score: float
    confidence: float
    window_start: pd.Timestamp
    window_end: pd.Timestamp
    evidence_line_numbers: list[int]
    explanation: dict[str, Any]
    mitre_technique: str | None = None


@dataclass(slots=True)
class MLModelBundle:
    """Every artifact `train.py` writes, loaded together — `detect.py`'s and `evaluate.py`'s
    shared entrypoint so neither re-derives the `data/models/` layout independently."""

    scaler: StandardScaler
    iforest: IsolationForestArtifact
    mahalanobis: MahalanobisArtifact
    ecod: ECODArtifact
    lof: LOFArtifact

    @classmethod
    def load(cls, models_dir: Path = MODELS_DIR) -> MLModelBundle:
        return cls(
            scaler=load_scaler(models_dir / SCALER_ARTIFACT_FILENAME),
            iforest=IsolationForestArtifact.load(models_dir / IFOREST_ARTIFACT_FILENAME),
            mahalanobis=MahalanobisArtifact.load(models_dir / MAHALANOBIS_ARTIFACT_FILENAME),
            ecod=ECODArtifact.load(models_dir / ECOD_ARTIFACT_FILENAME),
            lof=LOFArtifact.load(models_dir / LOF_ARTIFACT_FILENAME),
        )

    def transform(self, df: pd.DataFrame) -> npt.NDArray[np.float64]:
        """`df` (from `build_entity_window_features`) -> the scaled matrix every model scores."""
        raw = to_feature_matrix(df)
        scaled: npt.NDArray[np.float64] = self.scaler.transform(raw)
        return scaled


def _rows_to_drafts(
    df: pd.DataFrame,
    x_scaled: npt.NDArray[np.float64],
    *,
    detector_key: str,
    raw_scores: npt.NDArray[np.float64],
    confidences: npt.NDArray[np.float64],
    explain_row: Any,
    threshold: float,
) -> list[MLSignalDraft]:
    drafts: list[MLSignalDraft] = []
    for i in range(len(df)):
        if confidences[i] < threshold:
            continue
        row = df.iloc[i]
        drafts.append(
            MLSignalDraft(
                detector_key=detector_key,
                detector_layer=DETECTOR_LAYER,
                entity_type=row["entity_type"],
                entity_value=row["entity_value"],
                raw_score=float(raw_scores[i]),
                confidence=float(confidences[i]),
                window_start=row["window_start"],
                window_end=row["window_end"],
                evidence_line_numbers=list(row["line_numbers"]),
                explanation=explain_row(x_scaled[i]),
            )
        )
    return drafts


def score_entity_windows(
    bundle: MLModelBundle,
    df: pd.DataFrame,
    *,
    threshold: float = SIGNAL_CONFIDENCE_THRESHOLD,
) -> list[MLSignalDraft]:
    """Score every `(entity, hour)` row in `df` (from `build_entity_window_features`) against all
    four models, returning one `MLSignalDraft` per (model, row) pair whose confidence clears
    `threshold`. `evaluate.py` instead calls each model's `raw_scores`/`confidence` directly over
    the *entire* `df` (thresholded and unthresholded) to compute AUC-PR/F1/recall — this function
    is the "what would actually get written as a signal" view, analogous to what a live pipeline
    integration would persist.
    """
    if df.empty:
        return []
    x_scaled = bundle.transform(df)

    drafts: list[MLSignalDraft] = []
    for detector_key, model in (
        (ML_IFOREST, bundle.iforest),
        (ML_MAHALANOBIS, bundle.mahalanobis),
        (ML_ECOD, bundle.ecod),
        (ML_PEER_GROUP, bundle.lof),
    ):
        raw = model.raw_scores(x_scaled)
        conf = model.confidence(raw)
        drafts += _rows_to_drafts(
            df,
            x_scaled,
            detector_key=detector_key,
            raw_scores=raw,
            confidences=conf,
            explain_row=model.explain_row,
            threshold=threshold,
        )
    return drafts
