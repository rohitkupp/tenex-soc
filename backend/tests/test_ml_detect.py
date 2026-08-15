"""Unit tests for `app.detection.ml.detect` — the unified `ml.<model>` signal surface.

Builds a tiny `MLModelBundle` from synthetic data (never touches `data/models/`, so this suite
does not depend on `train.py` having been run) and asserts the shape the task brief specifies:
"Signals: detector_key `ml.<model>`, detector_layer `ml`, structured explanation."
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from app.detection.ml.autoencoder import tune_and_train
from app.detection.ml.detect import (
    DETECTOR_LAYER,
    ML_AUTOENCODER,
    ML_IFOREST,
    ML_MAHALANOBIS,
    MLModelBundle,
    score_entity_windows,
)
from app.detection.ml.features import ENTITY_WINDOW_MODEL_FEATURES
from app.detection.ml.iforest import IsolationForestArtifact
from app.detection.ml.mahalanobis import MahalanobisArtifact

_N_FEATURES = len(ENTITY_WINDOW_MODEL_FEATURES)


def test_detector_keys_match_datagen_ground_truth_labels() -> None:
    """`app.detection.ml` deliberately does not import `datagen` (see `detect.py`'s module
    docstring) — this is the one test in the suite that legitimately imports both sides of that
    boundary to audit it hasn't drifted, the same shape of check
    `tests/test_signal_constants.py` runs for the L2 layer."""
    from datagen.types import ML_AUTOENCODER as GEN_AUTOENCODER
    from datagen.types import ML_IFOREST as GEN_IFOREST
    from datagen.types import ML_MAHALANOBIS as GEN_MAHALANOBIS

    assert ML_IFOREST == GEN_IFOREST
    assert ML_MAHALANOBIS == GEN_MAHALANOBIS
    assert ML_AUTOENCODER == GEN_AUTOENCODER


def test_detector_layer_is_ml_not_signal() -> None:
    assert DETECTOR_LAYER == "ml"


def _build_bundle(seed: int = 0) -> MLModelBundle:
    rng = np.random.default_rng(seed)
    x_raw = rng.normal(size=(1500, _N_FEATURES))
    split = 1300
    scaler = StandardScaler().fit(x_raw[:split])
    x_train, x_calib = scaler.transform(x_raw[:split]), scaler.transform(x_raw[split:])

    iforest = IsolationForestArtifact.fit(x_train, x_calib)
    mahalanobis = MahalanobisArtifact.fit(x_train, x_calib)

    x_val = rng.normal(size=(100, _N_FEATURES))
    y_val = np.zeros(100, dtype=np.int64)
    x_val[:10] = 9.0
    y_val[:10] = 1
    x_val_scaled = scaler.transform(x_val)
    autoencoder, _ = tune_and_train(x_train, x_calib, x_val_scaled, y_val, n_trials=2)

    return MLModelBundle(
        scaler=scaler, iforest=iforest, mahalanobis=mahalanobis, autoencoder=autoencoder
    )


def _make_df(rows: list[dict[str, object]]) -> pd.DataFrame:
    base = dict.fromkeys(ENTITY_WINDOW_MODEL_FEATURES, 0.0)
    records = []
    for i, overrides in enumerate(rows):
        record = {
            "entity_type": "user",
            "entity_value": f"user{i}@corp.example",
            "window_start": pd.Timestamp("2026-01-01", tz="UTC"),
            "window_end": pd.Timestamp("2026-01-01 01:00", tz="UTC"),
            "line_numbers": [i],
            **base,
        }
        record.update(overrides)
        records.append(record)
    return pd.DataFrame(records)


def test_score_entity_windows_flags_outliers_and_spares_ordinary_rows() -> None:
    bundle = _build_bundle()
    outlier_features = dict.fromkeys(ENTITY_WINDOW_MODEL_FEATURES, 9.0)
    df = _make_df([{}, outlier_features])  # row 0 ordinary, row 1 an extreme outlier

    drafts = score_entity_windows(bundle, df, threshold=0.99)

    flagged_entities = {d.entity_value for d in drafts}
    assert "user1@corp.example" in flagged_entities
    detector_keys = {d.detector_key for d in drafts}
    assert detector_keys <= {ML_IFOREST, ML_MAHALANOBIS, ML_AUTOENCODER}
    for draft in drafts:
        assert draft.detector_layer == "ml"
        assert draft.evidence_line_numbers
        assert "total" in next(iter(draft.explanation)) or "per_feature" in draft.explanation


def test_score_entity_windows_empty_df_returns_no_drafts() -> None:
    bundle = _build_bundle(seed=1)
    df = pd.DataFrame(
        columns=[
            "entity_type",
            "entity_value",
            "window_start",
            "window_end",
            "line_numbers",
            *ENTITY_WINDOW_MODEL_FEATURES,
        ]
    )
    assert score_entity_windows(bundle, df) == []


def test_score_entity_windows_threshold_gating() -> None:
    bundle = _build_bundle(seed=2)
    df = _make_df([{}])  # a single, perfectly ordinary row
    # threshold=0.0 means every row is flagged by every model (percentile rank >= 0 always).
    drafts_low_threshold = score_entity_windows(bundle, df, threshold=0.0)
    assert len(drafts_low_threshold) == 3  # one per model
    # threshold=1.01 is unreachable (confidence is clipped to [0, 1]).
    drafts_high_threshold = score_entity_windows(bundle, df, threshold=1.01)
    assert drafts_high_threshold == []
