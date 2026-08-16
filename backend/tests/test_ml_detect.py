"""Unit tests for `app.detection.ml.detect` — the unified `ml.<model>` signal surface.

Builds a tiny `MLModelBundle` from synthetic data (never touches `data/models/`, so this suite
does not depend on `train.py` having been run) and asserts the shape the task brief specifies:
"Signals: detector_key `ml.<model>`, detector_layer `ml`, structured explanation."
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from app.detection.ml.detect import (
    DETECTOR_LAYER,
    ML_ECOD,
    ML_EIF,
    ML_IFOREST,
    ML_KTH_NN,
    ML_MAHALANOBIS,
    ML_PEER_GROUP,
    MLModelBundle,
    score_entity_windows,
)
from app.detection.ml.ecod import ECODArtifact
from app.detection.ml.eif import EIFArtifact
from app.detection.ml.features import ENTITY_WINDOW_MODEL_FEATURES
from app.detection.ml.iforest import IsolationForestArtifact
from app.detection.ml.knn import KNNArtifact
from app.detection.ml.lof import LOFArtifact
from app.detection.ml.mahalanobis import MahalanobisArtifact

_N_FEATURES = len(ENTITY_WINDOW_MODEL_FEATURES)


def test_detector_keys_match_datagen_ground_truth_labels() -> None:
    """`app.detection.ml` deliberately does not import `datagen` (see `detect.py`'s module
    docstring) — this is the one test in the suite that legitimately imports both sides of that
    boundary to audit it hasn't drifted, the same shape of check
    `tests/test_signal_constants.py` runs for the L2 layer."""
    from datagen.types import ML_IFOREST as GEN_IFOREST
    from datagen.types import ML_MAHALANOBIS as GEN_MAHALANOBIS
    from datagen.types import ML_PEER_GROUP as GEN_PEER_GROUP

    assert ML_IFOREST == GEN_IFOREST
    assert ML_MAHALANOBIS == GEN_MAHALANOBIS
    assert ML_PEER_GROUP == GEN_PEER_GROUP
    # ML_ECOD has no datagen ground-truth counterpart to audit against (no scenario names it in
    # `expected_detectors` yet) -- nothing to compare here beyond the three that do.
    #
    # ML_EIF matches the literal string `datagen/generate_corpus.py` (the migration's regenerated
    # corpus, out of this package's ownership) already puts in `expected_detectors` -- see
    # `detect.py`'s own module docstring for that constant. ML_KTH_NN has no pre-existing
    # ground-truth counterpart yet, same situation ML_ECOD is already in.
    #
    # `datagen.types.ML_AUTOENCODER` still exists (scenario 4's own `expected_detectors` ground
    # truth, `datagen/scenarios/s04_low_and_slow_exfil.py`, is untouched by this migration phase)
    # but has no live counterpart in `app.detection.ml.detect` to audit against anymore --
    # migration change 19 removed the model. That is an honest, reportable gap (CLAUDE.md: "losing
    # is a valid, reportable outcome"), not a bug: EIF is what now takes over that job.


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
    ecod = ECODArtifact.fit(x_train, x_calib)
    lof = LOFArtifact.fit(x_train, x_calib)
    eif = EIFArtifact.fit(x_train, x_calib)
    kth_nn = KNNArtifact.fit(x_train, x_calib)

    return MLModelBundle(
        scaler=scaler,
        iforest=iforest,
        mahalanobis=mahalanobis,
        ecod=ecod,
        lof=lof,
        eif=eif,
        kth_nn=kth_nn,
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
    assert detector_keys <= {
        ML_IFOREST,
        ML_MAHALANOBIS,
        ML_ECOD,
        ML_PEER_GROUP,
        ML_EIF,
        ML_KTH_NN,
    }
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
    assert len(drafts_low_threshold) == 6  # one per model
    # threshold=1.01 is unreachable (confidence is clipped to [0, 1]).
    drafts_high_threshold = score_entity_windows(bundle, df, threshold=1.01)
    assert drafts_high_threshold == []


def test_model_roster_covers_every_model_in_the_bundle() -> None:
    """`ML_MODEL_FIELDS` is the single source of truth for "every L3 model", and anything
    iterating the roster (isotonic calibration, the benchmark, the demo pipeline) reads it
    rather than carrying its own copy.

    This guards the exact drift that already happened once: `calibration._model_pairs` held
    four hardcoded tuples under a docstring claiming it read the roster dynamically, so EIF
    and kth-NN were added to the bundle by migration change 19 and then silently never
    calibrated. A model in the bundle that is absent from the mapping is that bug returning.
    """
    import dataclasses

    from app.detection.ml.detect import ML_MODEL_FIELDS, MLModelBundle

    bundle_fields = {f.name for f in dataclasses.fields(MLModelBundle)}
    # Everything the roster points at must exist on the bundle.
    assert not (set(ML_MODEL_FIELDS.values()) - bundle_fields)

    # And every *model* on the bundle must be in the roster. `scaler` is preprocessing, not a
    # scored model, so it is the one legitimate exclusion — spelled out rather than filtered by
    # a name heuristic that would quietly swallow a future omission.
    non_model_fields = {"scaler"}
    assert bundle_fields - non_model_fields - set(ML_MODEL_FIELDS.values()) == set()
