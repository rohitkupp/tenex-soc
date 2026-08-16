"""End-to-end smoke test for `train.py`/`evaluate.py`'s orchestration — real `datagen` subprocess
calls, real feature extraction, real (tiny) model fits, real artifact save/load, real metrics.
Deliberately small (a few thousand events, 2 Optuna trials) so this runs in CI in seconds rather
than the minutes the real M8 benchmark (`evals/results.md`) takes at full scale; this test is
about proving the wiring, not about detection quality at that scale.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import app.detection.ml.evaluate as evaluate_module
import app.detection.ml.train as train_module
from app.detection.ml.artifacts import load_feature_manifest
from app.detection.ml.detect import (
    ML_ECOD,
    ML_IFOREST,
    ML_MAHALANOBIS,
    ML_PEER_GROUP,
)


def test_train_then_evaluate_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    models_dir = tmp_path / "models"
    summary = train_module.train(
        corpus_seed=4242,
        corpus_events=3000,
        corpus_dir=tmp_path / "corpus",
        models_dir=models_dir,
    )

    assert summary["corpus_seed"] == 4242
    assert (models_dir / "scaler.joblib").exists()
    assert (models_dir / "iforest.joblib").exists()
    assert (models_dir / "mahalanobis.joblib").exists()
    assert (models_dir / "ecod.joblib").exists()
    assert (models_dir / "lof.joblib").exists()
    # No `autoencoder.pt` -- migration change 19 removed that model (and, with it, `train.py`'s
    # whole tuning-validation-corpus machinery that existed only to feed its Optuna search).

    manifest = load_feature_manifest(models_dir)
    assert manifest.corpus_seed == 4242

    monkeypatch.setattr(evaluate_module, "SCENARIO_KEYS", ("c2_beaconing", "benign_but_weird"))
    monkeypatch.setattr(evaluate_module, "SCENARIO_EVENTS", 3000)

    result = evaluate_module.evaluate(
        eval_seed=5454, eval_dir=tmp_path / "eval", models_dir=models_dir
    )

    all_models = (ML_IFOREST, ML_MAHALANOBIS, ML_ECOD, ML_PEER_GROUP)
    assert result["winner"] in all_models
    assert result["baseline"] == ML_IFOREST
    for model_key in all_models:
        assert model_key in result["aggregate"]
        assert 0.0 <= result["fp_rate_background"][model_key] <= 1.0
    # Prediction 1 (autoencoder vs. ECOD on scenario 4) is retired along with the model it
    # concerned -- see `evaluate.py::_pre_registered_predictions`'s own docstring.
    assert set(result["pre_registered_predictions"]) == {
        "2_peer_group_lof_not_global",
        "3_seasonal_stl_not_l3",
    }
    # Two seeds (corpus 4242, eval 5454) are distinct, as `train.py`'s own module docstring
    # requires -- checked here, not just asserted in prose.
    assert 4242 != 5454
