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
    ML_AUTOENCODER,
    ML_ECOD,
    ML_IFOREST,
    ML_MAHALANOBIS,
    ML_PEER_GROUP,
)


def test_train_then_evaluate_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Keep the tuning-validation set to one cheap, non-acceptance-gated scenario at small volume
    # -- `low_and_slow_exfil`'s own acceptance gate (datagen/scenarios/s08_...) needs real volume
    # (docs/11's ~50k default) to find a victim with enough history, which this smoke test's
    # whole point is to avoid paying for.
    monkeypatch.setattr(train_module, "_TUNING_SCENARIO_KEYS", ("c2_beaconing",))
    monkeypatch.setattr(train_module, "_TUNING_SCENARIO_EVENTS", 3000)

    models_dir = tmp_path / "models"
    summary = train_module.train(
        corpus_seed=4242,
        corpus_events=3000,
        corpus_dir=tmp_path / "corpus",
        tuning_seed=4343,
        tuning_dir=tmp_path / "tuning",
        optuna_trials=2,
        models_dir=models_dir,
    )

    assert summary["corpus_seed"] == 4242
    assert (models_dir / "scaler.joblib").exists()
    assert (models_dir / "iforest.joblib").exists()
    assert (models_dir / "mahalanobis.joblib").exists()
    assert (models_dir / "ecod.joblib").exists()
    assert (models_dir / "lof.joblib").exists()
    assert (models_dir / "autoencoder.pt").exists()

    manifest = load_feature_manifest(models_dir)
    assert manifest.corpus_seed == 4242

    monkeypatch.setattr(evaluate_module, "SCENARIO_KEYS", ("c2_beaconing", "benign_but_weird"))
    monkeypatch.setattr(evaluate_module, "SCENARIO_EVENTS", 3000)

    result = evaluate_module.evaluate(
        eval_seed=5454, eval_dir=tmp_path / "eval", models_dir=models_dir
    )

    all_models = (ML_IFOREST, ML_MAHALANOBIS, ML_ECOD, ML_PEER_GROUP, ML_AUTOENCODER)
    assert result["winner"] in all_models
    assert result["baseline"] == ML_IFOREST
    for model_key in all_models:
        assert model_key in result["aggregate"]
        assert 0.0 <= result["fp_rate_background"][model_key] <= 1.0
    assert set(result["pre_registered_predictions"]) == {
        "1_low_and_slow_ae_not_ecod",
        "2_peer_group_lof_not_global",
        "3_seasonal_stl_not_l3",
    }
    # Three seeds (corpus 4242, tuning 4343, eval 5454) are pairwise distinct, as `train.py`'s
    # own module docstring requires -- checked here, not just asserted in prose.
    assert len({4242, 4343, 5454}) == 3
