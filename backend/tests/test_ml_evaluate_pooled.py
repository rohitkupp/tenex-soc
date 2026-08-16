"""Unit tests for `app.detection.ml.evaluate`'s pooled (micro-averaged) metrics, confusion-matrix
counts, and the F1 -> F2 winner-rule forward change (docs/12 changes 2 and 3). Pure, no DB, no
datagen subprocess, no trained model artifacts — built directly from hand-constructed
`ScenarioModelMetrics` rows, the same dataclass `evaluate()` itself produces.
"""

from __future__ import annotations

import math

import numpy as np

from app.detection.ml.evaluate import (
    MODEL_KEYS,
    ScenarioModelMetrics,
    _aggregate_metrics,
    _attack_scenario_keys,
    _f_beta,
    _metrics_for_model,
    _pick_winner,
    _pick_winner_f2,
    _pooled_metrics,
)

# `_aggregate_metrics`/`_pooled_metrics` both filter internally to the real, module-level attack-
# scenario keys (`_attack_scenario_keys()`, excludes the FP control and the injection canary) --
# a constructed row must use one of these real names or it is silently dropped by that filter.
# Pulled live rather than hardcoded so a future scenario rename cannot make this file's rows
# silently stop counting.
_ATTACK_SCENARIOS = sorted(_attack_scenario_keys())
_S1, _S2 = _ATTACK_SCENARIOS[0], _ATTACK_SCENARIOS[1]


def _row(
    scenario: str,
    model: str,
    *,
    n_positive: int,
    tp: int,
    fp: int,
    n_rows: int | None = None,
) -> ScenarioModelMetrics:
    fn = n_positive - tp
    assert fn >= 0
    n_flagged = tp + fp
    precision = tp / n_flagged if n_flagged else 0.0
    recall = tp / n_positive if n_positive else 0.0
    f1 = _f_beta(precision, recall, beta=1.0)
    f2 = _f_beta(precision, recall, beta=2.0)
    return ScenarioModelMetrics(
        scenario=scenario,
        model=model,
        n_rows=n_rows if n_rows is not None else n_positive + fp + 100,
        n_positive=n_positive,
        n_flagged=n_flagged,
        tp=tp,
        fp=fp,
        fn=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        f2=f2,
        auc_pr=float("nan"),
        detected=recall > 0.0,
    )


def test_metrics_for_model_computes_confusion_matrix_directly_from_predictions() -> None:
    """TP/FP/FN must come from the actual (y, y_pred) arrays, not be reconstructible only from
    precision/recall -- docs/12 change 2's explicit requirement, checked here against a model
    that flags nothing (a real, distinguishable FP=0, not an unrepresentable 0/0)."""
    y = np.array([1, 1, 0, 0, 0], dtype=np.int64)
    raw = np.array([0.9, 0.1, 0.05, 0.05, 0.05])
    conf_flags_nothing = np.array([0.1, 0.1, 0.1, 0.1, 0.1])  # below threshold everywhere
    m = _metrics_for_model("s", "model.x", y, raw, conf_flags_nothing)
    assert (m.tp, m.fp, m.fn) == (0, 0, 2)
    assert m.precision == 0.0  # sklearn zero_division=0
    assert m.recall == 0.0

    conf_perfect = np.array([1.0, 1.0, 0.0, 0.0, 0.0])
    m2 = _metrics_for_model("s", "model.x", y, raw, conf_perfect)
    assert (m2.tp, m2.fp, m2.fn) == (2, 0, 0)
    assert m2.precision == 1.0
    assert m2.recall == 1.0
    assert m2.f1 == 1.0
    assert m2.f2 == 1.0


def test_pooled_confusion_matrix_sums_correctly() -> None:
    """TP + FN must equal the model's total pooled positive count, and the pooled dict's TP/FP/FN
    must be the exact sums of the per-scenario rows -- docs/12 change 2's own sanity check."""
    rows = [
        _row(_S1, "ml.eif", n_positive=10, tp=8, fp=5),
        _row(_S2, "ml.eif", n_positive=90, tp=10, fp=50),
    ]
    pooled = _pooled_metrics(rows, model_keys=("ml.eif",))
    p = pooled["ml.eif"]
    assert p["tp"] == 18
    assert p["fp"] == 55
    assert p["fn"] == 82
    assert p["tp"] + p["fn"] == 100  # == total n_positive across both scenarios
    assert math.isclose(p["precision"], 18 / (18 + 55))
    assert math.isclose(p["recall"], 18 / 100)


def test_pooled_recall_differs_from_macro_mean_recall_as_docs04_describes() -> None:
    """The scenario docs/04's own final section names: a model with perfect recall on a
    2-positive scenario and near-zero recall on a 100-positive one reads far higher under a
    macro mean (which weights both scenarios equally) than under the pooled figure (which weights
    by event count) -- this is exactly why docs/12 now requires both, labeled, not one standing in
    for the other."""
    rows = [
        _row(_S1, "ml.kth_nn", n_positive=2, tp=2, fp=100),  # recall 1.0 on 2 positives
        _row(_S2, "ml.kth_nn", n_positive=100, tp=2, fp=4300),  # recall 0.02 on 100 positives
    ]
    agg = _aggregate_metrics(rows, model_keys=("ml.kth_nn",))
    pooled = _pooled_metrics(rows, model_keys=("ml.kth_nn",))
    macro_recall = agg["ml.kth_nn"]["mean_recall"]
    pooled_recall = pooled["ml.kth_nn"]["recall"]
    assert math.isclose(macro_recall, (1.0 + 0.02) / 2)
    assert math.isclose(pooled_recall, 4 / 102)
    assert macro_recall > pooled_recall  # the flattering figure is the macro one, as docs/04 says
    assert macro_recall - pooled_recall > 0.3  # a real, not a rounding-noise, gap


def test_f2_weights_recall_more_than_f1_and_can_flip_the_winner() -> None:
    """A precise-but-blind model (ECOD's real profile: precision 1.0, recall 0.05-ish) loses to a
    noisier-but-broader one under F2 even though it wins under F1 -- docs/12 change 3's whole
    point. Constructed directly rather than asserting on live ECOD/EIF numbers so this test does
    not depend on trained model artifacts or the golden corpus."""
    # precision 1.0, recall 0.05 (ECOD's real profile on this codebase's own corpus)
    precise_blind = _row(_S1, "ml.precise_blind", n_positive=100, tp=5, fp=0)
    # precision 0.05, recall 0.4 -- noisier, but catches 8x as many of the 100 malicious events
    noisy_broad = _row(_S1, "ml.noisy_broad", n_positive=100, tp=40, fp=760)

    agg = _aggregate_metrics(
        [precise_blind, noisy_broad], model_keys=("ml.precise_blind", "ml.noisy_broad")
    )
    assert agg["ml.precise_blind"]["mean_f1"] > agg["ml.noisy_broad"]["mean_f1"]
    winner_f1 = _pick_winner(agg)
    assert winner_f1 == "ml.precise_blind"

    winner_f2 = _pick_winner_f2(agg)
    assert winner_f2 == "ml.noisy_broad"
    assert winner_f2 != winner_f1  # the forward change actually changes the pick on this data

    # F2 must weight recall 2x precision relative to F1, not just "favor recall arbitrarily":
    # verify against the closed-form formula directly.
    p, r = noisy_broad.precision, noisy_broad.recall
    expected_f2 = (5 * p * r) / (4 * p + r)
    assert math.isclose(agg["ml.noisy_broad"]["mean_f2"], expected_f2)


def test_all_six_model_keys_present_in_aggregate_and_pooled_by_default() -> None:
    rows = [_row(_S1, key, n_positive=10, tp=1, fp=1) for key in MODEL_KEYS]
    agg = _aggregate_metrics(rows)
    pooled = _pooled_metrics(rows)
    assert set(agg) == set(MODEL_KEYS)
    assert set(pooled) == set(MODEL_KEYS)


def test_fn_per_tp_is_none_not_infinite_when_a_model_never_produces_a_pooled_true_positive() -> (
    None
):
    rows = [_row(_S1, "ml.silent", n_positive=10, tp=0, fp=3)]
    pooled = _pooled_metrics(rows, model_keys=("ml.silent",))
    assert pooled["ml.silent"]["fn_per_tp"] is None
