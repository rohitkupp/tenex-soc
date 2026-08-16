"""The L3 benchmark (docs/12 §"Model comparison — the headline tables", row "L3 unsupervised":
Isolation Forest / Mahalanobis / ECOD / LOF / EIF / kth-NN, F1 / AUC-PR / per-scenario recall).
Was five models through the autoencoder; migration change 19
(`docs/v2_migration/MIGRATION-01-evidence-first.md`) removed it (its job -- joint-distribution
anomalies -- is what EIF's oblique splits take over) and named EIF and kth-NN as the roster
entries that absorb its job and round the L3 distance/instance-based side out, respectively. Both
land here alongside the three retained baselines (Isolation Forest, Mahalanobis, ECOD) and LOF --
change 19's own words: those three stay registered specifically "so EIF has to prove oblique
splitting earns its cost against them."

    python -m app.detection.ml.evaluate --eval-seed 7 --eval-dir /tmp/m8_eval

## The governing rule this script exists to test (CLAUDE.md, restated)

"No model ships without a benchmark. Every model has a simpler baseline it must beat on the
labeled eval set. Losing is a valid, reportable outcome." docs/04's own model table names
Isolation Forest "Baseline" — so that is literally the bar every other model here must clear, not
an informal comparison. This script does not try to make any one model win; it measures which
model wins and reports that, plainly, including if it loses.

## Full-space vs. PCA (migration change 25's test plan)

`ml.kth_nn` and `ml.peer_group` (LOF) are this package's two distance-based models. `train.py`
fits and saves a PCA-space variant of each (`dimensionality.py`) purely so this benchmark can
report the comparison the test plan asks for — see `evaluate`'s own `full_vs_pca_metrics` and the
returned `full_vs_pca` section. This is a separate, additional comparison from the primary
six-model `aggregate`/`winner` table above; the PCA variants are never candidates for `winner`.

## Data provenance

Ten scenario files, one per `docs/11` row, generated via `python -m datagen scenario --name
<key> --seed <eval-seed> --out <eval-dir> --events 50000` (docs/11's own per-scenario volume
target) — a CLI subprocess call, same boundary `train.py` holds (`app.detection.ml` never
imports `datagen`). `--eval-seed` defaults to 7, distinct from `train.py`'s corpus seed (42) and
tuning seed (1009) — three different integers, asserted, on top of `datagen.corpus.role_seed`'s
own "benign" vs "eval" role namespacing (so even an accidental seed collision with the *training*
corpus would still resolve to a different simulated org).

## Metrics, and what "detected" means for a scenario

Per scenario, per model: precision/recall/F1 at the fixed `SIGNAL_CONFIDENCE_THRESHOLD` operating
point (`detect.py` — the same threshold that would actually decide whether a `signals` row gets
written, not a threshold picked after seeing these results) against `y`, and AUC-PR
(threshold-free) against the continuous `raw_score`. `y[i]` is `1` iff row `i`'s `line_numbers`
(from `build_entity_window_features`) intersect `GroundTruth.malicious_line_numbers` for that
scenario. False-positive rate is measured two ways per docs/12: aggregated benign (`y=0`) rows
across every scenario's own background traffic, and specifically on scenario 10
(`benign_but_weird`, the dedicated false-positive control).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import numpy.typing as npt
import pandas as pd
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score

from app.core.logging import configure_logging, get_logger
from app.detection.ml.artifacts import MODELS_DIR
from app.detection.ml.detect import (
    ML_ECOD,
    ML_EIF,
    ML_IFOREST,
    ML_KTH_NN,
    ML_MAHALANOBIS,
    ML_PEER_GROUP,
    SIGNAL_CONFIDENCE_THRESHOLD,
    MLModelBundle,
)
from app.detection.ml.events import load_ml_events
from app.detection.ml.features import build_entity_window_features
from app.detection.ml.knn import KNN_PCA_ARTIFACT_FILENAME, KNNArtifact
from app.detection.ml.lof import LOF_PCA_ARTIFACT_FILENAME, LOFArtifact

log = get_logger(__name__)

# docs/11's eight scenarios (down from ten -- password_spray, impossible_travel,
# account_takeover_chain, and mfa_fatigue were Okta/identity-only and removed along with that
# source; peer_group_deviation and seasonal_deviation were added at M8b for the docs/12
# prediction #2/#3 pre-registered tests), verbatim key order from docs/11's table. Hardcoded
# rather than `datagen.scenarios.scenario_keys()` -- `app.detection.ml` does not import
# `datagen` (module docstrings across this package explain why); `tests/test_ml_evaluate.py`
# asserts this tuple stays in sync with the registered scenario keys as an independent audit.
SCENARIO_KEYS: tuple[str, ...] = (
    "c2_beaconing",
    "data_exfiltration",
    "insider_mass_download",
    "low_and_slow_exfil",
    "peer_group_deviation",
    "seasonal_deviation",
    "prompt_injection_canary",
    "benign_but_weird",
)
SCENARIO_EVENTS = 50_000
FP_CONTROL_SCENARIO = "benign_but_weird"
LOW_AND_SLOW_SCENARIO = "low_and_slow_exfil"
PEER_GROUP_SCENARIO = "peer_group_deviation"
SEASONAL_SCENARIO = "seasonal_deviation"

MODEL_KEYS: tuple[str, str, str, str, str, str] = (
    ML_IFOREST,
    ML_MAHALANOBIS,
    ML_ECOD,
    ML_PEER_GROUP,
    ML_EIF,
    ML_KTH_NN,
)
BASELINE_MODEL = ML_IFOREST

# Full-space vs. PCA comparison (module docstring) — distinct model keys from the primary six
# above so the PCA variants never enter `_pick_winner`'s contention; they exist to answer "does
# PCA help the distance methods," not to compete for the shipped slot.
ML_PEER_GROUP_PCA = "ml.peer_group.pca"
ML_KTH_NN_PCA = "ml.kth_nn.pca"


def _run_datagen(args: list[str]) -> None:
    cmd = [sys.executable, "-m", "datagen", *args]
    log.info("datagen.invoke", cmd=cmd)
    subprocess.run(cmd, check=True, cwd=Path(__file__).resolve().parents[3])  # noqa: S603


def _generate_eval_scenarios(eval_dir: Path, eval_seed: int) -> dict[str, Path]:
    """One directory per scenario key; returns `{key: directory}`."""
    out: dict[str, Path] = {}
    for key in SCENARIO_KEYS:
        out_dir = eval_dir / key
        if not out_dir.exists() or not any(out_dir.glob("*.labels.json")):
            _run_datagen(
                [
                    "scenario",
                    "--name",
                    key,
                    "--seed",
                    str(eval_seed),
                    "--out",
                    str(out_dir),
                    "--events",
                    str(SCENARIO_EVENTS),
                ]
            )
        out[key] = out_dir
    return out


def _load_scenario(
    scenario_dir: Path,
) -> tuple[pd.DataFrame, npt.NDArray[np.int64], dict[str, Any]]:
    """`(df, y, ground_truth_summary)` for one scenario directory. `ground_truth_summary` carries
    `expected_detectors`/`technique`/notes, straight from `.labels.json`, for the report."""
    log_files = sorted(scenario_dir.glob("*.log"))
    label_files = sorted(scenario_dir.glob("*.labels.json"))

    malicious_by_file: dict[str, set[int]] = {}
    gt_summary: dict[str, Any] = {"expected_detectors": [], "technique": None, "scenarios": []}
    for label_path in label_files:
        payload = json.loads(label_path.read_text(encoding="utf-8"))
        lines = {ln for s in payload["scenarios"] for ln in s["malicious_line_numbers"]}
        malicious_by_file[payload["log_file"]] = lines
        for s in payload["scenarios"]:
            gt_summary["expected_detectors"].extend(s["expected_detectors"])
            gt_summary["technique"] = gt_summary["technique"] or s["technique"]
            gt_summary["scenarios"].append(
                {
                    "scenario_id": s["scenario_id"],
                    "expected_disposition": s["expected_disposition"],
                    "n_malicious_lines": len(s["malicious_line_numbers"]),
                }
            )

    paths = {"zscaler": log_files[0]} if log_files else {}
    events = load_ml_events(paths)
    df = build_entity_window_features(events)
    all_malicious: set[int] = set()
    for lines in malicious_by_file.values():
        all_malicious |= lines

    if df.empty:
        return df, np.empty((0,), dtype=np.int64), gt_summary
    y = df["line_numbers"].apply(lambda lns, mal=all_malicious: any(ln in mal for ln in lns))
    return df, y.to_numpy(dtype=np.int64), gt_summary


@dataclass(slots=True)
class ScenarioModelMetrics:
    scenario: str
    model: str
    n_rows: int
    n_positive: int
    n_flagged: int
    precision: float
    recall: float
    f1: float
    auc_pr: float
    detected: bool  # recall > 0 -- "did this model catch any of the injected campaign"


def _metrics_for_model(
    scenario: str,
    model_key: str,
    y: npt.NDArray[np.int64],
    raw: npt.NDArray[np.float64],
    conf: npt.NDArray[np.float64],
) -> ScenarioModelMetrics:
    y_pred = (conf >= SIGNAL_CONFIDENCE_THRESHOLD).astype(np.int64)
    n_positive = int(y.sum())
    if n_positive == 0 or len(np.unique(y)) < 2:
        auc_pr = float("nan")
    else:
        auc_pr = float(average_precision_score(y, raw))
    precision = float(precision_score(y, y_pred, zero_division=0))
    recall = float(recall_score(y, y_pred, zero_division=0))
    f1 = float(f1_score(y, y_pred, zero_division=0))
    return ScenarioModelMetrics(
        scenario=scenario,
        model=model_key,
        n_rows=len(y),
        n_positive=n_positive,
        n_flagged=int(y_pred.sum()),
        precision=precision,
        recall=recall,
        f1=f1,
        auc_pr=auc_pr,
        detected=recall > 0.0,
    )


def evaluate(
    *,
    eval_seed: int,
    eval_dir: Path,
    models_dir: Path = MODELS_DIR,
) -> dict[str, Any]:
    t0 = time.perf_counter()
    bundle = MLModelBundle.load(models_dir)
    # PCA-space variants of the two distance models — `train.py` always fits and saves both
    # spaces (module docstring "Full-space vs. PCA"); loaded here, outside `MLModelBundle`,
    # purely for the comparison this benchmark reports and never for `_pick_winner`.
    lof_pca = LOFArtifact.load(models_dir / LOF_PCA_ARTIFACT_FILENAME)
    kth_nn_pca = KNNArtifact.load(models_dir / KNN_PCA_ARTIFACT_FILENAME)
    scenario_dirs = _generate_eval_scenarios(eval_dir, eval_seed)

    per_scenario_metrics: list[ScenarioModelMetrics] = []
    full_vs_pca_metrics: list[ScenarioModelMetrics] = []
    ground_truths: dict[str, dict[str, Any]] = {}
    fp_background_flagged: dict[str, int] = dict.fromkeys(MODEL_KEYS, 0)
    fp_background_total = 0
    fp_scenario10: dict[str, tuple[int, int]] = {}

    for key in SCENARIO_KEYS:
        df, y, gt_summary = _load_scenario(scenario_dirs[key])
        ground_truths[key] = gt_summary
        if df.empty:
            log.warning("evaluate.scenario_empty", scenario=key)
            continue
        x_scaled = bundle.transform(df)

        benign_mask = y == 0
        fp_background_total += int(benign_mask.sum())

        for model_key, model in (
            (ML_IFOREST, bundle.iforest),
            (ML_MAHALANOBIS, bundle.mahalanobis),
            (ML_ECOD, bundle.ecod),
            (ML_PEER_GROUP, bundle.lof),
            (ML_EIF, bundle.eif),
            (ML_KTH_NN, bundle.kth_nn),
        ):
            raw = model.raw_scores(x_scaled)
            conf = model.confidence(raw)
            metrics = _metrics_for_model(key, model_key, y, raw, conf)
            per_scenario_metrics.append(metrics)

            flagged_benign = int(((conf >= SIGNAL_CONFIDENCE_THRESHOLD) & benign_mask).sum())
            fp_background_flagged[model_key] += flagged_benign
            if key == FP_CONTROL_SCENARIO:
                fp_scenario10[model_key] = (flagged_benign, int(benign_mask.sum()))

        # Full-space vs. PCA comparison — same `x_scaled` input every model above scores (each
        # PCA artifact projects internally, `knn.py`/`lof.py`'s own `_project`), kept in a
        # separate metrics list so these two extra keys never enter `MODEL_KEYS`'s winner pick.
        for pca_model_key, pca_model in (
            (ML_PEER_GROUP_PCA, lof_pca),
            (ML_KTH_NN_PCA, kth_nn_pca),
        ):
            pca_raw = pca_model.raw_scores(x_scaled)
            pca_conf = pca_model.confidence(pca_raw)
            full_vs_pca_metrics.append(_metrics_for_model(key, pca_model_key, y, pca_raw, pca_conf))

        log.info("evaluate.scenario_done", scenario=key, n_rows=len(df), n_positive=int(y.sum()))

    aggregate = _aggregate_metrics(per_scenario_metrics)
    full_vs_pca_aggregate = _aggregate_metrics(
        per_scenario_metrics + full_vs_pca_metrics,
        model_keys=(ML_PEER_GROUP, ML_PEER_GROUP_PCA, ML_KTH_NN, ML_KTH_NN_PCA),
    )
    full_vs_pca = {
        "lof": {
            "full": full_vs_pca_aggregate[ML_PEER_GROUP],
            "pca": full_vs_pca_aggregate[ML_PEER_GROUP_PCA],
            "pca_n_components": lof_pca.pca.n_components if lof_pca.pca else None,
        },
        "kth_nn": {
            "full": full_vs_pca_aggregate[ML_KTH_NN],
            "pca": full_vs_pca_aggregate[ML_KTH_NN_PCA],
            "pca_n_components": kth_nn_pca.pca.n_components if kth_nn_pca.pca else None,
        },
    }
    fp_rates = {
        model: (fp_background_flagged[model] / fp_background_total if fp_background_total else 0.0)
        for model in MODEL_KEYS
    }
    fp_scenario10_rates = {
        model: (flagged / total if total else 0.0)
        for model, (flagged, total) in fp_scenario10.items()
    }

    winner = _pick_winner(aggregate)
    low_and_slow_detectors = [
        m.model for m in per_scenario_metrics if m.scenario == LOW_AND_SLOW_SCENARIO and m.detected
    ]
    peer_group_detectors = [
        m.model for m in per_scenario_metrics if m.scenario == PEER_GROUP_SCENARIO and m.detected
    ]
    seasonal_l3_detectors = [
        m.model for m in per_scenario_metrics if m.scenario == SEASONAL_SCENARIO and m.detected
    ]
    predictions = _pre_registered_predictions(
        peer_group_detectors=peer_group_detectors,
        seasonal_l3_detectors=seasonal_l3_detectors,
    )

    total_seconds = time.perf_counter() - t0
    result = {
        "eval_seed": eval_seed,
        "generated_at_seconds_elapsed": total_seconds,
        "per_scenario": [asdict(m) for m in per_scenario_metrics],
        "aggregate": aggregate,
        "fp_rate_background": fp_rates,
        "fp_rate_scenario10": fp_scenario10_rates,
        "winner": winner,
        "baseline": BASELINE_MODEL,
        "low_and_slow_detectors": low_and_slow_detectors,
        "peer_group_detectors": peer_group_detectors,
        "seasonal_l3_detectors": seasonal_l3_detectors,
        "pre_registered_predictions": predictions,
        "ground_truths": ground_truths,
        "full_vs_pca": full_vs_pca,
    }
    return result


def _pre_registered_predictions(
    *,
    peer_group_detectors: list[str],
    seasonal_l3_detectors: list[str],
) -> dict[str, dict[str, object]]:
    """docs/12's pre-registered predictions, evaluated against measured L3 results (#3's L2-side
    half -- whether `signal.stl_residual` itself detects scenario 6 -- is measured by a separate
    L2 harness this module does not own the input rows for, and merged into `evals/results.md`
    alongside this dict's own `l3_models_detected` field, not computed here).

    Prediction 1 ("the autoencoder detects scenario 4, ECOD does not") is retired, not merely
    always-FALSIFIED: migration change 19 (`docs/v2_migration/MIGRATION-01-evidence-first.md`)
    cut the autoencoder before this benchmark ran again, on architectural grounds ("if EIF matches
    the autoencoder, the autoencoder is cut" -- docs/04), so there is no longer a model on this
    side of the comparison to report a result for. Kept out of the returned dict entirely rather
    than reported as a permanent, uninformative FALSIFIED. Predictions 2 and 3 keep docs/12's own
    numbering (not renumbered to 1/2) so this dict's keys still match that doc's prose.

    Each entry's `outcome` is `"CONFIRMED"` or `"FALSIFIED"` per docs/12's own stated falsification
    condition, decided by the rule alone -- never reframed after seeing the numbers.
    """
    # `ml.eif` ("global entity anomaly") and `ml.kth_nn` ("global distance") both carry the
    # roster's own "global" label (docs/v2_migration change 19's post-migration roster table) --
    # included here alongside the three original global baselines so this prediction stays a
    # real test of "LOF's peer-relative-ness is what catches this, not global-ness in general"
    # now that there are five global models to check against, not three.
    global_models = {ML_IFOREST, ML_MAHALANOBIS, ML_ECOD, ML_EIF, ML_KTH_NN}
    lof_detected = ML_PEER_GROUP in peer_group_detectors
    any_global_detected = bool(global_models & set(peer_group_detectors))
    prediction_2_confirmed = lof_detected and not any_global_detected

    return {
        "2_peer_group_lof_not_global": {
            "statement": (
                "Scenario 5 (peer-group deviation): LOF (ml.peer_group) detects it; the other "
                f"{len(global_models)} global L3 models (iforest, mahalanobis, ecod, eif, "
                "kth_nn) do not."
            ),
            "lof_detected": lof_detected,
            "global_models_that_detected": sorted(global_models & set(peer_group_detectors)),
            "all_detectors": peer_group_detectors,
            "outcome": "CONFIRMED" if prediction_2_confirmed else "FALSIFIED",
        },
        "3_seasonal_stl_not_l3": {
            "statement": (
                "Scenario 6 (seasonal deviation): STL residuals (signal.stl_residual) detect it; "
                "none of the L3 feature-vector models do."
            ),
            "l3_models_detected": seasonal_l3_detectors,
            "l3_falsifies_prediction": bool(seasonal_l3_detectors),
            "note": (
                "STL-detection half measured separately (L2 harness, not this L3 evaluate.py) -- "
                "see evals/results.md for the combined verdict."
            ),
        },
    }


def _aggregate_metrics(
    rows: list[ScenarioModelMetrics], model_keys: Sequence[str] = MODEL_KEYS
) -> dict[str, dict[str, float]]:
    """Per-model aggregate F1/AUC-PR, averaged over the eight *attack* scenarios (excludes the
    prompt-injection canary and the benign-but-weird FP control, neither of which is a detection
    target for these models — averaging them in would penalize every model for correctly *not*
    flagging traffic that is not supposed to fire). `model_keys` defaults to the primary
    `MODEL_KEYS` six; the full-space-vs-PCA comparison (`evaluate`) calls this a second time with
    its own four-key subset so those two extra PCA keys never enter the primary aggregate."""
    attack_scenarios = {
        k for k in SCENARIO_KEYS if k not in (FP_CONTROL_SCENARIO, "prompt_injection_canary")
    }
    aggregate: dict[str, dict[str, float]] = {}
    for model in model_keys:
        model_rows = [r for r in rows if r.model == model and r.scenario in attack_scenarios]
        f1s = [r.f1 for r in model_rows]
        aucs = [r.auc_pr for r in model_rows if not np.isnan(r.auc_pr)]
        recalls = [r.recall for r in model_rows]
        precisions = [r.precision for r in model_rows]
        aggregate[model] = {
            "mean_f1": float(np.mean(f1s)) if f1s else 0.0,
            "mean_auc_pr": float(np.mean(aucs)) if aucs else 0.0,
            "mean_recall": float(np.mean(recalls)) if recalls else 0.0,
            "mean_precision": float(np.mean(precisions)) if precisions else 0.0,
            "n_scenarios_detected": float(sum(1 for r in model_rows if r.detected)),
            "n_scenarios": float(len(model_rows)),
        }
    return aggregate


def _pick_winner(aggregate: dict[str, dict[str, float]]) -> str:
    """Highest mean F1 at the fixed operating point wins; ties broken by mean AUC-PR
    (threshold-free, so a legitimate tiebreaker rather than a second vote for the same metric).
    Decided by this rule alone -- never by which model the report "wants" to win (CLAUDE.md).
    """
    return max(aggregate, key=lambda m: (aggregate[m]["mean_f1"], aggregate[m]["mean_auc_pr"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark the L3 model bench (docs/12, M8)")
    parser.add_argument("--eval-seed", type=int, default=7)
    parser.add_argument("--eval-dir", type=Path, default=Path("/tmp/m8_eval"))  # noqa: S108
    parser.add_argument("--models-dir", type=Path, default=MODELS_DIR)
    parser.add_argument("--out", type=Path, default=None, help="Write raw JSON results here")
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)
    configure_logging(args.log_level)

    result = evaluate(eval_seed=args.eval_seed, eval_dir=args.eval_dir, models_dir=args.models_dir)
    log.info(
        "evaluate.done",
        winner=result["winner"],
        aggregate=result["aggregate"],
        elapsed_s=round(result["generated_at_seconds_elapsed"], 2),
    )
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        log.info("evaluate.written", path=str(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
