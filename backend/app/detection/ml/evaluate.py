"""The L3 benchmark (docs/12 §"Model comparison — the headline tables", row "L3 unsupervised":
Isolation Forest / Mahalanobis / Autoencoder, F1 / AUC-PR / per-scenario recall).

    python -m app.detection.ml.evaluate --eval-seed 7 --eval-dir /tmp/m8_eval

## The governing rule this script exists to test (CLAUDE.md, restated)

"No model ships without a benchmark. Every model has a simpler baseline it must beat on the
labeled eval set. Losing is a valid, reportable outcome." docs/04's own model table names
Isolation Forest "Baseline" — so that is literally the bar `ml.mahalanobis` and `ml.autoencoder`
must clear here, not an informal comparison. This script does not try to make the autoencoder
win; it measures which model wins and reports that, plainly, including if it loses.

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
    ML_AUTOENCODER,
    ML_IFOREST,
    ML_MAHALANOBIS,
    SIGNAL_CONFIDENCE_THRESHOLD,
    MLModelBundle,
)
from app.detection.ml.events import load_ml_events
from app.detection.ml.features import build_entity_window_features

log = get_logger(__name__)

# docs/11's ten scenarios, verbatim key order from that doc's table. Hardcoded rather than
# `datagen.scenarios.scenario_keys()` -- `app.detection.ml` does not import `datagen` (module
# docstrings across this package explain why); `tests/test_ml_evaluate.py` asserts this tuple
# stays in sync with the registered scenario keys as an independent audit.
SCENARIO_KEYS: tuple[str, ...] = (
    "c2_beaconing",
    "data_exfiltration",
    "password_spray",
    "impossible_travel",
    "account_takeover_chain",
    "mfa_fatigue",
    "insider_mass_download",
    "low_and_slow_exfil",
    "prompt_injection_canary",
    "benign_but_weird",
)
SCENARIO_EVENTS = 50_000
FP_CONTROL_SCENARIO = "benign_but_weird"
LOW_AND_SLOW_SCENARIO = "low_and_slow_exfil"

MODEL_KEYS: tuple[str, str, str] = (ML_IFOREST, ML_MAHALANOBIS, ML_AUTOENCODER)
BASELINE_MODEL = ML_IFOREST


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
    log_files = sorted(scenario_dir.glob("*.log")) + sorted(scenario_dir.glob("*.jsonl"))
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

    paths = {("zscaler" if p.suffix == ".log" else "okta"): p for p in log_files}
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
    scenario_dirs = _generate_eval_scenarios(eval_dir, eval_seed)

    per_scenario_metrics: list[ScenarioModelMetrics] = []
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
            (ML_AUTOENCODER, bundle.autoencoder),
        ):
            raw = model.raw_scores(x_scaled)
            conf = model.confidence(raw)
            metrics = _metrics_for_model(key, model_key, y, raw, conf)
            per_scenario_metrics.append(metrics)

            flagged_benign = int(((conf >= SIGNAL_CONFIDENCE_THRESHOLD) & benign_mask).sum())
            fp_background_flagged[model_key] += flagged_benign
            if key == FP_CONTROL_SCENARIO:
                fp_scenario10[model_key] = (flagged_benign, int(benign_mask.sum()))

        log.info("evaluate.scenario_done", scenario=key, n_rows=len(df), n_positive=int(y.sum()))

    aggregate = _aggregate_metrics(per_scenario_metrics)
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
        "ground_truths": ground_truths,
    }
    return result


def _aggregate_metrics(rows: list[ScenarioModelMetrics]) -> dict[str, dict[str, float]]:
    """Per-model aggregate F1/AUC-PR, averaged over the eight *attack* scenarios (excludes the
    prompt-injection canary and the benign-but-weird FP control, neither of which is a detection
    target for these models — averaging them in would penalize every model for correctly *not*
    flagging traffic that is not supposed to fire)."""
    attack_scenarios = {
        k for k in SCENARIO_KEYS if k not in (FP_CONTROL_SCENARIO, "prompt_injection_canary")
    }
    aggregate: dict[str, dict[str, float]] = {}
    for model in MODEL_KEYS:
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
