"""`python -m evals.run` / `make eval` — orchestrates the full harness end to end (docs/12):
ensures the golden set, fits/loads calibrators, runs every scenario through the real L1-L5
pipeline, computes every metric family, renders and writes `evals/results.md`, records an
`eval_runs` row, evaluates the regression gate against `evals/baselines.json`, and exits 1 on a
regression the gate catches.

CI must never require `ANTHROPIC_API_KEY` (docs/07/docs/12) — nothing in this module or anything
it calls makes an LLM API call; agent metrics degrade to "not measured"
(`evals/metrics/agent.py`) rather than attempting a live call.
"""

from __future__ import annotations

import argparse
import time
import uuid
from typing import Any

from app.core.db import get_session_factory
from app.core.logging import configure_logging, get_logger
from app.detection import initial_weights
from app.detection.calibration import CalibratorStore
from app.models.eval_run import EvalRun
from evals import gate, golden, pipeline, predictions, report
from evals.config import EVAL_CALIBRATORS_DIR, EVAL_SEED, FP_CONTROL_SCENARIO, RESULTS_MD_PATH
from evals.db import cleanup_tenants
from evals.metrics import agent as agent_metrics
from evals.metrics import calibration as calibration_metrics
from evals.metrics import correlation as correlation_metrics
from evals.metrics import cost as cost_metrics
from evals.metrics import detection as detection_metrics

log = get_logger(__name__)


def _load_or_fit_calibrators(*, refit: bool) -> CalibratorStore:
    if not refit and EVAL_CALIBRATORS_DIR.exists() and any(EVAL_CALIBRATORS_DIR.glob("*.joblib")):
        store = CalibratorStore(directory=EVAL_CALIBRATORS_DIR)
        log.info("run.calibrators_loaded_cached", n=len(store), detectors=store.detector_keys())
        return store
    return pipeline.fit_isolated_calibrators()


def _compute_injection_resistance(runs: dict[str, Any]) -> tuple[float | None, str]:
    """docs/12: "scenarios where disposition is unchanged with the canary present / total."
    `disposition` is an agent concept (docs/07's `TriageVerdictOut.disposition`), produced by
    `app.agent.orchestrator.triage_incident` — which exists now (`app/agent/orchestrator.py`,
    `app/agent/verifier.py`), unlike when this function was first written. This is still
    `None`/not-measured here, same as `disposition_accuracy`/`hallucination_rate`
    (`evals/metrics/agent.py`), but for a different, narrower reason: CI deliberately never sets
    `ANTHROPIC_API_KEY` (see this module's own docstring and `.github/workflows/ci.yml`'s top-level
    `env` comment), and no recorded fixtures exist yet at `tests/fixtures/llm/` to replay instead
    — golden-set-wide agent replay needs one recorded verdict per scenario, which nobody with API
    access has captured. That is a one-time, out-of-band recording task, not a missing code path.
    The real, live-enforced version of this gate lives in `tests/test_agent_orchestrator.py`
    (`test_injection_resistance_across_all_canary_styles_is_1_0`): it replays every
    `datagen.scenarios.s07_prompt_injection_canary.INJECTION_STYLES` payload through the real
    orchestrator with scripted (not live) stage outputs and asserts the computed ratio is exactly
    1.0, in the normal `pytest` CI job — no API key required, and it does fail the build on a
    regression. The prompt-injection canary scenario (docs/11 #7) also DID run through
    detection/correlation like every other golden scenario here — see its row in the per-scenario
    tables — but that is a different question from whether an LLM's disposition changes when the
    injected instruction is present, which is what this specific metric measures."""
    detail = (
        "not measured in this harness — CI never sets ANTHROPIC_API_KEY (by design) and no "
        "recorded tests/fixtures/llm/ fixtures exist yet for golden-set-wide agent replay. The "
        "real injection_resistance == 1.0 gate is enforced in the normal pytest job instead: see "
        "tests/test_agent_orchestrator.py::test_injection_resistance_across_all_canary_styles_is_1_0."
    )
    return None, detail


def main(argv: list[str] | None = None) -> int:
    # The harness ingests every golden scenario into DATABASE_URL and deletes its tenants after.
    # Same guard as pipeline_demo's ingest paths — see app.core.db.assert_local_database for the
    # outage that made this necessary.
    from app.core.db import assert_local_database

    assert_local_database("evals.run")
    parser = argparse.ArgumentParser(description="Run the evaluation harness (docs/12)")
    parser.add_argument("--log-level", default="info")
    parser.add_argument(
        "--skip-sweep", action="store_true", help="Skip the jitter-sweep detection curve (faster)"
    )
    parser.add_argument(
        "--refit-calibrators",
        action="store_true",
        help="Refit calibrators instead of reusing the cached store",
    )
    parser.add_argument(
        "--promote",
        action="store_true",
        help="Save this run's metrics as the new committed baseline",
    )
    parser.add_argument(
        "--regenerate-golden",
        action="store_true",
        help="Regenerate the golden set instead of reusing the committed files",
    )
    args = parser.parse_args(argv)
    configure_logging(args.log_level)

    t_start = time.perf_counter()
    all_tenant_ids: list[uuid.UUID] = []

    log.info("run.golden_set.ensure")
    golden.ensure_golden_set(seed=EVAL_SEED, regenerate=args.regenerate_golden)

    log.info("run.calibrators")
    calibrators = _load_or_fit_calibrators(refit=args.refit_calibrators)

    log.info("run.golden_scenarios")
    runs, scenario_tenant_ids = pipeline.run_golden_scenarios(calibrators=calibrators)
    all_tenant_ids.extend(scenario_tenant_ids)

    log.info("run.benign_pure")
    benign_run, benign_tenant_ids = pipeline.run_benign_pure(calibrators=calibrators)
    all_tenant_ids.extend(benign_tenant_ids)

    log.info("run.ml_fp_rates")
    # docs/12 change 1 ("Measure the missing false-positive rates"): every model in
    # `app.detection.ml.detect.ML_MODEL_FIELDS` (all six), scored directly against both FP-control
    # files — independent of `run_scenario`'s persisted-Signal/fusion path, which stays scoped to
    # the three shipped models (see `evals.pipeline.ml_fp_counts_for_file`'s own docstring).
    scenario8_log_path, _scenario8_labels_path = golden.scenario_log_and_labels(FP_CONTROL_SCENARIO)
    ml_fp_counts_scenario8 = pipeline.ml_fp_counts_for_file(scenario8_log_path)
    ml_fp_counts_benign_pure = pipeline.ml_fp_counts_for_file(golden.benign_pure_log())

    log.info("run.detection_metrics")
    detection_report = detection_metrics.build_report(
        runs,
        benign_run,
        ml_fp_counts_scenario8=ml_fp_counts_scenario8,
        ml_fp_counts_benign_pure=ml_fp_counts_benign_pure,
    )

    log.info("run.correlation_metrics")
    correlation = correlation_metrics.build_report(runs)

    log.info("run.l3_benchmark")
    l3_result = predictions.run_l3_benchmark()
    predictions_report = predictions.build_report(l3_result, detection_report.per_scenario_detector)

    log.info("run.initial_fusion_weights")
    # docs/12 change 4 ("Audit and set initial fusion weights"): derived from this run's own
    # freshly-measured pooled L3 benchmark (l3_result["pooled"], docs/12 change 2), using
    # mechanism 2's own clamp formula (`app.detection.initial_weights.clamp_fusion_weight`/
    # `pooled_precision`, reused not reimplemented — see `app.learning.initial_weights`). Written
    # to `data/models/initial_fusion_weights.json` (production `MODELS_DIR`, since this run
    # already scored `l3_result` against those exact artifacts) for
    # `app.pipeline.stages.correlate._fusion_weight` to read as its fallback the next time it is
    # imported, replacing the uniform-1.0-for-every-detector starting point.
    shipped_initial_weights = initial_weights.compute_shipped_initial_weights(l3_result["pooled"])
    shipped_pooled_counts = {
        key: (int(l3_result["pooled"][key]["tp"]), int(l3_result["pooled"][key]["fp"]))
        for key in shipped_initial_weights
    }
    initial_weights_prior = initial_weights.pooled_precision(shipped_pooled_counts.values())
    initial_weights_source = {
        "eval_seed": l3_result.get("eval_seed"),
        "derived_from": "app.detection.ml.evaluate.evaluate()['pooled'], this run",
        "pooled_counts": {k: {"tp": tp, "fp": fp} for k, (tp, fp) in shipped_pooled_counts.items()},
        "prior_precision": initial_weights_prior,
    }
    initial_weights.save_initial_fusion_weights(
        shipped_initial_weights, source=initial_weights_source
    )

    log.info("run.calibration_metrics")
    calibration = calibration_metrics.build_report(runs, benign_run)

    log.info("run.cost_metrics")
    cost = cost_metrics.build_report(runs, benign_run)

    log.info("run.agent_metrics")
    agent = agent_metrics.build_report()

    injection_resistance, injection_detail = _compute_injection_resistance(runs)

    sweep = None
    if not args.skip_sweep:
        log.info("run.sweep")
        try:
            from evals.sweep import run_beaconing_jitter_sweep

            sweep = run_beaconing_jitter_sweep()
        except Exception:
            log.warning("run.sweep_failed", exc_info=True)
            sweep = None

    current_metrics: dict[str, float | None] = {
        "detection_f1_aggregate": detection_report.detection_f1_aggregate,
        "incident_recall": correlation.get("incident_recall"),
        "disposition_accuracy": agent.get("disposition_accuracy"),
        "hallucination_rate": agent.get("hallucination_rate"),
        "brier_score": calibration.get("brier_score"),
        "injection_resistance": injection_resistance,
    }
    gate_passed, gate_checks = gate.evaluate_gate(current_metrics)

    git_sha = gate._git_sha()
    md = report.render(
        git_sha=git_sha,
        gate_passed=gate_passed,
        gate_checks=gate_checks,
        detection_report=detection_report,
        correlation=correlation,
        predictions=predictions_report,
        l3_result=l3_result,
        calibration=calibration,
        cost=cost,
        agent=agent,
        injection_resistance=injection_resistance,
        injection_detail=injection_detail,
        sweep=sweep,
        initial_fusion_weights=shipped_initial_weights,
        initial_fusion_weights_source=initial_weights_source,
        extra_weaknesses=[
            "**A real defect found and worked around, not silently patched.** "
            "`app/graph/features.py`'s graph-signal explanation payload can carry a raw "
            "`z_score` of `+/-inf` (`robust_z` returns it by documented design when a "
            "feature's reference population has zero MAD) and Postgres JSONB rejects the "
            "literal `Infinity` token. `app.graph.pipeline_demo._calibration_feature` already "
            "sanitizes the identical root cause on the calibration path; `evals/pipeline.py` "
            "applies the same finite-sentinel policy as a process-local monkeypatch of "
            "`app.graph.features`'s `robust_z` binding (not an edit to any `app/**` file) so "
            "this harness can run at all. Every one of the eight golden scenarios hit this at "
            "this harness's 120-user org size — a real, reproducible bug filed here, not "
            "silently avoided.",
            "**Resolved: `app.graph.pipeline_demo._ml_model_pairs` used to score the "
            "pre-migration-19 L3 roster** (`ml.iforest`/`ml.mahalanobis`/`ml.ecod`/"
            "`ml.peer_group`) instead of `SHIPPED_MODEL_FIELDS` (`ml.eif`/`ml.kth_nn`/"
            "`ml.peer_group`) — the same class of stale-hardcoded-list bug already fixed for "
            "`known_detector_registry` and `app.detection.calibration._model_pairs`, previously "
            "left unfixed here for lack of sign-off to touch `app/graph/pipeline_demo.py`. Now "
            "reads `SHIPPED_MODEL_FIELDS` directly (`app.detection.ml.detect`'s own roster "
            "constant), so `_run_l3`'s signal emission and `fit_layer_calibrators`'s calibration-"
            "sample collection both stay faithful to what production actually ships, and "
            "`ml.eif`/`ml.kth_nn` now appear in section 3's live-pipeline breakdown and get a "
            "fitted calibrator like every other shipped model.",
        ],
    )
    RESULTS_MD_PATH.write_text(md, encoding="utf-8")
    log.info("run.results_written", path=str(RESULTS_MD_PATH))

    gate.record_history(passed=gate_passed, checks=gate_checks)

    if args.promote:
        gate.save_baselines(current_metrics)
        log.info("run.baseline_promoted", metrics=current_metrics)

    session = get_session_factory()()
    try:
        eval_run = EvalRun(
            git_sha=git_sha,
            metrics={
                "gated": current_metrics,
                "detection": {
                    "aggregate": detection_report.detection_f1_aggregate,
                    "per_detector": detection_report.per_detector_aggregate,
                    "fp_rate_scenario8": detection_report.fp_rate_scenario8_total,
                    "fp_rate_benign_pure": detection_report.fp_rate_benign_pure_total,
                },
                "correlation": {k: v for k, v in correlation.items() if k != "per_scenario"},
                "calibration": {
                    "brier_score": calibration.get("brier_score"),
                    "n_samples": calibration.get("n_samples"),
                },
                "cost": {
                    k: v
                    for k, v in cost.items()
                    if k not in ("pipeline_latency_per_scenario_s", "not_measured")
                },
                "agent": {"measured": agent.get("measured"), "reason": agent.get("reason")},
                "predictions": {k: v.get("outcome") for k, v in predictions_report.items()},
            },
            passed=gate_passed,
        )
        session.add(eval_run)
        session.commit()
        log.info("run.eval_run_recorded", id=str(eval_run.id))
    finally:
        session.close()

    log.info("run.cleanup", n_tenants=len(all_tenant_ids))
    cleanup_tenants(all_tenant_ids)

    elapsed = time.perf_counter() - t_start
    log.info("run.done", elapsed_s=round(elapsed, 2), gate_passed=gate_passed)

    print(f"\n{'=' * 70}")
    print(f"Gate: {'PASS' if gate_passed else 'FAIL'}  ({elapsed:.1f}s total)")
    print(f"{'=' * 70}")
    for c in gate_checks:
        mark = "PASS" if c.passed else "FAIL"
        print(f"  [{mark}] {c.metric}: {c.reason}")
    print(f"\nresults.md written to {RESULTS_MD_PATH}")

    return 0 if gate_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
