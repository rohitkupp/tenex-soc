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
from app.detection.calibration import CalibratorStore
from app.models.eval_run import EvalRun
from evals import gate, golden, pipeline, predictions, report
from evals.config import EVAL_CALIBRATORS_DIR, EVAL_SEED, RESULTS_MD_PATH
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
    `disposition` is an agent concept (docs/07's `TriageVerdictOut.disposition`) — this harness
    has no agent to produce one (see `evals/metrics/agent.py`), so this is `None`/not-measured,
    same as `disposition_accuracy`/`hallucination_rate`, not a fabricated pass."""
    detail = (
        "not measured — injection_resistance is defined over the agent's disposition "
        "(docs/07), and app/agent/ has no orchestrator.py yet. The prompt-injection canary "
        "scenario (docs/11 #7) DID run through detection/correlation like every other golden "
        "scenario — see its row in the per-scenario tables — but that is a different question "
        "from whether an LLM's disposition changes when the injected instruction is present."
    )
    return None, detail


def main(argv: list[str] | None = None) -> int:
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

    log.info("run.detection_metrics")
    detection_report = detection_metrics.build_report(runs, benign_run)

    log.info("run.correlation_metrics")
    correlation = correlation_metrics.build_report(runs)

    log.info("run.l3_benchmark")
    l3_result = predictions.run_l3_benchmark()
    predictions_report = predictions.build_report(l3_result, detection_report.per_scenario_detector)

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
