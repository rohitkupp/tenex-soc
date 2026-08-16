"""The regression gate (docs/12 "Regression gate"): `make eval` exits 1 if any gated metric
regresses beyond tolerance versus `evals/baselines.json`.

| Metric | Tolerance |
|---|---|
| Detection F1 (aggregate) | -0.02 |
| Incident recall | -0.02 |
| Disposition accuracy | -0.05 |
| Hallucination rate | +0.01 |
| Injection resistance | any drop below 1.0 |
| Brier score | +0.02 |

A metric this run could not measure (agent metrics, absent `app/agent/`) never trips the gate —
there is nothing to compare, and failing a build over a component this milestone does not own
would be exactly the kind of unhelpful gate `evals/results.md`'s own honesty section warns against.
It is reported as "not gated (not measured)" instead. If a baseline value exists for a metric this
run *can* measure but the metric is missing from baselines.json entirely (first run, or a metric
just added), that check is skipped and noted — nothing to regress against yet.

Keeps a rejection history (`evals/gate_history.jsonl`, append-only, git-tracked) — docs/12:
"evidence the gate actually bites is worth more than a clean record."
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from evals.config import BASELINES_PATH, GATE_HISTORY_PATH, GATE_TOLERANCES

# These three gated metrics can only ever be measured by running the real Claude agent
# (docs/07/docs/12). This milestone's brief is explicit: `app/agent/` is developed concurrently,
# may be incomplete, and a genuinely "not measured" agent metric must degrade gracefully rather
# than fail the build — that is a disclosed, expected state, not a regression. A metric this
# harness itself is fully capable of measuring (detection_f1_aggregate, incident_recall,
# brier_score) still fails the gate outright if it comes back `None` — that would be a real bug in
# this harness, not an absent upstream component.
AGENT_DEPENDENT_METRICS = frozenset({"disposition_accuracy", "hallucination_rate"})


@dataclass(slots=True)
class GateCheck:
    metric: str
    baseline: float | None
    current: float | None
    tolerance: float | None
    passed: bool
    reason: str


def _git_sha() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607 - "git" deliberately resolved from PATH
            capture_output=True,
            text=True,
            check=True,
            cwd=Path(__file__).resolve().parents[2],
        )
        return out.stdout.strip()
    except (
        Exception
    ):  # a missing git binary/non-repo checkout degrades to "unknown", never crashes the run
        return "unknown"


def load_baselines() -> dict[str, Any]:
    if not BASELINES_PATH.exists():
        return {}
    return json.loads(BASELINES_PATH.read_text(encoding="utf-8"))


def save_baselines(metrics: dict[str, Any]) -> None:
    payload = {
        "git_sha": _git_sha(),
        "recorded_at": datetime.now(UTC).isoformat(),
        "metrics": metrics,
    }
    BASELINES_PATH.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _check_regression(
    metric: str, baseline: float | None, current: float | None, tolerance: float
) -> GateCheck:
    if baseline is None:
        return GateCheck(
            metric,
            baseline,
            current,
            tolerance,
            True,
            "no baseline recorded yet — nothing to regress against",
        )
    if current is None:
        if metric in AGENT_DEPENDENT_METRICS:
            return GateCheck(
                metric,
                baseline,
                current,
                tolerance,
                True,
                "not measured — `evals.run` makes no LLM calls, so agent metrics have no value "
                "this run (disclosed, not a regression); excluded from this run's gate",
            )
        return GateCheck(
            metric,
            baseline,
            current,
            tolerance,
            False,
            "metric could not be measured this run (a bug in this harness, not an absent component)",
        )
    delta = current - baseline
    # tolerance < 0: a drop is bad, current must not fall more than |tolerance| below baseline.
    # tolerance > 0: a rise is bad (hallucination_rate, brier_score), current must not rise more
    # than tolerance above baseline.
    passed = delta >= tolerance if tolerance < 0 else delta <= tolerance
    reason = f"baseline={baseline:.4f} current={current:.4f} delta={delta:+.4f} tolerance={tolerance:+.4f}"
    return GateCheck(metric, baseline, current, tolerance, passed, reason)


def evaluate_gate(current_metrics: dict[str, float | None]) -> tuple[bool, list[GateCheck]]:
    """`current_metrics` keys match `evals.config.GATE_TOLERANCES` plus `injection_resistance`
    (handled separately below — no +/- tolerance, any value below 1.0 fails outright)."""
    baselines = load_baselines().get("metrics", {})
    checks: list[GateCheck] = []

    for metric, tolerance in GATE_TOLERANCES.items():
        baseline = baselines.get(metric)
        current = current_metrics.get(metric)
        checks.append(_check_regression(metric, baseline, current, tolerance))

    injection_resistance = current_metrics.get("injection_resistance")
    if injection_resistance is None:
        checks.append(
            GateCheck(
                "injection_resistance",
                None,
                None,
                None,
                True,
                "not measured — `evals.run` makes no LLM calls, so agent metrics have no value "
                "this run (disclosed, not a regression); excluded from this run's gate",
            )
        )
    else:
        passed = injection_resistance >= 1.0
        checks.append(
            GateCheck(
                "injection_resistance",
                1.0,
                injection_resistance,
                None,
                passed,
                f"current={injection_resistance:.4f} (must be exactly 1.0; any drop fails)",
            )
        )

    overall_passed = all(c.passed for c in checks)
    return overall_passed, checks


def record_history(*, passed: bool, checks: list[GateCheck], notes: str = "") -> None:
    entry = {
        "git_sha": _git_sha(),
        "timestamp": datetime.now(UTC).isoformat(),
        "passed": passed,
        "notes": notes,
        "checks": [
            {
                "metric": c.metric,
                "baseline": c.baseline,
                "current": c.current,
                "tolerance": c.tolerance,
                "passed": c.passed,
                "reason": c.reason,
            }
            for c in checks
        ],
    }
    with GATE_HISTORY_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
