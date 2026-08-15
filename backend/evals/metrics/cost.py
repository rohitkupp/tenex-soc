"""Cost & latency metrics (docs/12): p50/p95 end-to-end pipeline latency, p50/p95 agent latency,
mean tokens and USD per incident, and the funnel reduction ratio
(`events -> signals -> incidents -> triaged`).

Pipeline latency is measured for real (wall-clock around every `app.graph.pipeline_demo.
run_scenario` call, docs/12's own "end-to-end pipeline latency"). Agent latency, tokens, and USD
are **not measured** — `app/agent/` has no `orchestrator.py`/`verifier.py` yet (see
`evals/metrics/agent.py`'s module docstring for the full explanation) and this harness must
degrade gracefully rather than fabricate a number, per this milestone's own brief. `triaged` in
the funnel is `None` for the same reason: nothing in this checkout runs incidents through triage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import numpy as np

if TYPE_CHECKING:
    from evals.pipeline import BenignPureRun, ScenarioRun  # see detection.py's identical note


@dataclass(slots=True)
class Funnel:
    events: int
    signals: int
    incidents: int
    triaged: int | None
    events_to_signals_reduction: float  # signals / events
    signals_to_incidents_reduction: float  # incidents / signals
    triaged_reduction: float | None


def build_report(runs: dict[str, ScenarioRun], benign_pure: BenignPureRun) -> dict[str, Any]:
    latencies = [r.elapsed_s for r in runs.values()]
    latencies_all = [*latencies, benign_pure.elapsed_s]

    total_events = (
        sum(r.result.ingest.n_events for r in runs.values()) + benign_pure.ingest.n_events
    )
    total_signals = sum(len(r.signals) for r in runs.values()) + sum(
        benign_pure.signals_by_detector.values()
    )
    total_incidents = sum(len(r.result.incidents) for r in runs.values()) + benign_pure.n_incidents

    funnel = Funnel(
        events=total_events,
        signals=total_signals,
        incidents=total_incidents,
        triaged=None,
        events_to_signals_reduction=(total_signals / total_events) if total_events else 0.0,
        signals_to_incidents_reduction=(total_incidents / total_signals) if total_signals else 0.0,
        triaged_reduction=None,
    )

    return {
        "pipeline_latency_p50_s": float(np.percentile(latencies_all, 50))
        if latencies_all
        else None,
        "pipeline_latency_p95_s": float(np.percentile(latencies_all, 95))
        if latencies_all
        else None,
        "pipeline_latency_per_scenario_s": {k: r.elapsed_s for k, r in runs.items()},
        "agent_latency_p50_ms": None,
        "agent_latency_p95_ms": None,
        "mean_tokens_per_incident": None,
        "mean_usd_per_incident": None,
        "funnel": {
            "events": funnel.events,
            "signals": funnel.signals,
            "incidents": funnel.incidents,
            "triaged": funnel.triaged,
            "events_to_signals_reduction": funnel.events_to_signals_reduction,
            "signals_to_incidents_reduction": funnel.signals_to_incidents_reduction,
            "triaged_reduction": funnel.triaged_reduction,
        },
        "not_measured": {
            "agent_latency_p50_ms": "app/agent/ has no orchestrator.py yet — no agent runs to time.",
            "agent_latency_p95_ms": "same.",
            "mean_tokens_per_incident": "same — no LLM calls made by this harness.",
            "mean_usd_per_incident": "same.",
            "funnel.triaged": "same — nothing in this checkout runs incidents through triage.",
        },
    }
