"""Correlation metrics (docs/12): `incident_recall` (scenarios whose malicious events landed in
ONE incident / total) and `fragmentation` (mean incidents per scenario, target 1.0).

Thin wrapper over `app.graph.pipeline_demo.correlation_metrics` — the M10 milestone's own
implementation of exactly this docs/12 formula (re-exported from `evals.pipeline`), applied to
the four scenarios docs/11 marks `must_correlate_into_one_incident: true`
(`evals.config.CORRELATION_SCENARIO_KEYS`). The other four golden scenarios (peer-group and
seasonal deviation, the injection canary, benign-but-weird) are not scored for correlation: two
are new additions this milestone's own ground truth does not mark `must_correlate_into_one_
incident` for (LOF/STL-detected scenarios were added at M8b specifically to test L3/L2 detection,
not correlation), and the other two have no malicious events to correlate at all.
"""

from __future__ import annotations

from typing import Any

from evals.config import CORRELATION_SCENARIO_KEYS
from evals.pipeline import ScenarioRun, correlation_metrics


def build_report(runs: dict[str, ScenarioRun]) -> dict[str, Any]:
    selected = [runs[k].result for k in CORRELATION_SCENARIO_KEYS if k in runs]
    missing = [k for k in CORRELATION_SCENARIO_KEYS if k not in runs]
    metrics = correlation_metrics(selected)
    metrics["scenarios_scored"] = [k for k in CORRELATION_SCENARIO_KEYS if k in runs]
    metrics["scenarios_missing"] = missing
    return metrics
