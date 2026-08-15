"""Detection metrics (docs/12 "Detection layer"): precision/recall/F1 **per detector and per
layer**, against `malicious_line_numbers`, plus false-positive rate on scenario 8 (benign-but-
weird) and on the pure-benign corpus.

## Units: signal-level precision, event-level recall — stated explicitly, not silently mixed

What this harness has to score against is exactly what the live system would ever have to show an
analyst: persisted `signals` rows (`detector_key`, `evidence_event_ids`), not a full unthresholded
candidate matrix the way `app.detection.ml.evaluate` can score L3 alone (that module has every
entity-window's raw score, flagged or not — this harness, spanning all four layers uniformly,
only has what was actually raised). So:

- **Precision** is signal-level: of the signals a detector raised in a scenario, what fraction had
  evidence overlapping `malicious_event_ids` (the file's malicious lines, joined to `events.id`
  via `raw_line_no` — see `evals/pipeline.py::_malicious_event_ids`)?
- **Recall** is event-level: of the scenario's malicious events, what fraction were covered by at
  least one of that detector's true-positive signals?

This is the standard way an alerting system gets scored (an analyst reads *alerts*; precision asks
"were the alerts right", recall asks "was the attack covered") and it is what `evals/results.md`
states plainly rather than presenting as docs/12's textbook TP/(TP+FN) formula computed on a
single, uniform unit — that formula *is* used, just on two different natural units for the two
different questions it is being asked to answer.

The detector **registry** (which keys exist to report a zero-row for, even when a detector never
fired) is read live from each layer's own source of truth — `app.detection.sigma.runner.
load_rules()`, `app.detection.signal.constants`, `app.detection.ml.detect`'s exported model keys,
`app.graph.features.GRAPH_FEATURE_NAMES` — so this table is "automatic" per docs/12, not
hand-maintained, and a detector added or removed in any of those (concurrently-developed) packages
is picked up here without an edit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.core.logging import get_logger
from app.models.signal import Signal
from evals.config import ATTACK_SCENARIO_KEYS, FP_CONTROL_SCENARIO, SCENARIO_KEYS

if TYPE_CHECKING:
    # Deferred: `evals.pipeline` pulls in torch/lightgbm/SQLAlchemy at import time (it drives the
    # live DB pipeline) and these two names are used here purely as parameter annotations, never
    # instantiated or called — `from __future__ import annotations` (above) already makes every
    # annotation in this file a lazy string, so this module can be imported (and unit-tested) on
    # its own without paying for that dependency chain.
    from evals.pipeline import BenignPureRun, ScenarioRun

log = get_logger(__name__)


def known_detector_registry() -> dict[str, str]:
    """`{detector_key: detector_layer}` for every detector this codebase currently ships, read
    live from each layer's own source of truth. Never hardcoded — see module docstring."""
    registry: dict[str, str] = {}

    try:
        from app.detection.sigma.runner import load_rules

        for rule in load_rules():
            registry[rule.detector_key] = "rule"
    except Exception:
        log.warning("detection.registry.sigma_unavailable", exc_info=True)

    try:
        from app.detection.signal import constants as sig_constants

        for name in (
            "SIGNAL_BEACONING",
            "SIGNAL_DGA",
            "SIGNAL_BURST",
            "SIGNAL_RARITY",
            "SIGNAL_STL_RESIDUAL",
            "SIGNAL_URL_PATH",
        ):
            key = getattr(sig_constants, name, None)
            if key:
                registry[key] = "signal"
    except Exception:
        log.warning("detection.registry.signal_unavailable", exc_info=True)

    try:
        from app.detection.ml import detect as ml_detect

        for name in ("ML_IFOREST", "ML_MAHALANOBIS", "ML_ECOD", "ML_PEER_GROUP", "ML_AUTOENCODER"):
            key = getattr(ml_detect, name, None)
            if key:
                registry[key] = "ml"
    except Exception:
        log.warning("detection.registry.ml_unavailable", exc_info=True)

    try:
        from app.graph.features import GRAPH_FEATURE_NAMES

        for feature in GRAPH_FEATURE_NAMES:
            registry[f"graph.{feature}"] = "graph"
    except Exception:
        log.warning("detection.registry.graph_unavailable", exc_info=True)

    return registry


@dataclass(slots=True)
class DetectorScenarioRow:
    scenario: str
    detector_key: str
    detector_layer: str
    n_signals: int
    n_tp_signals: int
    n_fp_signals: int
    n_malicious_events: int
    n_malicious_events_covered: int
    precision: float | None  # None = detector never fired (undefined, not zero)
    recall: float | None  # None = scenario has no malicious events for this detector to find
    f1: float | None
    detected: bool


def _f1(p: float | None, r: float | None) -> float | None:
    if p is None or r is None or (p + r) == 0:
        return 0.0 if (p is not None and r is not None) else None
    return 2 * p * r / (p + r)


def score_scenario(run: ScenarioRun, registry: dict[str, str]) -> list[DetectorScenarioRow]:
    """One `DetectorScenarioRow` per known detector for this scenario (zero-rows included)."""
    by_detector: dict[str, list[Signal]] = {}
    for s in run.signals:
        by_detector.setdefault(s.detector_key, []).append(s)

    n_malicious = len(run.malicious_event_ids)
    rows: list[DetectorScenarioRow] = []
    seen_keys = set(registry) | set(by_detector)
    for key in sorted(seen_keys):
        layer = registry.get(key) or (
            by_detector[key][0].detector_layer if key in by_detector else "unknown"
        )
        sigs = by_detector.get(key, [])
        n_signals = len(sigs)
        tp_sigs = [s for s in sigs if set(s.evidence_event_ids) & run.malicious_event_ids]
        n_tp = len(tp_sigs)
        n_fp = n_signals - n_tp
        covered: set[int] = set()
        for s in tp_sigs:
            covered |= set(s.evidence_event_ids) & run.malicious_event_ids
        precision = (n_tp / n_signals) if n_signals else None
        recall = (len(covered) / n_malicious) if n_malicious else None
        rows.append(
            DetectorScenarioRow(
                scenario=run.key,
                detector_key=key,
                detector_layer=layer,
                n_signals=n_signals,
                n_tp_signals=n_tp,
                n_fp_signals=n_fp,
                n_malicious_events=n_malicious,
                n_malicious_events_covered=len(covered),
                precision=precision,
                recall=recall,
                f1=_f1(precision, recall),
                detected=len(covered) > 0,
            )
        )
    return rows


@dataclass(slots=True)
class LayerAggregate:
    layer: str
    mean_f1: float
    mean_precision: float
    mean_recall: float
    n_detector_scenario_pairs_fired: int
    n_detector_scenario_pairs_total: int


@dataclass(slots=True)
class DetectionReport:
    per_scenario_detector: list[DetectorScenarioRow]
    per_detector_aggregate: dict[
        str, dict[str, float]
    ]  # detector_key -> {mean_f1, mean_precision, mean_recall, n_scenarios_detected}
    per_layer_aggregate: dict[str, LayerAggregate]
    detection_f1_aggregate: float  # single gated scalar (docs/12 regression gate)
    fp_rate_scenario8: dict[str, float]  # detector_key -> signals / n_events
    fp_rate_benign_pure: dict[str, float]
    fp_rate_scenario8_total: float
    fp_rate_benign_pure_total: float


def build_report(runs: dict[str, ScenarioRun], benign_pure: BenignPureRun) -> DetectionReport:
    registry = known_detector_registry()
    per_scenario_detector: list[DetectorScenarioRow] = []
    for key in SCENARIO_KEYS:
        if key not in runs:
            continue
        per_scenario_detector.extend(score_scenario(runs[key], registry))

    # Aggregate per detector, over ATTACK_SCENARIO_KEYS only (the canary and FP-control are not
    # detection targets — same exclusion `app.detection.ml.evaluate._aggregate_metrics` makes).
    attack_rows = [r for r in per_scenario_detector if r.scenario in ATTACK_SCENARIO_KEYS]
    per_detector_aggregate: dict[str, dict[str, float]] = {}
    for key in sorted({r.detector_key for r in attack_rows}):
        rows = [r for r in attack_rows if r.detector_key == key]
        f1s = [r.f1 for r in rows if r.f1 is not None]
        precisions = [r.precision for r in rows if r.precision is not None]
        recalls = [r.recall for r in rows if r.recall is not None]
        per_detector_aggregate[key] = {
            "mean_f1": (sum(f1s) / len(f1s)) if f1s else 0.0,
            "mean_precision": (sum(precisions) / len(precisions)) if precisions else 0.0,
            "mean_recall": (sum(recalls) / len(recalls)) if recalls else 0.0,
            "n_scenarios_detected": float(sum(1 for r in rows if r.detected)),
            "n_scenarios": float(len(rows)),
        }

    per_layer_aggregate: dict[str, LayerAggregate] = {}
    for layer in sorted({r.detector_layer for r in attack_rows}):
        rows = [r for r in attack_rows if r.detector_layer == layer]
        f1s = [r.f1 for r in rows if r.f1 is not None]
        precisions = [r.precision for r in rows if r.precision is not None]
        recalls = [r.recall for r in rows if r.recall is not None]
        per_layer_aggregate[layer] = LayerAggregate(
            layer=layer,
            mean_f1=(sum(f1s) / len(f1s)) if f1s else 0.0,
            mean_precision=(sum(precisions) / len(precisions)) if precisions else 0.0,
            mean_recall=(sum(recalls) / len(recalls)) if recalls else 0.0,
            n_detector_scenario_pairs_fired=sum(1 for r in rows if r.n_signals > 0),
            n_detector_scenario_pairs_total=len(rows),
        )

    all_f1s = [v["mean_f1"] for v in per_detector_aggregate.values()]
    detection_f1_aggregate = (sum(all_f1s) / len(all_f1s)) if all_f1s else 0.0

    # False-positive rate: scenario 8 (benign-but-weird — must NOT fire, docs/11) and the pure-
    # benign corpus. Every signal raised on either is a false positive by construction (zero
    # malicious lines in both files) — fp_rate = n_signals(detector) / n_events(file).
    fp_rate_scenario8: dict[str, float] = {}
    scenario8_rows = [r for r in per_scenario_detector if r.scenario == FP_CONTROL_SCENARIO]
    n_events_scenario8 = (
        runs[FP_CONTROL_SCENARIO].result.ingest.n_events if FP_CONTROL_SCENARIO in runs else 0
    )
    for r in scenario8_rows:
        if r.n_signals:
            fp_rate_scenario8[r.detector_key] = (
                r.n_signals / n_events_scenario8 if n_events_scenario8 else 0.0
            )
    total_signals_scenario8 = sum(r.n_signals for r in scenario8_rows)
    fp_rate_scenario8_total = (
        total_signals_scenario8 / n_events_scenario8 if n_events_scenario8 else 0.0
    )

    fp_rate_benign_pure: dict[str, float] = {}
    n_events_benign_pure = benign_pure.ingest.n_events
    for key, n_signals in benign_pure.signals_by_detector.items():
        fp_rate_benign_pure[key] = n_signals / n_events_benign_pure if n_events_benign_pure else 0.0
    total_signals_benign_pure = sum(benign_pure.signals_by_detector.values())
    fp_rate_benign_pure_total = (
        total_signals_benign_pure / n_events_benign_pure if n_events_benign_pure else 0.0
    )

    return DetectionReport(
        per_scenario_detector=per_scenario_detector,
        per_detector_aggregate=per_detector_aggregate,
        per_layer_aggregate=per_layer_aggregate,
        detection_f1_aggregate=detection_f1_aggregate,
        fp_rate_scenario8=fp_rate_scenario8,
        fp_rate_benign_pure=fp_rate_benign_pure,
        fp_rate_scenario8_total=fp_rate_scenario8_total,
        fp_rate_benign_pure_total=fp_rate_benign_pure_total,
    )
