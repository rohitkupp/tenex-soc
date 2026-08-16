"""Runs the real L1 (Sigma) -> L2 (signal) -> L3 (ml) -> L5 (graph) -> fusion -> incident pipeline
over the golden scenario set, via `app.graph.pipeline_demo` — the M10 milestone's own end-to-end
verification harness (`app/graph/pipeline_demo.py`'s module docstring: "parse -> events -> L1/L2/
L3 detectors -> calibrate -> entity graph -> L5 graph features -> incidents -> fuse & severity").
No `classify` stage: migration change 19 (`docs/v2_migration/MIGRATION-01-evidence-first.md`)
removed `app.graph.classifier`'s LightGBM technique classifier this module used to load
(`load_classifier`, deleted with it) and thread through `run_golden_scenarios`/`run_benign_pure`;
multiclass technique attribution is the LLM hypothesis-evaluation stage's job now (docs/07), out
of this milestone's ownership. This module is the thin evals-owned glue around it: an isolated
calibrator store (so
this harness never races the shared `data/models/calibrators/` directory other concurrently-
developed code reads/writes), per-scenario timing, re-querying persisted `Signal` rows for
per-detector precision/recall, a benign-only-corpus runner (`run_scenario` itself requires a
scenario's `.labels.json`, which a pure-benign file has none of), and tenant cleanup so repeated
`make eval` runs do not accumulate scratch rows in a shared database forever.

Everything here calls *public* `app.graph.pipeline_demo` functions (`run_scenario`,
`correlation_metrics`) except for four read-only internals reused deliberately rather than
duplicated: `_run_l1/_run_l2/_run_l3/_run_l5` (the per-layer signal runners — exactly the
decomposition this harness's own calibration-fitting step needs), `_calibration_feature` (the
one-line burst-abs-value/NaN-sanitize rule calibration fitting must match exactly), `_load_ground_
truth` (a `.labels.json` parser), and `_line_to_event_id` (a three-line `raw_line_no -> events.id`
lookup). All five are read-only reuse of already-built, already-tested code — no modification to
`app/graph/pipeline_demo.py`, per this milestone's ownership boundary.
"""

from __future__ import annotations

import math
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select

from app.core.db import get_session_factory
from app.core.logging import get_logger
from app.detection.calibration import CalibratorStore, DetectorSample, fit_calibrators
from app.graph.builder import fetch_graph_events
from app.graph.ingest import IngestResult, ingest_log_file
from app.graph.pipeline_demo import (
    RunResult,
    _calibration_feature,
    _line_to_event_id,
    _load_ground_truth,
    _run_l1,
    _run_l2,
    _run_l3,
    _run_l5,
    correlation_metrics,
    run_scenario,
)
from app.models.base import tenant_scope
from app.models.signal import Signal
from evals import golden
from evals.config import (
    CALIBRATION_SEED,
    EVAL_CALIBRATORS_DIR,
    EVAL_SEED,
    GOLDEN_EVENTS_PER_SCENARIO,
    SCENARIO_KEYS,
)
from evals.db import cleanup_tenants

log = get_logger(__name__)


# ---------------------------------------------------------------------------- known upstream defect
#
# `app.graph.features.graph_signals_for_incident` persists each graph signal's raw z-score
# straight into `Signal.explanation` (JSONB). `robust_z` (`app.detection.features`, the single
# canonical implementation every layer shares) legitimately returns +/-inf when a feature's
# reference population has zero MAD (a real, documented policy — see that module's own
# docstring) -- and Postgres JSONB has no representation for `Infinity`/`NaN` (`json.dumps`
# happily emits the literal token `Infinity`, which is not valid JSON, and psycopg's insert then
# fails with `InvalidTextRepresentation`). `app.graph.pipeline_demo._calibration_feature` already
# works around the identical root cause for the *calibration* path (sanitizing to a finite
# `_INF_SENTINEL = 1e6`) but `app/graph/features.py`'s own `explanation` payload was never given
# the same treatment -- a real, narrow bug in code this milestone does not own (`app/graph/**`)
# and cannot edit. Verified empirically: every one of the eight golden scenarios hits it (the
# 120-user/6-department org this harness uses for CI speed produces enough nodes with identical
# `fan_out` to zero out that population's MAD).
#
# Rather than let it take down the whole harness, this module applies the *exact same* finite-
# sentinel policy `_calibration_feature` already established for this exact defect, as a
# process-local monkeypatch of `app.graph.features`'s own `robust_z` binding (not a change to any
# file under `app/**`) -- documented here, and in `evals/results.md`'s Known Weaknesses section,
# as a found defect worked around, not silently hidden.
def _install_robust_z_sanitizer() -> None:
    from app.detection import features as detection_features
    from app.graph import features as graph_features

    if getattr(detection_features.robust_z, "_eval_harness_sanitized", False):
        return

    original = detection_features.robust_z

    def sanitized(*args: object, **kwargs: object) -> float:
        value = original(*args, **kwargs)  # type: ignore[arg-type]
        if value != value:  # NaN
            return 0.0
        if value in (float("inf"), float("-inf")):
            return math.copysign(1e6, value)
        return value

    sanitized._eval_harness_sanitized = True  # type: ignore[attr-defined]
    graph_features.robust_z = sanitized
    log.warning(
        "pipeline.robust_z_sanitizer_installed",
        reason="Signal.explanation z_score=Infinity is not valid JSONB",
    )


_install_robust_z_sanitizer()

# Calibration fitting reuses the *same* event count/org spec as the golden set. Tempting as it is
# to shrink this for a faster fit (calibration only needs labeled samples per detector_key, not a
# realistic benchmark — docs/04's own `MIN_SAMPLES_TO_FIT = 8` is a low bar), several scenarios'
# own generators (`s04_low_and_slow_exfil.py`, `s05_peer_group_deviation.py`) enforce an
# acceptance gate at *injection time* that raises rather than degrading at low event volume on
# this org size (verified empirically: `peer_group_deviation` fails its gate below ~15,000 events
# at this 120-user org, every seed tried). Matching `GOLDEN_EVENTS_PER_SCENARIO` sidesteps that
# rather than chasing a second, separately-tuned "just barely enough" constant.
_CALIBRATION_FIT_EVENTS = GOLDEN_EVENTS_PER_SCENARIO


def fit_isolated_calibrators(
    *, seed: int = CALIBRATION_SEED, events: int = _CALIBRATION_FIT_EVENTS
) -> CalibratorStore:
    """Fit one isotonic calibrator per detector_key (L1/L2/L3/L5, whatever the live packages
    currently ship) on a held-out seed, saved to this harness's OWN `EVAL_CALIBRATORS_DIR` — never
    the shared `data/models/calibrators/` directory `app.detection.calibration.CalibratorStore`
    defaults to. Mirrors `app.graph.pipeline_demo.fit_layer_calibrators` exactly except for that
    one substitution (this milestone cannot modify that function to accept a directory argument —
    `app/graph/pipeline_demo.py` is out of this milestone's ownership)."""
    t0 = time.perf_counter()
    samples: list[DetectorSample] = []
    tenant_ids: list[uuid.UUID] = []

    with tempfile.TemporaryDirectory(prefix="tenex-eval-calfit-") as tmp:
        fit_dir = Path(tmp)
        for key in SCENARIO_KEYS:
            scenario_dir = fit_dir / key
            golden.generate_scenario(key, seed, scenario_dir, events)
            log_path = sorted(scenario_dir.glob("*.log"))[0]
            labels_path = sorted(scenario_dir.glob("*.labels.json"))[0]
            ground_truth = _load_ground_truth(labels_path)

            session = get_session_factory()()
            try:
                ingest: IngestResult = ingest_log_file(session, path=log_path)
                tenant_ids.append(ingest.tenant_id)
                line_to_event_id = _line_to_event_id(session, ingest.analysis_id, ingest.tenant_id)
                malicious_event_ids = {
                    line_to_event_id[ln]
                    for ln in ground_truth.malicious_line_numbers
                    if ln in line_to_event_id
                }
                l1 = _run_l1(ingest.analysis_id, ingest.tenant_id)
                l2 = _run_l2(session, ingest.analysis_id, ingest.tenant_id)
                l3, _l3_df, _bundle = _run_l3(log_path, line_to_event_id)
                with tenant_scope(session, ingest.tenant_id):
                    graph_events = fetch_graph_events(session, ingest.analysis_id)
                _build, _node_features, l5 = _run_l5(graph_events)
            finally:
                session.close()

            for rs in l1 + l2 + l3 + l5:
                label = int(bool(malicious_event_ids & set(rs.evidence_event_ids)))
                feature = _calibration_feature(rs.detector_key, rs.raw_score)
                samples.append(
                    DetectorSample(detector_key=rs.detector_key, raw_score=feature, label=label)
                )
            log.info("calibration_fit.scenario_done", scenario=key, n_samples=len(samples))

    calibrators = fit_calibrators(samples)
    store = CalibratorStore(directory=EVAL_CALIBRATORS_DIR)
    store.save_all(calibrators)
    cleanup_tenants(tenant_ids)
    log.info(
        "calibration_fit.done",
        detectors=sorted(calibrators),
        n_samples={k: c.n_samples for k, c in calibrators.items()},
        elapsed_s=round(time.perf_counter() - t0, 2),
    )
    return store


def ml_fp_counts_for_file(log_path: Path) -> dict[str, int]:
    """`{detector_key: n_flagged_entity_windows}` for **every** model in `app.detection.ml.
    detect.ML_MODEL_FIELDS` (all six -- iforest, mahalanobis, ecod, peer_group/LOF, eif, kth_nn),
    scored directly against `log_path` at the live-pipeline confidence threshold. This is the fix
    for docs/12's change 1 ("Measure the missing false-positive rates"): `run_scenario`'s own
    persisted-`Signal` path only ever scores `SHIPPED_MODEL_FIELDS` (`_run_l3` inside
    `app.graph.pipeline_demo`, reused above) -- deliberately, so the eval harness's simulated
    fusion/incident-formation stays faithful to what migration change 19 actually made production
    score. That means `ml.ecod`/`ml.eif`/`ml.kth_nn` never produce persisted signals in this
    harness at all, so their false-positive rate on either control file was unmeasurable from
    persisted signals alone -- not merely omitted by a hardcoded list (though `evals.metrics.
    detection.known_detector_registry`'s ml section *was* also that same class of bug, fixed
    separately). This function is a second, independent, benchmark-style scoring pass -- it loads
    `MLModelBundle` and scores the file directly, exactly the way `app.detection.ml.evaluate`
    already does for its own FP-rate figures -- and never persists a `Signal` row or touches
    `form_incidents`/`fuse_signals`, so it cannot perturb `run_scenario`'s production-fidelity
    incident metrics. Call it against `evals.golden.scenario_log_and_labels(FP_CONTROL_SCENARIO)`
    and `evals.golden.benign_pure_log()` -- the two files every signal on which is a false
    positive by construction (docs/12)."""
    from app.detection.ml.detect import ML_MODEL_FIELDS, SIGNAL_CONFIDENCE_THRESHOLD, MLModelBundle
    from app.detection.ml.events import load_ml_events
    from app.detection.ml.features import build_entity_window_features

    events = load_ml_events({"zscaler": log_path})
    df = build_entity_window_features(events)
    if df.empty:
        return dict.fromkeys(ML_MODEL_FIELDS, 0)

    bundle = MLModelBundle.load()
    x_scaled = bundle.transform(df)
    counts: dict[str, int] = {}
    for key, bundle_field in ML_MODEL_FIELDS.items():
        model = getattr(bundle, bundle_field)
        raw = model.raw_scores(x_scaled)
        conf = model.confidence(raw)
        counts[key] = int((conf >= SIGNAL_CONFIDENCE_THRESHOLD).sum())
    return counts


@dataclass(slots=True)
class ScenarioRun:
    key: str
    result: RunResult
    signals: list[Signal]
    malicious_event_ids: frozenset[int]
    elapsed_s: float


def _malicious_event_ids(result: RunResult) -> frozenset[int]:
    """`ground_truth.malicious_line_numbers` (file line numbers, docs/11) -> real `events.id`
    values, via `Event.raw_line_no` — the same join `app.graph.pipeline_demo`'s own
    `_malicious_event_ids` does, reused here so `evals/metrics/detection.py` can score persisted
    `Signal.evidence_event_ids` (real event ids) against ground truth without a third copy of this
    three-line lookup."""
    session = get_session_factory()()
    try:
        line_to_event_id = _line_to_event_id(
            session, result.ingest.analysis_id, result.ingest.tenant_id
        )
    finally:
        session.close()
    return frozenset(
        line_to_event_id[ln]
        for ln in result.ground_truth.malicious_line_numbers
        if ln in line_to_event_id
    )


def _fetch_signals(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> list[Signal]:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            rows = list(
                session.execute(select(Signal).where(Signal.analysis_id == analysis_id)).scalars()
            )
        return rows
    finally:
        session.close()


def run_golden_scenarios(
    *, calibrators: CalibratorStore
) -> tuple[dict[str, ScenarioRun], list[uuid.UUID]]:
    """Run every one of docs/11's eight golden scenarios end to end (L1-L5, fusion, incidents),
    against the frozen `evals/golden/<key>/` files. Returns `{key: ScenarioRun}` plus the list of
    scratch tenant ids created, for the caller to clean up once every metric that needs the live
    rows has read them."""
    golden.ensure_golden_set(seed=EVAL_SEED)
    runs: dict[str, ScenarioRun] = {}
    tenant_ids: list[uuid.UUID] = []
    for key in SCENARIO_KEYS:
        t0 = time.perf_counter()
        result = run_scenario(
            scenario=key,
            seed=EVAL_SEED,
            events=GOLDEN_EVENTS_PER_SCENARIO,
            out_dir=golden.scenario_dir(key),
            calibrators=calibrators,
        )
        elapsed = time.perf_counter() - t0
        signals = _fetch_signals(result.ingest.analysis_id, result.ingest.tenant_id)
        malicious_event_ids = _malicious_event_ids(result)
        tenant_ids.append(result.ingest.tenant_id)
        runs[key] = ScenarioRun(
            key=key,
            result=result,
            signals=signals,
            malicious_event_ids=malicious_event_ids,
            elapsed_s=elapsed,
        )
        log.info(
            "golden.scenario_run_done",
            scenario=key,
            n_events=result.ingest.n_events,
            n_signals=len(signals),
            n_incidents=len(result.incidents),
            elapsed_s=round(elapsed, 2),
        )
    return runs, tenant_ids


@dataclass(slots=True)
class BenignPureRun:
    ingest: IngestResult
    signals_by_detector: dict[str, int] = field(default_factory=dict)
    n_incidents: int = 0
    elapsed_s: float = 0.0
    reliability_samples: list[tuple[float, int]] = field(default_factory=list)


def run_benign_pure(*, calibrators: CalibratorStore) -> tuple[BenignPureRun, list[uuid.UUID]]:
    """Run L1-L5 over the pure-benign FP-control corpus (docs/12: false-positive rate "on pure
    benign files"). No `.labels.json` exists for this file (`datagen benign` does not write one,
    unlike `datagen scenario`) so `app.graph.pipeline_demo.run_scenario` cannot be reused directly
    — every signal raised here is by construction a false positive, so ground truth is simply
    "everything is benign" and this function only needs the per-layer raw signal counts, not the
    full incident-formation/fusion machinery `run_scenario` also does (though it is included for
    a secondary "spurious incidents on clean data" datapoint, at negligible extra cost)."""
    from app.detection.fusion import FusionInput, score_incident
    from app.graph.incidents import SignalRef, form_incidents

    t0 = time.perf_counter()
    log_path = golden.benign_pure_log()
    session = get_session_factory()()
    try:
        ingest = ingest_log_file(session, path=log_path)
        line_to_event_id = _line_to_event_id(session, ingest.analysis_id, ingest.tenant_id)
        l1 = _run_l1(ingest.analysis_id, ingest.tenant_id)
        l2 = _run_l2(session, ingest.analysis_id, ingest.tenant_id)
        l3, _l3_df, _bundle = _run_l3(log_path, line_to_event_id)
        with tenant_scope(session, ingest.tenant_id):
            graph_events = fetch_graph_events(session, ingest.analysis_id)
        build, _node_features, l5 = _run_l5(graph_events)
    finally:
        session.close()
    graph = build.graph

    all_raw = l1 + l2 + l3 + l5
    counts: dict[str, int] = {}
    signal_refs: list[SignalRef] = []
    reliability_samples: list[tuple[float, int]] = []
    for i, rs in enumerate(all_raw):
        counts[rs.detector_key] = counts.get(rs.detector_key, 0) + 1
        feature = _calibration_feature(rs.detector_key, rs.raw_score)
        confidence = calibrators.calibrate(rs.detector_key, feature)
        reliability_samples.append((confidence, 0))  # pure-benign corpus: every signal is label=0
        signal_refs.append(
            SignalRef(
                signal_id=i,
                detector_key=rs.detector_key,
                detector_layer=rs.detector_layer,
                confidence=confidence,
                entity_type=rs.entity_type,
                entity_value=rs.entity_value,
                mitre_technique=rs.mitre_technique,
                evidence_event_ids=tuple(rs.evidence_event_ids),
                window_start=rs.window_start,
                window_end=rs.window_end,
            )
        )

    n_incidents = 0
    if signal_refs:
        candidates = form_incidents(graph, signal_refs)
        for candidate in candidates:
            fusion_inputs = [
                FusionInput(
                    detector_key=s.detector_key,
                    detector_layer=s.detector_layer,
                    confidence=s.confidence,
                )
                for s in candidate.signals
            ]
            score_incident(
                fusion_inputs, community_signal_density=candidate.community_signal_density
            )
        n_incidents = len(candidates)

    elapsed = time.perf_counter() - t0
    log.info(
        "benign_pure.done",
        n_events=ingest.n_events,
        n_signals=len(all_raw),
        n_incidents=n_incidents,
        elapsed_s=round(elapsed, 2),
    )
    run = BenignPureRun(
        ingest=ingest,
        signals_by_detector=counts,
        n_incidents=n_incidents,
        elapsed_s=elapsed,
        reliability_samples=reliability_samples,
    )
    return run, [ingest.tenant_id]


__all__ = [
    "BenignPureRun",
    "ScenarioRun",
    "correlation_metrics",
    "fit_isolated_calibrators",
    "ml_fp_counts_for_file",
    "run_benign_pure",
    "run_golden_scenarios",
]
