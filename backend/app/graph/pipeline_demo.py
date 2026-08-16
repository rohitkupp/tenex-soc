"""End-to-end M10 verification: parse -> events (Postgres) -> L1/L2/L3 detectors -> calibrate ->
entity graph -> L5 graph features -> incidents -> fuse & severity -> title -> timeline ->
recurrence -> persist.

    python -m app.graph.pipeline_demo run --scenario c2_beaconing --seed 7 --events 50000
    python -m app.graph.pipeline_demo fit-calibrators
    python -m app.graph.pipeline_demo full-report

This module is the orchestration glue docs/13 M10's verification bar asks for ("load a real
generated scenario end to end ... show the incidents formed, their fused scores and
severities"). It reuses, read-only, every layer this milestone does not own
(`app.detection.sigma.runner`, `app.detection.evidence.*`, `app.detection.ml.*`) exactly as a
future `app/pipeline` orchestrator would, and owns only the M10-specific glue: turning each
layer's raw output into one common `RawSignal` shape, calibrating it
(`app.detection.calibration`), building the graph (`app.graph.builder`), forming incidents
(`app.graph.incidents`), scoring them (`app.detection.fusion`), titling, and linking recurrences.

**No `classify` stage, and no `train-classifier` command.** The pipeline used to run `L5 graph ->
classify -> fuse` (docs/04's old ordering) via `app.graph.classifier`'s LightGBM technique
classifier; migration change 19 (`docs/v2_migration/MIGRATION-01-evidence-first.md`) deleted that
model -- multiclass technique attribution is the LLM hypothesis-evaluation stage's job now
(`docs/07`, out of this package's ownership), not a stage this offline demo pipeline performs
itself. `_pick_top_technique` below falls back to `None` (`NO_KNOWN_MAPPING`, in the language of
docs/07) when no L1/L2 rule already supplied a technique for an incident's signals, rather than
asking a second, now-nonexistent classifier to guess one.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_engine, get_session_factory
from app.core.logging import configure_logging, get_logger
from app.detection.calibration import (
    CALIBRATION_FIT_SEED,
    CalibratorStore,
    DetectorSample,
    fit_calibrators,
    reliability_diagram,
)
from app.detection.evidence.beaconing import detect_beaconing
from app.detection.evidence.burst import detect_burst
from app.detection.evidence.dga import detect_dga
from app.detection.evidence.dga import load_artifact as load_dga_artifact
from app.detection.evidence.events_dao import fetch_event_rows
from app.detection.evidence.rarity import detect_rarity
from app.detection.fusion import FusionInput, score_incident
from app.detection.sigma.runner import run_rules as sigma_run_rules
from app.graph.builder import (
    EntityKey,
    GraphEvent,
    build_entity_graph,
    fetch_graph_events,
    persist_entity_graph,
)
from app.graph.features import NodeFeatures, compute_node_features, graph_signals_for_incident
from app.graph.incidents import IncidentCandidate, SignalRef, form_incidents
from app.graph.ingest import IngestResult, ingest_log_file
from app.graph.recurrence import canonical_text, embed_text, link_recurrence
from app.graph.timeline import build_timeline
from app.graph.titling import title_for_incident
from app.models.base import tenant_scope
from app.models.detector_stats import DetectorStats
from app.models.event import Event
from app.models.incident import Incident
from app.models.signal import Signal

log = get_logger(__name__)

_BACKEND_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

# Same six scenario keys `app.detection.ml.evaluate` benchmarks (docs/11); the four with an
# attached ATT&CK technique and `must_correlate_into_one_incident: true` are what
# `incident_recall`/`fragmentation` (docs/12) are measured against.
CORRELATION_SCENARIO_KEYS: Final[tuple[str, ...]] = (
    "c2_beaconing",
    "data_exfiltration",
    "insider_mass_download",
    "low_and_slow_exfil",
)

# signal.burst's raw_score is a signed z-score (docs/04: flag |z| > 3.5) -- calibrated on its
# absolute value, and any +/-inf (robust_z's documented MAD==0 policy) sanitized to a large
# finite sentinel before it reaches sklearn.
_BURST_DETECTOR_KEY: Final[str] = "signal.burst"
_INF_SENTINEL: Final[float] = 1e6


def _calibration_feature(detector_key: str, raw_score: float) -> float:
    x = raw_score
    if x != x:  # NaN
        x = 0.0
    elif x in (float("inf"), float("-inf")):
        x = _INF_SENTINEL if x > 0 else -_INF_SENTINEL
    if detector_key == _BURST_DETECTOR_KEY:
        x = abs(x)
    return x


# ---------------------------------------------------------------------------- common signal shape


@dataclass(slots=True)
class RawSignal:
    detector_key: str
    detector_layer: str
    raw_score: float
    entity_type: str
    entity_value: str
    evidence_event_ids: list[int]
    explanation: dict[str, Any]
    window_start: datetime | None = None
    window_end: datetime | None = None
    mitre_technique: str | None = None


# ---------------------------------------------------------------------------- per-layer runners


def _run_l1(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> list[RawSignal]:
    with get_engine().connect() as conn:
        drafts = sigma_run_rules(conn, analysis_id, tenant_id)
    return [
        RawSignal(
            detector_key=d.detector_key,
            detector_layer="rule",
            raw_score=d.raw_score,
            entity_type=d.entity_type,
            entity_value=d.entity_value,
            window_start=d.window_start,
            window_end=d.window_end,
            evidence_event_ids=list(d.evidence_event_ids),
            explanation=d.explanation,
            mitre_technique=d.mitre_technique,
        )
        for d in drafts
    ]


def _run_l2(session: Session, analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> list[RawSignal]:
    with tenant_scope(session, tenant_id):
        rows = fetch_event_rows(session, analysis_id)
    artifact = load_dga_artifact()
    drafts = [
        *detect_beaconing(rows),
        *detect_dga(rows, artifact=artifact),
        *detect_burst(rows),
        *detect_rarity(rows),
    ]
    return [
        RawSignal(
            detector_key=d.detector_key,
            detector_layer="signal",
            raw_score=d.raw_score,
            entity_type=d.entity_type,
            entity_value=d.entity_value,
            window_start=d.window_start,
            window_end=d.window_end,
            evidence_event_ids=list(d.evidence_event_ids),
            explanation=d.explanation,
            mitre_technique=d.mitre_technique,
        )
        for d in drafts
    ]


def _ml_model_pairs(bundle: Any) -> list[tuple[str, Any]]:
    """`[(detector_key, model), ...]` for every L3 model the *current*
    `app.detection.ml.detect.MLModelBundle` exposes -- see
    `app.detection.calibration._model_pairs`'s docstring for why this is read dynamically off
    that package's own constants rather than hardcoded (it grew from three models to five during
    this milestone's own development window, then back down to four when migration change 19 cut
    the autoencoder)."""
    from app.detection.ml import detect as ml_detect

    return [
        (ml_detect.ML_IFOREST, bundle.iforest),
        (ml_detect.ML_MAHALANOBIS, bundle.mahalanobis),
        (ml_detect.ML_ECOD, bundle.ecod),
        (ml_detect.ML_PEER_GROUP, bundle.lof),
    ]


def _run_l3(log_path: Path, line_to_event_id: dict[int, int]) -> tuple[list[RawSignal], Any, Any]:
    """L3 signals for the demo path. Pre-filters on each model's own uncalibrated percentile
    confidence (`SIGNAL_CONFIDENCE_THRESHOLD`, the same cheap gate `app.detection.ml.detect.
    score_entity_windows` itself applies) *before* computing `explain_row` -- SHAP attribution is
    the expensive part of this loop, and computing it for every one of tens of thousands of
    entity-window rows across all five models (instead of only the ~0.5% that clear the
    threshold) is what made an earlier version of this function take 20+ minutes on a single
    50k-event scenario. Every other L1/L2 detector already pre-filters on its own raw score
    before producing a draft at all (beaconing's score threshold, burst's `|z| > 3.5`, ...); this
    restores the same discipline for L3 rather than trying to keep every row for later
    calibration -- calibration-sample collection is `_run_l3_calibration_samples`'s job instead,
    which needs `raw_score` only and never calls `explain_row`.
    """
    from app.detection.ml.detect import SIGNAL_CONFIDENCE_THRESHOLD, MLModelBundle
    from app.detection.ml.events import load_ml_events
    from app.detection.ml.features import build_entity_window_features

    events = load_ml_events({"zscaler": log_path})
    df = build_entity_window_features(events)
    bundle = MLModelBundle.load()
    if df.empty:
        return [], df, bundle
    x_scaled = bundle.transform(df)

    signals: list[RawSignal] = []
    for detector_key, model in _ml_model_pairs(bundle):
        raw = model.raw_scores(x_scaled)
        conf = model.confidence(raw)
        candidate_idx = np.flatnonzero(conf >= SIGNAL_CONFIDENCE_THRESHOLD)
        for i in candidate_idx:
            row = df.iloc[i]
            evidence = [
                line_to_event_id[ln] for ln in row["line_numbers"] if ln in line_to_event_id
            ]
            if not evidence:
                continue
            signals.append(
                RawSignal(
                    detector_key=detector_key,
                    detector_layer="ml",
                    raw_score=float(raw[i]),
                    entity_type=row["entity_type"],
                    entity_value=row["entity_value"],
                    window_start=row["window_start"].to_pydatetime(),
                    window_end=row["window_end"].to_pydatetime(),
                    evidence_event_ids=evidence,
                    explanation=model.explain_row(x_scaled[i]),
                )
            )
    return signals, df, bundle


def _run_l3_calibration_samples(
    log_path: Path, line_to_event_id: dict[int, int], malicious_event_ids: set[int]
) -> list[DetectorSample]:
    """Every L3 model's raw score on every entity-window row, labeled, for calibration fitting
    only -- deliberately never calls `explain_row` (see `_run_l3`'s docstring for why that
    matters at 50k-event scale). Isotonic regression needs the full raw-score distribution,
    including plenty of ordinary/negative rows, not just the ones that would clear a percentile
    pre-filter -- so unlike `_run_l3`, this keeps every row with at least one mapped evidence
    event."""
    from app.detection.ml.detect import MLModelBundle
    from app.detection.ml.events import load_ml_events
    from app.detection.ml.features import build_entity_window_features

    events = load_ml_events({"zscaler": log_path})
    df = build_entity_window_features(events)
    if df.empty:
        return []
    bundle = MLModelBundle.load()
    x_scaled = bundle.transform(df)

    line_numbers_by_row = df["line_numbers"].tolist()
    evidence_by_row = [
        {line_to_event_id[ln] for ln in lns if ln in line_to_event_id}
        for lns in line_numbers_by_row
    ]
    labels = [int(bool(malicious_event_ids & ev)) for ev in evidence_by_row]
    keep = [i for i, ev in enumerate(evidence_by_row) if ev]

    samples: list[DetectorSample] = []
    for detector_key, model in _ml_model_pairs(bundle):
        raw = model.raw_scores(x_scaled)
        samples.extend(
            DetectorSample(detector_key=detector_key, raw_score=float(raw[i]), label=labels[i])
            for i in keep
        )
    return samples


def _entity_event_index(events: list[GraphEvent]) -> dict[EntityKey, set[int]]:
    """Every entity's full set of event ids, from the same rows `build_entity_graph` consumes --
    used both to label graph-derived calibration samples and to attach evidence to `graph.*`
    signals (which `app.graph.features` computes at node granularity, without evidence lists of
    their own)."""
    from app.graph.builder import (
        ENTITY_ASN,
        ENTITY_COUNTRY,
        ENTITY_DOMAIN,
        ENTITY_DST_IP,
        ENTITY_SRC_IP,
        ENTITY_USER,
    )

    index: dict[EntityKey, set[int]] = defaultdict(set)
    for e in events:
        if e.principal:
            index[(ENTITY_USER, e.principal)].add(e.event_id)
        if e.src_ip:
            index[(ENTITY_SRC_IP, e.src_ip)].add(e.event_id)
        if e.domain:
            index[(ENTITY_DOMAIN, e.domain)].add(e.event_id)
        if e.dst_ip:
            index[(ENTITY_DST_IP, e.dst_ip)].add(e.event_id)
        if e.asn is not None:
            index[(ENTITY_ASN, str(e.asn))].add(e.event_id)
        if e.country:
            index[(ENTITY_COUNTRY, e.country)].add(e.event_id)
    return dict(index)


def _run_l5(
    graph_events: list[GraphEvent],
) -> tuple[Any, dict[EntityKey, NodeFeatures], list[RawSignal]]:
    build = build_entity_graph(graph_events)
    node_features = compute_node_features(build.graph)
    entity_index = _entity_event_index(graph_events)
    graph_signals = graph_signals_for_incident(list(build.graph.nodes), node_features)
    raw_signals = [
        RawSignal(
            detector_key=gs.detector_key,
            detector_layer="graph",
            raw_score=gs.raw_score,
            entity_type=gs.entity_type,
            entity_value=gs.entity_value,
            evidence_event_ids=sorted(entity_index.get((gs.entity_type, gs.entity_value), set())),
            explanation=gs.explanation,
        )
        for gs in graph_signals
    ]
    return build, node_features, raw_signals


# ---------------------------------------------------------------------------- scenario generation


def _run_datagen(args: list[str]) -> None:
    cmd = [sys.executable, "-m", "datagen", *args]
    log.info("datagen.invoke", cmd=cmd)
    subprocess.run(cmd, check=True, cwd=_BACKEND_ROOT)  # noqa: S603


def _generate_scenario(out_dir: Path, name: str, seed: int, events: int) -> tuple[Path, Path]:
    if not out_dir.exists() or not any(out_dir.glob("*.labels.json")):
        _run_datagen(
            [
                "scenario",
                "--name",
                name,
                "--seed",
                str(seed),
                "--out",
                str(out_dir),
                "--events",
                str(events),
            ]
        )
    log_path = sorted(out_dir.glob("*.log"))[0]
    labels_path = sorted(out_dir.glob("*.labels.json"))[0]
    return log_path, labels_path


@dataclass(frozen=True, slots=True)
class ScenarioGroundTruth:
    technique: str | None
    primary_entity: EntityKey | None
    malicious_line_numbers: frozenset[int]
    must_correlate_into_one_incident: bool


def _load_ground_truth(labels_path: Path) -> ScenarioGroundTruth:
    payload = json.loads(labels_path.read_text(encoding="utf-8"))
    lines: set[int] = set()
    technique: str | None = None
    primary_entity: EntityKey | None = None
    must_correlate = False
    for s in payload["scenarios"]:
        lines.update(s["malicious_line_numbers"])
        technique = technique or s.get("technique")
        pe = s.get("primary_entity")
        if pe and primary_entity is None:
            primary_entity = (pe["type"], pe["value"])
        must_correlate = must_correlate or bool(s.get("must_correlate_into_one_incident"))
    return ScenarioGroundTruth(
        technique=technique,
        primary_entity=primary_entity,
        malicious_line_numbers=frozenset(lines),
        must_correlate_into_one_incident=must_correlate,
    )


# ---------------------------------------------------------------------------- one full run


@dataclass(slots=True)
class PersistedIncident:
    incident_id: uuid.UUID
    title: str
    severity: str
    fused_score: float
    # docs/v2_migration change 3: fused_score rescaled to 0-100
    # (app.detection.fusion.anomaly_confidence_from_fused_score) -- the same value persisted to
    # incidents.anomaly_confidence below, surfaced here too so this verification tool's own
    # output demonstrates the derivation, not just the schema.
    anomaly_confidence: float
    base_score: float
    n_distinct_detector_layers: int
    community_signal_density: float
    top_technique: str | None
    entity_keys: frozenset[EntityKey]
    n_signals: int
    evidence_event_ids: set[int]
    recurrence_of: uuid.UUID | None
    recurrence_similarity: float | None
    n_timeline_phases: int
    first_phase_summary: str | None


@dataclass(slots=True)
class RunResult:
    scenario: str
    ingest: IngestResult
    ground_truth: ScenarioGroundTruth
    n_signals_raw: dict[str, int]
    incidents: list[PersistedIncident]
    reliability_samples: list[tuple[float, int]]  # (calibrated confidence, label)


def _fusion_weight(session: Session, tenant_id: uuid.UUID, detector_key: str) -> float:
    with tenant_scope(session, tenant_id):
        row = session.execute(
            select(DetectorStats.fusion_weight).where(DetectorStats.detector_key == detector_key)
        ).scalar_one_or_none()
    return float(row) if row is not None else 1.0


def _line_to_event_id(
    session: Session, analysis_id: uuid.UUID, tenant_id: uuid.UUID
) -> dict[int, int]:
    stmt = select(Event.raw_line_no, Event.id).where(Event.analysis_id == analysis_id)
    with tenant_scope(session, tenant_id):
        return dict(session.execute(stmt).tuples().all())


def _pick_primary_entity(candidate: IncidentCandidate) -> EntityKey:
    counts: dict[EntityKey, int] = defaultdict(int)
    for s in candidate.signals:
        counts[(s.entity_type, s.entity_value)] += 1
    return max(candidate.seed_entity_keys, key=lambda k: (counts.get(k, 0), k))


def _pick_top_technique(candidate: IncidentCandidate) -> str | None:
    """The most common `mitre_technique` already attached to one of `candidate`'s own L1/L2
    signals (deterministic: ties broken alphabetically), or `None` -- this offline demo pipeline's
    equivalent of docs/07's `NO_KNOWN_MAPPING` -- when no contributing signal carried one.

    Used to fall back to `app.graph.classifier`'s LightGBM technique classifier here; migration
    change 19 deleted that model (module docstring, "No `classify` stage"). Multiclass softmax
    attribution is not reintroduced as a fallback -- that is exactly the "two components assigning
    techniques with no defined precedence" problem the migration cut it to avoid, and the real
    replacement (LLM hypothesis evaluation, docs/07) is out of this package's ownership.
    """
    techniques = [s.mitre_technique for s in candidate.signals if s.mitre_technique]
    if not techniques:
        return None
    # deterministic: most common, ties broken alphabetically
    counts: dict[str, int] = defaultdict(int)
    for t in techniques:
        counts[t] += 1
    return max(sorted(counts), key=lambda t: counts[t])


def run_scenario(
    *,
    scenario: str,
    seed: int,
    events: int,
    out_dir: Path,
    calibrators: CalibratorStore,
) -> RunResult:
    t0 = time.perf_counter()
    log_path, labels_path = _generate_scenario(out_dir, scenario, seed, events)
    ground_truth = _load_ground_truth(labels_path)

    session = get_session_factory()()
    ingest = ingest_log_file(session, path=log_path)

    line_to_event_id = _line_to_event_id(session, ingest.analysis_id, ingest.tenant_id)
    malicious_event_ids = {
        line_to_event_id[ln] for ln in ground_truth.malicious_line_numbers if ln in line_to_event_id
    }

    l1 = _run_l1(ingest.analysis_id, ingest.tenant_id)
    l2 = _run_l2(session, ingest.analysis_id, ingest.tenant_id)
    # `l3_df`/`bundle` (the entity-window frame and loaded model bundle) used to also feed
    # `_pick_top_technique`'s LightGBM fallback -- migration change 19 removed that path (module
    # docstring), so only the signals list is needed here now.
    l3, _l3_df, _bundle = _run_l3(log_path, line_to_event_id)

    with tenant_scope(session, ingest.tenant_id):
        graph_events = fetch_graph_events(session, ingest.analysis_id)
    build, _node_features, l5 = _run_l5(graph_events)

    all_raw = l1 + l2 + l3 + l5
    n_signals_raw = {"rule": len(l1), "signal": len(l2), "ml": len(l3), "graph": len(l5)}

    reliability_samples: list[tuple[float, int]] = []
    persisted: list[Signal] = []
    signal_refs: list[SignalRef] = []
    with tenant_scope(session, ingest.tenant_id):
        for rs in all_raw:
            feature = _calibration_feature(rs.detector_key, rs.raw_score)
            confidence = calibrators.calibrate(rs.detector_key, feature)
            label = int(bool(malicious_event_ids & set(rs.evidence_event_ids)))
            reliability_samples.append((confidence, label))

            row = Signal(
                analysis_id=ingest.analysis_id,
                tenant_id=ingest.tenant_id,
                detector_key=rs.detector_key,
                detector_layer=rs.detector_layer,
                raw_score=rs.raw_score,
                confidence=confidence,
                entity_type=rs.entity_type,
                entity_value=rs.entity_value,
                window_start=rs.window_start,
                window_end=rs.window_end,
                mitre_technique=rs.mitre_technique,
                evidence_event_ids=rs.evidence_event_ids,
                explanation=rs.explanation,
            )
            session.add(row)
            persisted.append(row)
        session.flush()

        entity_key_to_id = persist_entity_graph(
            session, analysis_id=ingest.analysis_id, result=build
        )

        for row, rs in zip(persisted, all_raw, strict=True):
            signal_refs.append(
                SignalRef(
                    signal_id=row.id,
                    detector_key=rs.detector_key,
                    detector_layer=rs.detector_layer,
                    confidence=row.confidence,
                    entity_type=rs.entity_type,
                    entity_value=rs.entity_value,
                    mitre_technique=rs.mitre_technique,
                    evidence_event_ids=tuple(rs.evidence_event_ids),
                    window_start=rs.window_start,
                    window_end=rs.window_end,
                )
            )

        candidates = form_incidents(build.graph, signal_refs)

        persisted_incidents: list[PersistedIncident] = []
        for candidate in candidates:
            fusion_inputs = [
                FusionInput(
                    detector_key=s.detector_key,
                    detector_layer=s.detector_layer,
                    confidence=s.confidence,
                    fusion_weight=_fusion_weight(session, ingest.tenant_id, s.detector_key),
                )
                for s in candidate.signals
            ]
            incident_score = score_incident(
                fusion_inputs, community_signal_density=candidate.community_signal_density
            )

            top_technique = _pick_top_technique(candidate)
            primary_entity = _pick_primary_entity(candidate)
            title = title_for_incident(
                top_technique_id=top_technique,
                primary_entity_type=primary_entity[0],
                primary_entity_value=primary_entity[1],
            )
            timeline = build_timeline(list(candidate.signals))

            evidence_ids: set[int] = set()
            for s in candidate.signals:
                evidence_ids.update(s.evidence_event_ids)
            tags: set[str] = set()
            if evidence_ids:
                stmt = select(Event.enrichment).where(Event.id.in_(evidence_ids))
                for (enrichment,) in session.execute(stmt):
                    tags.update((enrichment or {}).get("tags", []))

            text = canonical_text(
                technique_ids=[s.mitre_technique for s in candidate.signals],
                detector_keys=[s.detector_key for s in candidate.signals],
                entity_types=[k[0] for k in candidate.entity_keys],
                enrichment_tags=sorted(tags),
            )
            embedding = embed_text(text)
            link = link_recurrence(session, embedding)

            entity_ids = [
                entity_key_to_id[k] for k in candidate.entity_keys if k in entity_key_to_id
            ]
            incident_row = Incident(
                analysis_id=ingest.analysis_id,
                tenant_id=ingest.tenant_id,
                title=title,
                severity=incident_score.severity,
                fused_score=incident_score.fused_score,
                anomaly_confidence=incident_score.anomaly_confidence,
                entity_ids=entity_ids,
                signal_ids=[s.signal_id for s in candidate.signals],
                recurrence_of=link.recurrence_of if link else None,
                recurrence_similarity=link.recurrence_similarity if link else None,
                embedding=embedding,
            )
            session.add(incident_row)
            session.flush()

            persisted_incidents.append(
                PersistedIncident(
                    incident_id=incident_row.id,
                    title=title,
                    severity=incident_score.severity,
                    fused_score=incident_score.fused_score,
                    anomaly_confidence=incident_score.anomaly_confidence,
                    base_score=incident_score.base_score,
                    n_distinct_detector_layers=incident_score.n_distinct_detector_layers,
                    community_signal_density=incident_score.community_signal_density,
                    top_technique=top_technique,
                    entity_keys=candidate.entity_keys,
                    n_signals=len(candidate.signals),
                    evidence_event_ids=evidence_ids,
                    recurrence_of=link.recurrence_of if link else None,
                    recurrence_similarity=link.recurrence_similarity if link else None,
                    n_timeline_phases=len(timeline),
                    first_phase_summary=timeline[0].summary if timeline else None,
                )
            )

        session.commit()

    session.close()
    elapsed = time.perf_counter() - t0
    log.info(
        "run_scenario.done",
        scenario=scenario,
        n_events=ingest.n_events,
        n_signals=len(all_raw),
        n_incidents=len(persisted_incidents),
        elapsed_s=round(elapsed, 2),
    )
    return RunResult(
        scenario=scenario,
        ingest=ingest,
        ground_truth=ground_truth,
        n_signals_raw=n_signals_raw,
        incidents=persisted_incidents,
        reliability_samples=reliability_samples,
    )


# ---------------------------------------------------------------------------- correlation metrics


def correlation_metrics(runs: list[RunResult]) -> dict[str, Any]:
    """docs/12 "Correlation": `incident_recall` = scenarios whose malicious events landed in one
    incident / total; `fragmentation` = mean incidents (containing that scenario's evidence) per
    scenario."""
    per_scenario: list[dict[str, Any]] = []
    n_recalled = 0
    fragmentation_counts: list[int] = []
    for r in runs:
        gt = r.ground_truth
        containing = [
            inc for inc in r.incidents if inc.evidence_event_ids & _malicious_event_ids(r)
        ]
        recalled = len(containing) == 1
        if recalled:
            n_recalled += 1
        fragmentation_counts.append(max(len(containing), 1) if gt.malicious_line_numbers else 0)
        per_scenario.append(
            {
                "scenario": r.scenario,
                "n_malicious_lines": len(gt.malicious_line_numbers),
                "n_incidents_containing_evidence": len(containing),
                "recalled": recalled,
            }
        )
    total = len(runs)
    incident_recall = n_recalled / total if total else 0.0
    fragmentation = float(np.mean(fragmentation_counts)) if fragmentation_counts else 0.0
    return {
        "incident_recall": incident_recall,
        "fragmentation": fragmentation,
        "per_scenario": per_scenario,
    }


def _malicious_event_ids(run: RunResult) -> set[int]:
    session = get_session_factory()()
    try:
        line_to_event_id = _line_to_event_id(session, run.ingest.analysis_id, run.ingest.tenant_id)
    finally:
        session.close()
    return {
        line_to_event_id[ln]
        for ln in run.ground_truth.malicious_line_numbers
        if ln in line_to_event_id
    }


# ---------------------------------------------------------------------------- calibration fitting


def fit_layer_calibrators(*, fit_dir: Path, seed: int = CALIBRATION_FIT_SEED) -> CalibratorStore:
    """Fit isotonic calibrators for every detector_key produced by L1/L2/L3/L5 (not just the
    three `ml.*` models `app.detection.calibration._fit_ml_calibrators` covers) by running the
    exact same layered pipeline `run_scenario` uses, on a held-out seed, over
    `CORRELATION_SCENARIO_KEYS` plus the two non-attack scenarios (for benign/negative samples).
    """
    from app.detection.ml.evaluate import SCENARIO_KEYS

    samples: list[DetectorSample] = []
    for key in SCENARIO_KEYS:
        scenario_dir = fit_dir / key
        log_path, labels_path = _generate_scenario(scenario_dir, key, seed, 50_000)
        ground_truth = _load_ground_truth(labels_path)

        session = get_session_factory()()
        try:
            ingest = ingest_log_file(session, path=log_path)
            line_to_event_id = _line_to_event_id(session, ingest.analysis_id, ingest.tenant_id)
            malicious_event_ids = {
                line_to_event_id[ln]
                for ln in ground_truth.malicious_line_numbers
                if ln in line_to_event_id
            }
            l1 = _run_l1(ingest.analysis_id, ingest.tenant_id)
            l2 = _run_l2(session, ingest.analysis_id, ingest.tenant_id)
            l3_samples = _run_l3_calibration_samples(
                log_path, line_to_event_id, malicious_event_ids
            )
            with tenant_scope(session, ingest.tenant_id):
                graph_events = fetch_graph_events(session, ingest.analysis_id)
            _build, _node_features, l5 = _run_l5(graph_events)
        finally:
            session.close()

        for rs in l1 + l2 + l5:
            label = int(bool(malicious_event_ids & set(rs.evidence_event_ids)))
            feature = _calibration_feature(rs.detector_key, rs.raw_score)
            samples.append(
                DetectorSample(detector_key=rs.detector_key, raw_score=feature, label=label)
            )
        samples.extend(l3_samples)
        log.info("fit_layer_calibrators.scenario_done", scenario=key, n_samples=len(samples))

    calibrators = fit_calibrators(samples)
    store = CalibratorStore()
    store.save_all(calibrators)
    log.info(
        "fit_layer_calibrators.done",
        detectors=sorted(calibrators),
        n_samples_by_detector={k: c.n_samples for k, c in calibrators.items()},
    )
    return store


# ---------------------------------------------------------------------------- CLI


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M10 end-to-end verification (docs/13 M10)")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run one scenario end to end")
    run_p.add_argument("--scenario", required=True)
    run_p.add_argument("--seed", type=int, default=7)
    run_p.add_argument("--events", type=int, default=50_000)
    run_p.add_argument("--out", type=Path, default=Path("/tmp/m10_demo_run"))  # noqa: S108
    run_p.add_argument("--repeat", type=int, default=1)

    fit_calibrators_p = sub.add_parser(
        "fit-calibrators", help="Fit L1/L2/L3/L5 calibrators on a held-out seed"
    )

    report_p = sub.add_parser("full-report", help="Run every correlation scenario + report metrics")
    report_p.add_argument("--out", type=Path, default=None)

    for p in (run_p, fit_calibrators_p, report_p):
        p.add_argument("--log-level", default="info")

    args = parser.parse_args(argv)
    configure_logging(getattr(args, "log_level", "info"))

    if args.command == "fit-calibrators":
        fit_layer_calibrators(fit_dir=Path("/tmp/m10_calibration_fit"))  # noqa: S108
        return 0

    calibrators = CalibratorStore()

    if args.command == "run":
        results: list[RunResult] = []
        for i in range(args.repeat):
            out_dir = args.out if i == 0 else Path(f"{args.out}_repeat{i}")
            result = run_scenario(
                scenario=args.scenario,
                seed=args.seed,
                events=args.events,
                out_dir=out_dir,
                calibrators=calibrators,
            )
            results.append(result)
            _print_run(result)
        return 0

    if args.command == "full-report":
        runs = [
            run_scenario(
                scenario=key,
                seed=7,
                events=50_000,
                out_dir=Path(f"/tmp/m10_demo_run_{key}"),  # noqa: S108
                calibrators=calibrators,
            )
            for key in CORRELATION_SCENARIO_KEYS
        ]
        for r in runs:
            _print_run(r)
        metrics = correlation_metrics(runs)
        all_samples = [s for r in runs for s in r.reliability_samples]
        confidences = np.array([c for c, _ in all_samples], dtype=np.float64)
        labels = np.array([label for _, label in all_samples], dtype=np.int64)
        reliability = reliability_diagram(confidences, labels)
        report = {
            "correlation": metrics,
            "brier_score": reliability.brier_score,
            "reliability_bins": [
                {
                    "bin_lo": b.bin_lo,
                    "bin_hi": b.bin_hi,
                    "n": b.n,
                    "mean_predicted": b.mean_predicted,
                    "observed_precision": b.observed_precision,
                }
                for b in reliability.bins
            ],
        }
        print(json.dumps(report, indent=2))  # noqa: T201
        if args.out is not None:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        return 0

    return 1


def _print_run(result: RunResult) -> None:
    print(f"\n=== scenario={result.scenario} analysis_id={result.ingest.analysis_id} ===")  # noqa: T201
    print(f"events={result.ingest.n_events} signals_raw={result.n_signals_raw}")  # noqa: T201
    for inc in result.incidents:
        print(  # noqa: T201
            f"  incident={inc.incident_id} title={inc.title!r} severity={inc.severity} "
            f"fused={inc.fused_score:.3f} anomaly_confidence={inc.anomaly_confidence:.1f}/100 "
            f"base={inc.base_score:.3f} "
            f"n_layers={inc.n_distinct_detector_layers} density={inc.community_signal_density:.2f} "
            f"n_signals={inc.n_signals} n_entities={len(inc.entity_keys)} "
            f"recurrence_of={inc.recurrence_of} similarity={inc.recurrence_similarity} "
            f"technique={inc.top_technique} timeline_phases={inc.n_timeline_phases} "
            f"first_phase={inc.first_phase_summary!r}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
