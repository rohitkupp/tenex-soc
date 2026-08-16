"""Correlate — docs/01's `correlate` stage contract, made real:

* Precondition: signals exist (`detect` already ran).
* Postcondition: `entities`, `entity_edges`, `incidents`.

`app.graph.pipeline_demo` (M10's own end-to-end verification tool) is the closest existing
reference for how these components compose — its `run_scenario` builds the graph, forms
incidents, scores and persists them in exactly this order; the logic below is that same
composition, reused rather than reinvented, minus the offline-script-only concerns (scenario
generation, calibration-sample collection) that do not belong in a live queue stage. Populates
`incidents.anomaly_confidence` via `app.detection.fusion.anomaly_confidence_from_fused_score`
(inside `score_incident`, the single derivation point that function's own docstring names).

Louvain community detection lives inside `app.graph.incidents.form_incidents` (docs/05's steps
1-6 in one function, `python-louvain`'s `best_partition`) — this stage does not call it directly,
only `form_incidents`.
"""

from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.core.db import get_engine, get_session_factory
from app.core.logging import get_logger
from app.detection.fusion import FusionInput, score_incident
from app.graph.builder import (
    EntityKey,
    build_entity_graph,
    fetch_graph_events,
    persist_entity_graph,
)
from app.graph.incidents import IncidentCandidate, SignalRef, form_incidents
from app.graph.recurrence import canonical_text, embed_text, link_recurrence
from app.graph.titling import title_for_incident
from app.learning.initial_weights import load_initial_fusion_weights
from app.models.base import tenant_scope
from app.models.detector_stats import DetectorStats
from app.models.event import Event
from app.models.incident import Incident
from app.models.signal import Signal
from app.pipeline import state
from app.pipeline.contracts import NEXT_QUEUE, STAGE_PROGRESS, public_counters
from app.pipeline.messages import StageMessage
from app.pipeline.progress import publish_progress
from app.pipeline.redis_client import get_redis

log = get_logger(__name__)

# docs/12 change 4 ("Audit and set initial fusion weights"): loaded once per process, not once per
# signal -- every detector started at a uniform 1.0 fusion weight until an analyst had confirmed
# or dismissed enough alerts for mechanism 2 (`app.learning.weights.retune_detector_weights`) to
# run, which fused LOF's ~0.003 measured precision with the same authority as EIF's ~0.2 before a
# single analyst click. `load_initial_fusion_weights` never raises and returns `{}` (falling
# through to the pre-existing 1.0 below, unchanged) on a fresh checkout that has not run
# `make eval` yet -- see `app.learning.initial_weights`'s own module docstring for the full
# derivation and why this is a file read, not a live benchmark call.
_INITIAL_FUSION_WEIGHTS = load_initial_fusion_weights()


def _fusion_weight(session: Any, tenant_id: uuid.UUID, detector_key: str) -> float:
    with tenant_scope(session, tenant_id):
        row = session.execute(
            select(DetectorStats.fusion_weight).where(DetectorStats.detector_key == detector_key)
        ).scalar_one_or_none()
    if row is not None:
        return float(row)
    return _INITIAL_FUSION_WEIGHTS.get(detector_key, 1.0)


def _pick_primary_entity(candidate: IncidentCandidate) -> EntityKey:
    counts: dict[EntityKey, int] = defaultdict(int)
    for s in candidate.signals:
        counts[(s.entity_type, s.entity_value)] += 1
    return max(candidate.seed_entity_keys, key=lambda k: (counts.get(k, 0), k))


def _pick_top_technique(candidate: IncidentCandidate) -> str | None:
    """The most common `mitre_technique` already attached to one of `candidate`'s own signals
    (deterministic: ties broken alphabetically), or `None` — `NO_KNOWN_MAPPING` in docs/07's
    language. No LightGBM fallback (migration change 19 removed that classifier; the LLM's own
    hypothesis-evaluation stage, out of this module's scope, is the real replacement)."""
    techniques = [s.mitre_technique for s in candidate.signals if s.mitre_technique]
    if not techniques:
        return None
    counts: dict[str, int] = defaultdict(int)
    for t in techniques:
        counts[t] += 1
    return max(sorted(counts), key=lambda t: counts[t])


def _run_correlate(message: StageMessage) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        with tenant_scope(session, message.tenant_id):
            graph_events = fetch_graph_events(session, message.analysis_id)

        build = build_entity_graph(graph_events)

        with tenant_scope(session, message.tenant_id):
            entity_key_to_id = persist_entity_graph(
                session, analysis_id=message.analysis_id, result=build
            )
            session.commit()

            signal_rows = (
                session.execute(select(Signal).where(Signal.analysis_id == message.analysis_id))
                .scalars()
                .all()
            )
            signal_refs = [
                SignalRef(
                    signal_id=s.id,
                    detector_key=s.detector_key,
                    detector_layer=s.detector_layer,
                    confidence=s.confidence,
                    entity_type=s.entity_type,
                    entity_value=s.entity_value,
                    mitre_technique=s.mitre_technique,
                    evidence_event_ids=tuple(s.evidence_event_ids),
                    window_start=s.window_start,
                    window_end=s.window_end,
                )
                for s in signal_rows
            ]

            candidates = form_incidents(build.graph, signal_refs)

            n_incidents = 0
            for candidate in candidates:
                fusion_inputs = [
                    FusionInput(
                        detector_key=s.detector_key,
                        detector_layer=s.detector_layer,
                        confidence=s.confidence,
                        fusion_weight=_fusion_weight(session, message.tenant_id, s.detector_key),
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

                evidence_ids: set[int] = set()
                for s in candidate.signals:
                    evidence_ids.update(s.evidence_event_ids)
                tags: set[str] = set()
                if evidence_ids:
                    for (enrichment,) in session.execute(
                        select(Event.enrichment).where(Event.id.in_(evidence_ids))
                    ):
                        tags.update((enrichment or {}).get("tags", []))

                canonical = canonical_text(
                    technique_ids=[s.mitre_technique for s in candidate.signals],
                    detector_keys=[s.detector_key for s in candidate.signals],
                    entity_types=[k[0] for k in candidate.entity_keys],
                    enrichment_tags=sorted(tags),
                )
                embedding = embed_text(canonical)
                link = link_recurrence(session, embedding)

                entity_ids = [
                    entity_key_to_id[k] for k in candidate.entity_keys if k in entity_key_to_id
                ]
                incident_row = Incident(
                    analysis_id=message.analysis_id,
                    tenant_id=message.tenant_id,
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
                n_incidents += 1

            session.commit()
    finally:
        session.close()

    with get_engine().begin() as conn:
        state.mark_stage(
            conn,
            analysis_id=message.analysis_id,
            tenant_id=message.tenant_id,
            stage="correlate",
            progress=STAGE_PROGRESS["correlate"],
        )
        counters = state.increment_counter(
            conn,
            analysis_id=message.analysis_id,
            tenant_id=message.tenant_id,
            key="incidents",
            delta=n_incidents,
        )

    log.info(
        "correlate.done",
        analysis_id=str(message.analysis_id),
        n_entities=len(entity_key_to_id),
        n_edges=build.n_edges,
        n_signals=len(signal_refs),
        n_incidents=n_incidents,
    )
    return {
        "n_entities": len(entity_key_to_id),
        "n_edges": build.n_edges,
        "n_signals": len(signal_refs),
        "n_incidents": n_incidents,
        "counters": counters,
    }


async def handle(message: StageMessage) -> list[tuple[str, StageMessage]]:
    result = await asyncio.to_thread(_run_correlate, message)

    await publish_progress(
        get_redis(),
        analysis_id=message.analysis_id,
        stage="correlate",
        progress=STAGE_PROGRESS["correlate"],
        status="running",
        message=(
            f"Correlation complete: {result['n_entities']} entities / {result['n_edges']} edges "
            f"in the graph, {result['n_signals']} signal(s) considered, "
            f"{result['n_incidents']} incident(s) formed via Louvain community detection."
        ),
        counters=public_counters(result["counters"]),
    )

    next_queue = NEXT_QUEUE["correlate"]
    assert next_queue is not None
    now = datetime.now(UTC)
    return [
        (
            next_queue,
            message.model_copy(update={"stage": next_queue, "attempt": 0, "emitted_at": now}),
        )
    ]
