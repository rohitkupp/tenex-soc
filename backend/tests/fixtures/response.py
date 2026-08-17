"""Shared, non-test factory helpers originally written for `tests/test_response_*.py` and
`tests/test_enforcement_*.py` (both deleted — docs/v2_migration change 20 removed the response
action graph and enforcement plane entirely). `make_incident`/`make_signal`/`make_triage_verdict`
and `response_tenant_cleanup` below are still imported by tests that are *not* about the response
plane (`tests/test_incident_detail_api.py`, `tests/test_events_signals.py`,
`tests/test_agent_tools.py`, `tests/test_tier2_indicator_overlap.py`,
`tests/test_tier2_signature_sync.py`) — this module's own equivalent of `tests/conftest.py`'s
`make_tenant`/`make_user`/`make_analysis`, kept separate so it never collided with the
now-deleted response-plane test modules. The module name stays `response.py` rather than being
renamed, to avoid an import-path churn across every test file above for no behavioral change.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import text

from app.core.db import get_engine, get_session_factory
from app.detection.fusion import anomaly_confidence_from_fused_score
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.triage_verdict import TriageVerdict


@pytest.fixture
def response_tenant_cleanup() -> Iterator[list[uuid.UUID]]:
    created: list[uuid.UUID] = []
    yield created
    if not created:
        return
    with get_engine().begin() as conn:
        conn.execute(
            text(
                "DELETE FROM triage_verdicts WHERE incident_id IN ("
                "  SELECT id FROM incidents WHERE tenant_id = ANY(:ids)"
                ")"
            ),
            {"ids": created},
        )
        conn.execute(text("DELETE FROM incidents WHERE tenant_id = ANY(:ids)"), {"ids": created})
        conn.execute(text("DELETE FROM signals WHERE tenant_id = ANY(:ids)"), {"ids": created})
        conn.execute(text("DELETE FROM analyses WHERE tenant_id = ANY(:ids)"), {"ids": created})
        conn.execute(text("DELETE FROM uploads WHERE tenant_id = ANY(:ids)"), {"ids": created})
        conn.execute(text("DELETE FROM users WHERE tenant_id = ANY(:ids)"), {"ids": created})
        conn.execute(text("DELETE FROM tenants WHERE id = ANY(:ids)"), {"ids": created})


def make_signal(
    *,
    tenant_id: uuid.UUID,
    analysis_id: uuid.UUID,
    entity_type: str,
    entity_value: str,
    detector_key: str = "signal.beaconing",
    detector_layer: str = "signal",
    raw_score: float = 0.8,
    confidence: float = 0.8,
    mitre_technique: str | None = "T1071.001",
    evidence_event_ids: list[int] | None = None,
    explanation: dict[str, Any] | None = None,
) -> Signal:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            signal = Signal(
                analysis_id=analysis_id,
                tenant_id=tenant_id,
                detector_key=detector_key,
                detector_layer=detector_layer,
                raw_score=raw_score,
                confidence=confidence,
                entity_type=entity_type,
                entity_value=entity_value,
                mitre_technique=mitre_technique,
                evidence_event_ids=evidence_event_ids or [],
                explanation=explanation or {},
            )
            session.add(signal)
            session.commit()
            session.refresh(signal)
        return signal
    finally:
        session.close()


def make_incident(
    *,
    tenant_id: uuid.UUID,
    analysis_id: uuid.UUID,
    signal_ids: list[int] | None = None,
    entity_ids: list[int] | None = None,
    title: str = "Test incident",
    severity: str = "high",
    fused_score: float = 0.85,
    anomaly_confidence: float | None = None,
    tags: list[str] | None = None,
    summary: str = "Test incident summary.",
) -> Incident:
    """`anomaly_confidence` (docs/v2_migration change 3) defaults to the real derivation off
    `fused_score` (`app.detection.fusion.anomaly_confidence_from_fused_score`) rather than an
    independent literal, so a test that only cares about `fused_score` gets a consistent pair for
    free; pass it explicitly when a test needs the two to disagree (e.g. to prove a consumer reads
    one and not the other). `tags`/`summary` (this task's deterministic pipeline outputs,
    `app.graph.tags`/`app.graph.summary`) default to a small non-empty placeholder rather than
    `[]`/`""`, matching what `app.pipeline.stages.correlate` always writes for a real incident —
    a test that needs the *absence* of a tag/technique passes `tags=[]` explicitly."""
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            incident = Incident(
                analysis_id=analysis_id,
                tenant_id=tenant_id,
                title=title,
                severity=severity,
                fused_score=fused_score,
                anomaly_confidence=(
                    anomaly_confidence
                    if anomaly_confidence is not None
                    else anomaly_confidence_from_fused_score(fused_score)
                ),
                entity_ids=entity_ids or [],
                signal_ids=signal_ids or [],
                tags=tags if tags is not None else ["layer:rule"],
                summary=summary,
                status="open",
            )
            session.add(incident)
            session.commit()
            session.refresh(incident)
        return incident
    finally:
        session.close()


def make_triage_verdict(
    *,
    incident_id: uuid.UUID,
    recommended_actions: list[str],
    disposition: str = "true_positive",
    threat_confidence: str = "high",
    threat_confidence_reason: str = "Synthetic verdict for response-module testing.",
    summary: str = "Synthetic verdict for response-module testing.",
) -> TriageVerdict:
    """`TriageVerdict` is not `TenantScopedMixin` (docs/02: isolation is transitive through
    `incident_id`), so unlike `make_incident`/`make_signal` this needs no `tenant_scope`."""
    session = get_session_factory()()
    try:
        verdict = TriageVerdict(
            incident_id=incident_id,
            disposition=disposition,
            threat_confidence=threat_confidence,
            threat_confidence_reason=threat_confidence_reason,
            mitre_techniques=[{"id": "T1071.001", "name": "Web Protocols", "rationale": "test"}],
            summary=summary,
            narrative=[{"step": 1, "claim": "synthetic", "evidence_event_ids": []}],
            recommended_actions=recommended_actions,
            tool_trace=[],
            citation_valid=True,
            model="test-fixture",
        )
        session.add(verdict)
        session.commit()
        session.refresh(verdict)
        return verdict
    finally:
        session.close()
