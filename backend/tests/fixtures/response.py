"""Shared, non-test factory helpers for `tests/test_response_*.py` and
`tests/test_enforcement_*.py` — this milestone's own equivalent of `tests/conftest.py`'s
`make_tenant`/`make_user`/`make_analysis`, kept in a separate module (not `conftest.py`) so this
milestone's fixtures never collide with what other, concurrently-developed milestones keep there.
Imported directly into test modules — pytest fixtures work the same whether they're defined in
the module or imported into it.

**Why cleanup can't reuse `conftest.py`'s `tenant_cleanup`.** `enforcement_journal.plan_id`
references `response_plans.id` with no `ON DELETE` action (docs/02, matched exactly) — deleting
a `response_plans` row (including via cascade: `analyses` -> `incidents` -> `response_plans`)
while it still has journal children violates that FK. `enforcement_state` carries no FK at all
(a bare `tenant_id` column, docs/02), so nothing cascades into it either.
`response_tenant_cleanup` tears the whole chain down in the order those constraints require.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import text

from app.core.db import get_engine, get_session_factory
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.response_plan import ResponsePlan
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
                "DELETE FROM enforcement_journal WHERE plan_id IN ("
                "  SELECT rp.id FROM response_plans rp "
                "  JOIN incidents i ON i.id = rp.incident_id "
                "  WHERE i.tenant_id = ANY(:ids)"
                ")"
            ),
            {"ids": created},
        )
        conn.execute(
            text("DELETE FROM enforcement_state WHERE tenant_id = ANY(:ids)"), {"ids": created}
        )
        conn.execute(
            text(
                "DELETE FROM response_plans WHERE incident_id IN ("
                "  SELECT id FROM incidents WHERE tenant_id = ANY(:ids)"
                ")"
            ),
            {"ids": created},
        )
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
) -> Incident:
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            incident = Incident(
                analysis_id=analysis_id,
                tenant_id=tenant_id,
                title=title,
                severity=severity,
                fused_score=fused_score,
                entity_ids=entity_ids or [],
                signal_ids=signal_ids or [],
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
    recommended_actions: list[dict[str, Any]],
    disposition: str = "true_positive",
    confidence: float = 0.9,
    summary: str = "Synthetic verdict for response-module testing.",
) -> TriageVerdict:
    """`TriageVerdict` is not `TenantScopedMixin` (docs/02: isolation is transitive through
    `incident_id`), so unlike `make_incident`/`make_signal` this needs no `tenant_scope`."""
    session = get_session_factory()()
    try:
        verdict = TriageVerdict(
            incident_id=incident_id,
            disposition=disposition,
            confidence=confidence,
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


def get_response_plan(plan_id: uuid.UUID) -> ResponsePlan:
    session = get_session_factory()()
    try:
        plan = session.get(ResponsePlan, plan_id)
        assert plan is not None
        return plan
    finally:
        session.close()
