"""`app.agent.verifier` — docs/v2_migration/MIGRATION-01-evidence-first.md change 3's confidence
integrity check, arriving early as change 7's own "confidence integrity" verifier rule.

`verify_anomaly_confidence` gets both a direct unit-level proof (fast, no LLM round trip) and a
full `triage_incident(...)` integration proof with a scripted `LLMCaller` standing in for a live
Claude call (`app.agent.client.LLMCaller`'s protocol; the same shape `FixtureCaller` replays real
recorded responses through) — the load-bearing test is that a mismatched `anomaly_confidence`
rejects the *whole verdict*, not just a flagged claim, all the way through persistence.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from anthropic.types import Message

from app.agent.context import build_agent_context
from app.agent.orchestrator import triage_incident
from app.agent.schemas import TriageVerdictOut
from app.agent.verifier import (
    ANOMALY_CONFIDENCE_TOLERANCE,
    AnomalyConfidenceCheck,
    verify_anomaly_confidence,
)
from app.core.db import get_session_factory
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.triage_verdict import TriageVerdict
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.response import make_incident

WINDOW_START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _setup_incident(cleanup: list[uuid.UUID], *, anomaly_confidence: float) -> tuple:
    tenant = make_tenant()
    cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"{uuid.uuid4()}@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    incident = make_incident(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        title="Test incident",
        severity="high",
        fused_score=0.9,
        anomaly_confidence=anomaly_confidence,
    )
    return tenant, analysis, incident


def _valid_verdict_kwargs(*, anomaly_confidence: float) -> dict[str, Any]:
    return {
        "disposition": "true_positive",
        "threat_confidence": "high",
        "threat_confidence_reason": "Regular interval requests strongly match beaconing.",
        "anomaly_confidence": anomaly_confidence,
        "llm_severity_opinion": "high",
        "mitre_techniques": (),
        "summary": "Beaconing pattern observed to a rare destination.",
        "narrative": (
            {"step": 1, "claim": "Regular interval requests.", "evidence_event_ids": ()},
        ),
        "contradicting_evidence": "Could be a scheduled sync; timing rules it out.",
        "recommended_actions": ("Confirm with the user whether this destination is expected.",),
    }


# ---------------------------------------------------------------------------- unit: verify_anomaly_confidence


def test_verify_anomaly_confidence_accepts_unchanged_value(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant, _analysis, incident = _setup_incident(tenant_cleanup, anomaly_confidence=87.3)
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        verdict = TriageVerdictOut(**_valid_verdict_kwargs(anomaly_confidence=87.3))
        check = verify_anomaly_confidence(ctx, verdict)
    finally:
        session.close()

    assert isinstance(check, AnomalyConfidenceCheck)
    assert check.ok is True
    assert check.reason is None
    assert check.expected == pytest.approx(87.3)
    assert check.actual == pytest.approx(87.3)


def test_verify_anomaly_confidence_rejects_differing_value(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """The load-bearing test: a verdict whose echoed anomaly_confidence differs from the
    incident's own value is rejected, with a recorded, inspectable reason -- not a silent
    `False`."""
    tenant, _analysis, incident = _setup_incident(tenant_cleanup, anomaly_confidence=87.3)
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        verdict = TriageVerdictOut(**_valid_verdict_kwargs(anomaly_confidence=42.0))
        check = verify_anomaly_confidence(ctx, verdict)
    finally:
        session.close()

    assert check.ok is False
    assert check.expected == pytest.approx(87.3)
    assert check.actual == pytest.approx(42.0)
    assert check.reason is not None
    assert "anomaly_confidence integrity check failed" in check.reason
    assert "87.3" in check.reason
    assert "42.0" in check.reason


def test_verify_anomaly_confidence_tolerates_float_roundtrip_noise_only(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """The tolerance exists to absorb IEEE-754 noise from Postgres' REAL column round-tripping
    the exact same decimal value, not to let a real change through. A difference far larger than
    the tolerance is always rejected; a difference at the tolerance's own edge is accepted."""
    tenant, _analysis, incident = _setup_incident(tenant_cleanup, anomaly_confidence=50.0)
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id)
        just_inside = TriageVerdictOut(
            **_valid_verdict_kwargs(anomaly_confidence=50.0 + ANOMALY_CONFIDENCE_TOLERANCE / 2)
        )
        just_outside = TriageVerdictOut(**_valid_verdict_kwargs(anomaly_confidence=50.1))
        inside_check = verify_anomaly_confidence(ctx, just_inside)
        outside_check = verify_anomaly_confidence(ctx, just_outside)
    finally:
        session.close()

    assert inside_check.ok is True
    assert outside_check.ok is False


# ---------------------------------------------------------------------------- scripted LLMCaller


class _ScriptedCaller:
    """A minimal stand-in for `app.agent.client.LLMCaller` -- same protocol `FixtureCaller`
    implements, but scripted in-line per test rather than loaded from a recorded fixture file, so
    each test can control exactly one thing: what `emit_verdict` returns for
    `anomaly_confidence`."""

    def __init__(self, messages: list[Message]) -> None:
        self._messages = list(messages)
        self._index = 0

    def create(self, **_kwargs: Any) -> Message:
        message = self._messages[self._index]
        self._index += 1
        return message


def _message(*, tool_name: str, tool_input: dict[str, Any]) -> Message:
    return Message.model_validate(
        {
            "id": f"msg_{tool_name}",
            "content": [
                {
                    "type": "tool_use",
                    "id": f"toolu_{tool_name}",
                    "name": tool_name,
                    "input": tool_input,
                }
            ],
            "model": "claude-opus-5",
            "role": "assistant",
            "stop_reason": "tool_use",
            "stop_sequence": None,
            "type": "message",
            "usage": {"input_tokens": 500, "output_tokens": 200},
        }
    )


def _findings_message() -> Message:
    return _message(
        tool_name="submit_findings",
        tool_input={
            "hypothesis": "Possible C2 beaconing to a rare destination.",
            "disposition_lean": "true_positive",
            "narrative": [
                {"step": 1, "claim": "Regular interval requests.", "evidence_event_ids": []}
            ],
            "mitre_techniques": [],
            "recommended_actions": ["Confirm with the user whether this destination is expected."],
        },
    )


def _rebuttal_message() -> Message:
    return _message(
        tool_name="submit_rebuttal",
        tool_input={
            "contradicting_evidence": "Could be a scheduled sync job.",
            "agrees_with_disposition": True,
            "notes": "Timing does not match any known scheduled job for this user.",
        },
    )


def _verdict_message(*, anomaly_confidence: float) -> Message:
    return _message(
        tool_name="emit_verdict",
        tool_input={
            "disposition": "true_positive",
            "threat_confidence": "high",
            "threat_confidence_reason": "Regular interval requests strongly match beaconing.",
            "anomaly_confidence": anomaly_confidence,
            "llm_severity_opinion": "high",
            "mitre_techniques": [],
            "summary": "Beaconing pattern observed to a rare destination.",
            "narrative": [
                {"step": 1, "claim": "Regular interval requests.", "evidence_event_ids": []}
            ],
            "contradicting_evidence": "Could be a scheduled sync; timing rules it out.",
            "recommended_actions": ["Confirm with the user whether this destination is expected."],
        },
    )


# ---------------------------------------------------------------------------- triage_incident integration


def test_triage_incident_rejects_verdict_with_mismatched_anomaly_confidence(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """End to end through the real orchestrator: a scripted Reporter that echoes back the wrong
    anomaly_confidence gets its entire verdict rejected -- hard rejection to needs_review, with
    the failure reason recorded, not a per-claim flag on an otherwise-trusted verdict."""
    tenant, _analysis, incident = _setup_incident(tenant_cleanup, anomaly_confidence=87.3)
    caller = _ScriptedCaller(
        [_findings_message(), _rebuttal_message(), _verdict_message(anomaly_confidence=42.0)]
    )

    session = get_session_factory()()
    try:
        row = triage_incident(session, tenant.id, incident.id, caller=caller)
    finally:
        session.close()

    assert row.disposition == "needs_review"
    assert row.threat_confidence == "low"
    assert "anomaly_confidence integrity check failed" in row.summary
    assert "87.3" in row.summary
    assert "42.0" in row.summary


def test_triage_incident_accepts_verdict_with_unchanged_anomaly_confidence(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant, _analysis, incident = _setup_incident(tenant_cleanup, anomaly_confidence=87.3)
    caller = _ScriptedCaller(
        [_findings_message(), _rebuttal_message(), _verdict_message(anomaly_confidence=87.3)]
    )

    session = get_session_factory()()
    try:
        row = triage_incident(session, tenant.id, incident.id, caller=caller)
    finally:
        session.close()

    assert row.disposition == "true_positive"
    assert row.threat_confidence == "high"
    assert row.threat_confidence_reason


def test_nothing_in_the_agent_path_can_write_anomaly_confidence(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """Two independent guarantees: (1) `triage_verdicts` has no `anomaly_confidence` column at
    all -- there is structurally nowhere for the LLM's output to land even if every other check
    were bypassed; (2) a full triage run never mutates `incidents.anomaly_confidence`, which
    lives entirely upstream of the agent (`app.detection.fusion`) and is only ever read by it."""
    assert "anomaly_confidence" not in {c.name for c in TriageVerdict.__table__.columns}

    tenant, _analysis, incident = _setup_incident(tenant_cleanup, anomaly_confidence=61.5)
    caller = _ScriptedCaller(
        [_findings_message(), _rebuttal_message(), _verdict_message(anomaly_confidence=61.5)]
    )

    session = get_session_factory()()
    try:
        row = triage_incident(session, tenant.id, incident.id, caller=caller)
        assert not hasattr(row, "anomaly_confidence")

        with tenant_scope(session, tenant.id):
            refreshed = session.get(Incident, incident.id)
            assert refreshed is not None
            assert refreshed.anomaly_confidence == pytest.approx(61.5)
    finally:
        session.close()
