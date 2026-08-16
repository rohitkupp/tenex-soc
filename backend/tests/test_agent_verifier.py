"""`app.agent.verifier` — docs/v2_migration/MIGRATION-01-evidence-first.md change 7 ("Dual
citations + numeric verification") and change 15 ("Verifier runs before the judge, and again
after"). Covers, roughly in the order change 7 lists them:

    1. existence      -- test_check_claim_existence_*
    2. numeric match   -- test_extract_numbers_*, test_numeric_leaves_*, test_check_claim_numeric_*
    3. retrieval match -- test_check_finding_retrieval_*
    4. scope           -- test_check_claim_scope_*
    5. confidence integrity -- test_verify_anomaly_confidence_* (unchanged mechanism)

plus the pass-1/pass-2 orchestration change 15 asks for, and `verify_narrator_output` for Path A
(change 14).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from anthropic.types import Message

from app.agent.context import build_agent_context
from app.agent.orchestrator import triage_incident
from app.agent.schemas import (
    NO_KNOWN_MAPPING,
    Claim,
    Finding,
    HypothesisEvaluation,
    NarratorOutput,
    TimelinePhaseNarrative,
    TriageVerdictOut,
)
from app.agent.verifier import (
    ANOMALY_CONFIDENCE_TOLERANCE,
    AnomalyConfidenceCheck,
    classify_citation,
    extract_numbers,
    hallucination_stats,
    numeric_leaves,
    verify_anomaly_confidence,
    verify_narrator_output,
    verify_pass1,
    verify_pass2,
)
from app.core.db import get_session_factory
from app.detection.evidence.payload import EvidencePayload
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.triage_verdict import TriageVerdict
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.agent import make_event
from tests.fixtures.response import make_incident, make_signal

WINDOW_START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
WINDOW_END = WINDOW_START + timedelta(hours=1)


# ---------------------------------------------------------------------------- classify_citation


def test_classify_citation_evidence_and_baseline() -> None:
    assert classify_citation("EVIDENCE-14") == ("evidence", "EVIDENCE-14")
    assert classify_citation("BASELINE-3") == ("evidence", "BASELINE-3")


def test_classify_citation_log() -> None:
    assert classify_citation("LOG-1291") == ("log", "1291")


def test_classify_citation_mitre() -> None:
    assert classify_citation("MITRE-T1567.002") == ("mitre", "T1567.002")


def test_classify_citation_zscaler_kb() -> None:
    assert classify_citation("ZSCALER-KB-threat-cat") == ("zscaler_kb", "threat-cat")


def test_classify_citation_unknown() -> None:
    assert classify_citation("garbage") == ("unknown", "garbage")


# ---------------------------------------------------------------------------- extract_numbers


def test_extract_numbers_bare_count_is_exact_tolerance() -> None:
    numbers = extract_numbers("63 requests over 4 distinct domains")
    assert len(numbers) == 2
    assert numbers[0].value == 63.0
    assert numbers[0].is_count is True
    assert numbers[0].tolerance == 0.0


def test_extract_numbers_byte_unit_has_decimal_and_binary_candidates() -> None:
    numbers = extract_numbers("transferred 2.4 GB in total")
    assert len(numbers) == 1
    n = numbers[0]
    assert n.unit == "gb"
    assert n.is_count is False
    assert n.tolerance == pytest.approx(0.01)
    assert 2.4e9 in n.candidates
    assert any(abs(c - 2.4 * 1024**3) < 1 for c in n.candidates)


def test_extract_numbers_duration_unit() -> None:
    numbers = extract_numbers("median interval of 60.1s")
    assert len(numbers) == 1
    assert numbers[0].candidates == (60.1,)


def test_extract_numbers_percentile() -> None:
    numbers = extract_numbers("at the 99.7th percentile")
    assert len(numbers) == 1
    assert numbers[0].candidates == (99.7,)


def test_extract_numbers_strips_technique_ids_and_citations() -> None:
    """A technique id or citation token embedded in prose must never be misread as a measurement
    — this is what protects numeric-match from false rejections on "...consistent with
    T1567.002, see [EVIDENCE-14]..."."""
    numbers = extract_numbers("consistent with T1567.002, see EVIDENCE-14 and BASELINE-3")
    assert numbers == []


def test_extract_numbers_strips_timestamps() -> None:
    numbers = extract_numbers("beaconing from 2026-02-23T16:19Z to 18:16 over the window")
    assert numbers == []


def test_extract_numbers_thousands_separator() -> None:
    numbers = extract_numbers("a fused score contribution from 1,740 output tokens")
    assert numbers[0].value == 1740.0
    assert numbers[0].is_count is True


# ---------------------------------------------------------------------------- numeric_leaves


def test_numeric_leaves_collects_nested_numbers() -> None:
    obj = {"measurements": {"requests": 63, "cv": 0.018}, "historical": {"percentile": 99.7}}
    leaves = numeric_leaves(obj)
    assert set(leaves) == {63.0, 0.018, 99.7}


def test_numeric_leaves_excludes_identifier_keys() -> None:
    obj = {"id": 42, "evidence_id": "EVIDENCE-1", "raw_line_no": 1291, "bytes_out": 500}
    leaves = numeric_leaves(obj)
    assert leaves == [500.0]


def test_numeric_leaves_excludes_booleans() -> None:
    assert numeric_leaves({"nominates_candidate": True, "value": 3}) == [3.0]


# ---------------------------------------------------------------------------- check_claim / check_finding via a real ctx


def _setup_incident_with_evidence(
    cleanup: list[uuid.UUID],
    *,
    bytes_out_measurement: float = 1_800_000_000.0,
    n_events: int = 3,
) -> tuple[Any, Any, list[Any], Any, Any, EvidencePayload]:
    tenant = make_tenant()
    cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"{uuid.uuid4()}@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    events = [
        make_event(
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            ts=WINDOW_START + timedelta(minutes=i),
            raw_line_no=1000 + i,
            principal="alice@corp.example",
            domain="rare-destination.example",
            bytes_out=100,
        )
        for i in range(n_events)
    ]
    signal = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="user",
        entity_value="alice@corp.example",
        detector_key="signal.beaconing",
        evidence_event_ids=[e.id for e in events],
        explanation={},
    )
    incident = make_incident(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signal_ids=[signal.id],
        title="Test incident",
        severity="high",
        fused_score=0.9,
    )
    payload = EvidencePayload(
        evidence_id="EVIDENCE-1",
        extractor="beaconing",
        entity={"type": "user", "value": "alice@corp.example"},
        window=(WINDOW_START, WINDOW_END),
        measurements={"requests": 63, "bytes_out": bytes_out_measurement},
        historical={"beaconing_percentile": 99.7},
        contributing_line_numbers=[e.raw_line_no for e in events],
        nominates_candidate=False,
    )
    return tenant, analysis, events, signal, incident, payload


def test_check_claim_numeric_match_accepts_matching_gb_value(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant, _analysis, _events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup, bytes_out_measurement=1_800_000_000.0
    )
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[payload])
        claim = Claim(text="transferred 1.8 GB to the destination", evidence_ids=("EVIDENCE-1",))
        from app.agent.verifier import _check_claim, _resolve_citations

        resolved = _resolve_citations(ctx, {"EVIDENCE-1"}, {})
        check = _check_claim(ctx, claim, resolved, check_scope=False)
    finally:
        session.close()
    assert check.numeric_ok is True


def test_check_claim_numeric_match_rejects_wrong_gb_value(tenant_cleanup: list[uuid.UUID]) -> None:
    """The load-bearing example from change 7: "transferred 2.4 GB [EVIDENCE-14]" where
    EVIDENCE-14 says 1.8 GB -> reject the statement."""
    tenant, _analysis, _events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup, bytes_out_measurement=1_800_000_000.0
    )
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[payload])
        claim = Claim(text="transferred 2.4 GB to the destination", evidence_ids=("EVIDENCE-1",))
        from app.agent.verifier import _check_claim, _resolve_citations

        resolved = _resolve_citations(ctx, {"EVIDENCE-1"}, {})
        check = _check_claim(ctx, claim, resolved, check_scope=False)
    finally:
        session.close()
    assert check.numeric_ok is False
    assert "2.4 GB" in check.mismatched_numbers[0]


def test_check_claim_existence_rejects_nonexistent_evidence_id(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant, _analysis, _events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup
    )
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[payload])
        claim = Claim(text="63 requests observed", evidence_ids=("EVIDENCE-99",))
        from app.agent.verifier import _check_claim, _resolve_citations

        resolved = _resolve_citations(ctx, {"EVIDENCE-99"}, {})
        check = _check_claim(ctx, claim, resolved, check_scope=False)
    finally:
        session.close()
    assert check.existence_ok is False
    assert check.missing_ids == ("EVIDENCE-99",)
    # No citation to verify against -> a bare count with no valid pool cannot be confirmed either.
    assert check.numeric_ok is False


def test_check_claim_existence_accepts_real_log_id(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant, _analysis, events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup
    )
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[payload])
        log_id = f"LOG-{events[0].raw_line_no}"
        claim = Claim(text="request observed", evidence_ids=(log_id,))
        from app.agent.verifier import (
            _check_claim,
            _fetch_events_by_line_no,
            _resolve_citations,
        )

        events_by_line_no = _fetch_events_by_line_no(ctx, {events[0].raw_line_no})
        resolved = _resolve_citations(ctx, {log_id}, events_by_line_no)
        check = _check_claim(ctx, claim, resolved, check_scope=True)
    finally:
        session.close()
    assert check.existence_ok is True
    assert check.scope_ok is True


def test_check_claim_existence_rejects_nonexistent_log_line(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """The `LOG-n` sibling of `test_check_claim_existence_rejects_nonexistent_evidence_id` --
    citation existence is checked the same way for both citation types (change 7's "dual
    citation types"), but only the `EVIDENCE-n` case had a dedicated test; a raw log-line
    citation to a `raw_line_no` nothing in this analysis ever had is a distinct code path
    (`_fetch_events_by_line_no` / `_resolve_citations` querying `events`, not the evidence-payload
    map) and needs its own coverage rather than relying on the out-of-scope case above, which
    exercises a line that *does* exist."""
    tenant, _analysis, _events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup
    )
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[payload])
        nonexistent_log_id = "LOG-999999"
        claim = Claim(text="request observed", evidence_ids=(nonexistent_log_id,))
        from app.agent.verifier import (
            _check_claim,
            _fetch_events_by_line_no,
            _resolve_citations,
        )

        events_by_line_no = _fetch_events_by_line_no(ctx, {999999})
        assert events_by_line_no == {}, "999999 must not collide with any real fixture event"
        resolved = _resolve_citations(ctx, {nonexistent_log_id}, events_by_line_no)
        check = _check_claim(ctx, claim, resolved, check_scope=True)
    finally:
        session.close()
    assert check.existence_ok is False
    assert check.missing_ids == (nonexistent_log_id,)


def test_check_claim_scope_rejects_out_of_scope_log_line(tenant_cleanup: list[uuid.UUID]) -> None:
    """change 7 check 4: a cited log line outside the incident's entities/window fails scope,
    even though it exists."""
    tenant, _analysis, _events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup
    )
    analysis = _analysis
    out_of_scope_event = make_event(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        ts=WINDOW_START + timedelta(days=3),  # well outside the +/-1h slack
        raw_line_no=9999,
        principal="bob@corp.example",  # a different entity entirely
        domain="unrelated.example",
    )
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[payload])
        log_id = f"LOG-{out_of_scope_event.raw_line_no}"
        claim = Claim(text="request observed", evidence_ids=(log_id,))
        from app.agent.verifier import (
            _check_claim,
            _fetch_events_by_line_no,
            _resolve_citations,
        )

        events_by_line_no = _fetch_events_by_line_no(ctx, {out_of_scope_event.raw_line_no})
        resolved = _resolve_citations(ctx, {log_id}, events_by_line_no)
        check = _check_claim(ctx, claim, resolved, check_scope=True)
    finally:
        session.close()
    assert check.existence_ok is True
    assert check.scope_ok is False
    assert log_id in check.out_of_scope_ids


def test_check_claim_scope_not_checked_in_pass1_mode(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant, _analysis, events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup
    )
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[payload])
        log_id = f"LOG-{events[0].raw_line_no}"
        claim = Claim(text="request observed", evidence_ids=(log_id,))
        from app.agent.verifier import (
            _check_claim,
            _fetch_events_by_line_no,
            _resolve_citations,
        )

        events_by_line_no = _fetch_events_by_line_no(ctx, {events[0].raw_line_no})
        resolved = _resolve_citations(ctx, {log_id}, events_by_line_no)
        check = _check_claim(ctx, claim, resolved, check_scope=False)
    finally:
        session.close()
    assert check.scope_ok is None


# ---------------------------------------------------------------------------- retrieval match


def test_check_finding_retrieval_rejects_unretrieved_technique(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """change 7 check 3: a technique the model recalled from training and never retrieved is a
    hallucination even if the mapping is plausible."""
    tenant, _analysis, _events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup
    )
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[payload])
        ctx.record_retrieved_techniques(["T1071.001"])  # T1567.002 never retrieved
        finding = Finding(
            finding_id="FINDING-1",
            anomaly_ids=("EVIDENCE-1",),
            observation="Beaconing observed.",
            hypothesis="Consistent with cloud exfiltration.",
            supporting_evidence_ids=("EVIDENCE-1",),
            contradicting_evidence_ids=(),
            missing_evidence=(),
            attack_technique_id="T1567.002",
            attack_source_id="MITRE-T1567.002",
            threat_confidence="moderate",
            confidence_reason="Matches known pattern.",
            benign_alternatives=("Could be sanctioned backup software.",),
        )
        from app.agent.verifier import _resolve_citations, check_finding

        resolved = _resolve_citations(ctx, {"EVIDENCE-1", "MITRE-T1567.002"}, {})
        check = check_finding(ctx, finding, resolved, check_scope=False)
    finally:
        session.close()
    assert check.technique_retrieval_ok is False
    assert check.valid is False


def test_check_finding_retrieval_accepts_retrieved_technique(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant, _analysis, _events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup
    )
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[payload])
        ctx.record_retrieved_techniques(["T1071.001"])
        finding = Finding(
            finding_id="FINDING-1",
            anomaly_ids=("EVIDENCE-1",),
            observation="Beaconing observed with 63 requests.",
            hypothesis="Consistent with periodic C2 check-in.",
            supporting_evidence_ids=("EVIDENCE-1",),
            contradicting_evidence_ids=(),
            missing_evidence=(),
            attack_technique_id="T1071.001",
            attack_source_id="MITRE-T1071.001",
            threat_confidence="moderate",
            confidence_reason="63 requests at regular intervals.",
            benign_alternatives=("Could be a health-check poller.",),
        )
        from app.agent.verifier import _resolve_citations, check_finding

        resolved = _resolve_citations(ctx, {"EVIDENCE-1", "MITRE-T1071.001"}, {})
        check = check_finding(ctx, finding, resolved, check_scope=False)
    finally:
        session.close()
    assert check.technique_retrieval_ok is True


def test_check_finding_no_known_mapping_is_always_retrieval_ok(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant, _analysis, _events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup
    )
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[payload])
        finding = Finding(
            finding_id="FINDING-1",
            anomaly_ids=("EVIDENCE-1",),
            observation="Anomalous but unexplained.",
            hypothesis="No known technique fits.",
            supporting_evidence_ids=(),
            contradicting_evidence_ids=(),
            missing_evidence=(),
            attack_technique_id=NO_KNOWN_MAPPING,
            attack_source_id=None,
            threat_confidence="low",
            confidence_reason="Evidence is too thin to map.",
            benign_alternatives=("Likely a misconfigured scheduled job.",),
        )
        from app.agent.verifier import _resolve_citations, check_finding

        resolved = _resolve_citations(ctx, set(), {})
        check = check_finding(ctx, finding, resolved, check_scope=False)
    finally:
        session.close()
    assert check.technique_retrieval_ok is True


# ---------------------------------------------------------------------------- verify_pass1 / verify_pass2


def _hypothesis_with_claims(good_claim: Claim, bad_claim: Claim) -> HypothesisEvaluation:
    return HypothesisEvaluation(
        technique_id="T1071.001",
        evidence_for=(good_claim, bad_claim),
        evidence_against=(),
        missing_evidence=(),
        assessment="plausible",
        threat_confidence="moderate",
    )


def _no_known_mapping() -> HypothesisEvaluation:
    return HypothesisEvaluation(
        technique_id=NO_KNOWN_MAPPING,
        evidence_for=(),
        evidence_against=(),
        missing_evidence=(),
        assessment="unsupported",
        threat_confidence="low",
    )


def test_verify_pass1_drops_claim_with_numeric_mismatch(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant, _analysis, _events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup, bytes_out_measurement=1_800_000_000.0
    )
    from app.agent.schemas import AnalystOutput

    good = Claim(text="63 requests observed", evidence_ids=("EVIDENCE-1",))
    bad = Claim(text="transferred 2.4 GB to the destination", evidence_ids=("EVIDENCE-1",))
    finding = Finding(
        finding_id="FINDING-1",
        anomaly_ids=("EVIDENCE-1",),
        observation="63 requests observed.",
        hypothesis="Consistent with C2 beaconing.",
        supporting_evidence_ids=("EVIDENCE-1",),
        contradicting_evidence_ids=(),
        missing_evidence=(),
        attack_technique_id="T1071.001",
        attack_source_id="MITRE-T1071.001",
        threat_confidence="moderate",
        confidence_reason="Regular interval.",
        benign_alternatives=("Could be a scheduled sync.",),
    )
    analyst_output = AnalystOutput(
        hypothesis_evaluations=(_hypothesis_with_claims(good, bad), _no_known_mapping()),
        findings=(finding,),
    )

    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[payload])
        result = verify_pass1(ctx, analyst_output)
    finally:
        session.close()

    surviving_texts = {
        c.text for c in result.sanitized_output.hypothesis_evaluations[0].evidence_for
    }
    assert good.text in surviving_texts
    assert bad.text not in surviving_texts
    assert any(c.claim.text == bad.text for c in result.dropped_claim_checks)


def test_verify_pass2_flags_finding_with_bad_number_from_revise(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """change 15: pass 2 catches a number introduced by a REVISE that was never checked before."""
    tenant, _analysis, _events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup, bytes_out_measurement=1_800_000_000.0
    )
    revised_finding = Finding(
        finding_id="FINDING-1",
        anomaly_ids=("EVIDENCE-1",),
        observation="Transferred 9.9 GB out, far above baseline.",  # fabricated by the judge's revision
        hypothesis="Consistent with bulk exfiltration.",
        supporting_evidence_ids=("EVIDENCE-1",),
        contradicting_evidence_ids=(),
        missing_evidence=(),
        attack_technique_id="T1567.002",
        attack_source_id="MITRE-T1567.002",
        threat_confidence="high",
        confidence_reason="9.9 GB transferred is far outside normal range.",
        benign_alternatives=("Could be a scheduled backup job.",),
    )
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[payload])
        result = verify_pass2(ctx, [revised_finding])
    finally:
        session.close()

    assert result.citation_valid is False
    assert result.invalid_citations
    assert result.finding_checks[0].valid is False


def test_verify_pass2_accepts_clean_finding(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant, _analysis, _events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup, bytes_out_measurement=1_800_000_000.0
    )
    finding = Finding(
        finding_id="FINDING-1",
        anomaly_ids=("EVIDENCE-1",),
        observation="63 requests observed, transferring 1.8 GB in total.",
        hypothesis="Consistent with scheduled data sync.",
        supporting_evidence_ids=("EVIDENCE-1",),
        contradicting_evidence_ids=(),
        missing_evidence=(),
        attack_technique_id=NO_KNOWN_MAPPING,
        attack_source_id=None,
        threat_confidence="low",
        confidence_reason="Regular pattern, benign-looking destination.",
        benign_alternatives=("Likely a scheduled backup.",),
    )
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[payload])
        result = verify_pass2(ctx, [finding])
    finally:
        session.close()
    assert result.citation_valid is True
    assert result.finding_checks[0].valid is True


# ---------------------------------------------------------------------------- hallucination_stats


def test_hallucination_stats_computed_from_pass2() -> None:
    class _FakeClaimCheck:
        def __init__(self, valid: bool) -> None:
            self._valid = valid

        @property
        def valid(self) -> bool:
            return self._valid

    class _FakeFindingCheck:
        def __init__(self, claim_checks: list[_FakeClaimCheck]) -> None:
            self.claim_checks = claim_checks

    from app.agent.verifier import Pass2Result

    pass2 = Pass2Result(
        finding_checks=(_FakeFindingCheck([_FakeClaimCheck(True), _FakeClaimCheck(False)]),),  # type: ignore[arg-type]
        citation_valid=False,
        invalid_citations=({"x": 1},),
    )
    stats = hallucination_stats(pass2)
    assert stats.total_citations == 2
    assert stats.invalid_citations == 1
    assert stats.hallucination_rate == pytest.approx(0.5)


# ---------------------------------------------------------------------------- verify_narrator_output


def test_verify_narrator_output_accepts_matching_numbers() -> None:
    overview = {"events": 83241, "users": 127}
    incidents: list[dict[str, Any]] = []
    timeline_phases = [
        {"phase_index": 0, "summary": "Initial burst", "log_ids": ["LOG-1"], "event_count": 12}
    ]
    output = NarratorOutput(
        executive_summary="83,241 events across 127 users were processed.",
        phase_narratives=(
            TimelinePhaseNarrative(
                phase_index=0, narrative="12 events in this phase.", cited_log_ids=("LOG-1",)
            ),
        ),
    )
    ok, invalid = verify_narrator_output(
        overview=overview, incidents=incidents, timeline_phases=timeline_phases, output=output
    )
    assert ok is True
    assert invalid == []


def test_verify_narrator_output_rejects_mismatched_number() -> None:
    overview = {"events": 83241}
    timeline_phases = [{"phase_index": 0, "summary": "x", "log_ids": ["LOG-1"]}]
    output = NarratorOutput(
        executive_summary="99,999 events were processed.",  # not in overview
        phase_narratives=(),
    )
    ok, invalid = verify_narrator_output(
        overview=overview, incidents=[], timeline_phases=timeline_phases, output=output
    )
    assert ok is False
    assert invalid[0]["section"] == "executive_summary"


def test_verify_narrator_output_rejects_phase_not_supplied() -> None:
    output = NarratorOutput(
        executive_summary="Some events happened.",
        phase_narratives=(
            TimelinePhaseNarrative(phase_index=5, narrative="Invented phase.", cited_log_ids=()),
        ),
    )
    ok, invalid = verify_narrator_output(
        overview={}, incidents=[], timeline_phases=[], output=output
    )
    assert ok is False
    assert "phase_5" in invalid[0]["section"]


def test_verify_narrator_output_rejects_out_of_scope_log_citation() -> None:
    timeline_phases = [{"phase_index": 0, "summary": "x", "log_ids": ["LOG-1"]}]
    output = NarratorOutput(
        executive_summary="Some events happened.",
        phase_narratives=(
            TimelinePhaseNarrative(
                phase_index=0, narrative="See this line.", cited_log_ids=("LOG-999",)
            ),
        ),
    )
    ok, invalid = verify_narrator_output(
        overview={}, incidents=[], timeline_phases=timeline_phases, output=output
    )
    assert ok is False
    assert any("LOG-999" in entry.get("ids", []) for entry in invalid)


# ---------------------------------------------------------------------------- verify_anomaly_confidence


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
        "narrative": ({"step": 1, "claim": "Regular interval requests.", "evidence_ids": ()},),
        "contradicting_evidence": "Could be a scheduled sync; timing rules it out.",
        "recommended_actions": ("Confirm with the user whether this destination is expected.",),
    }


def test_verify_anomaly_confidence_accepts_unchanged_value(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant, _analysis, incident = _setup_incident(tenant_cleanup, anomaly_confidence=87.3)
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[])
        verdict = TriageVerdictOut(**_valid_verdict_kwargs(anomaly_confidence=87.3))
        check = verify_anomaly_confidence(ctx, verdict)
    finally:
        session.close()

    assert isinstance(check, AnomalyConfidenceCheck)
    assert check.ok is True
    assert check.reason is None


def test_verify_anomaly_confidence_rejects_differing_value(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant, _analysis, incident = _setup_incident(tenant_cleanup, anomaly_confidence=87.3)
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[])
        verdict = TriageVerdictOut(**_valid_verdict_kwargs(anomaly_confidence=42.0))
        check = verify_anomaly_confidence(ctx, verdict)
    finally:
        session.close()

    assert check.ok is False
    assert check.reason is not None
    assert "87.3" in check.reason
    assert "42.0" in check.reason


def test_verify_anomaly_confidence_tolerates_float_roundtrip_noise_only(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant, _analysis, incident = _setup_incident(tenant_cleanup, anomaly_confidence=50.0)
    session = get_session_factory()()
    try:
        ctx = build_agent_context(session, tenant.id, incident.id, evidence_payloads=[])
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


# ---------------------------------------------------------------------------- triage_incident integration


class _ScriptedCaller:
    """A minimal stand-in for `app.agent.client.LLMCaller` — records every call for inspection
    (used by orchestrator-level tests) and replays scripted `Message`s in order."""

    def __init__(self, messages: list[Message]) -> None:
        self._messages = list(messages)
        self._index = 0
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Message:
        self.calls.append(kwargs)
        message = self._messages[self._index]
        self._index += 1
        return message


def _tool_message(*, tool_name: str, tool_input: dict[str, Any]) -> Message:
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


def _analysis_message(
    *, technique_id: str = "T1071.001", attack_source_id: str | None = "MITRE-T1071.001"
) -> Message:
    return _tool_message(
        tool_name="submit_analysis",
        tool_input={
            "hypothesis_evaluations": [
                {
                    "technique_id": technique_id,
                    "evidence_for": [
                        {"text": "63 requests observed.", "evidence_ids": ["EVIDENCE-1"]}
                    ],
                    "evidence_against": [],
                    "missing_evidence": [],
                    "assessment": "plausible",
                    "threat_confidence": "moderate",
                },
                {
                    "technique_id": NO_KNOWN_MAPPING,
                    "evidence_for": [],
                    "evidence_against": [],
                    "missing_evidence": [],
                    "assessment": "unsupported",
                    "threat_confidence": "low",
                },
            ],
            "findings": [
                {
                    "finding_id": "FINDING-1",
                    "anomaly_ids": ["EVIDENCE-1"],
                    "observation": "63 requests observed at regular intervals.",
                    "hypothesis": "Consistent with periodic beaconing.",
                    "supporting_evidence_ids": ["EVIDENCE-1"],
                    "contradicting_evidence_ids": [],
                    "missing_evidence": [],
                    "attack_technique_id": technique_id,
                    "attack_source_id": attack_source_id,
                    "threat_confidence": "moderate",
                    "confidence_reason": "Regular interval strongly matches beaconing.",
                    "benign_alternatives": ["Could be a scheduled health-check job."],
                }
            ],
        },
    )


def _judgement_message(*, decision: str = "PASS") -> Message:
    rubric = [{"item": i, "satisfied": decision == "PASS", "note": "checked"} for i in range(1, 11)]
    return _tool_message(
        tool_name="submit_judgement",
        tool_input={
            "verdicts": [
                {
                    "finding_id": "FINDING-1",
                    "decision": decision,
                    "rubric_assessment": rubric,
                    "rationale": "Evidence is well-cited and proportionate.",
                    "revised_finding": None,
                }
            ]
        },
    )


def _verdict_message(*, anomaly_confidence: float) -> Message:
    return _tool_message(
        tool_name="present_verdict",
        tool_input={
            "disposition": "true_positive",
            "threat_confidence": "moderate",
            "threat_confidence_reason": "Regular interval requests strongly match beaconing.",
            "anomaly_confidence": anomaly_confidence,
            "llm_severity_opinion": "medium",
            "mitre_techniques": [
                {"id": "T1071.001", "name": "Web Protocols", "rationale": "beaconing pattern"}
            ],
            "summary": "Beaconing pattern observed to a rare destination.",
            "narrative": [
                {
                    "step": 1,
                    "claim": "63 requests observed at regular intervals.",
                    "evidence_ids": ["EVIDENCE-1"],
                }
            ],
            "contradicting_evidence": "Could be a scheduled sync; timing rules it out.",
            "recommended_actions": ["Confirm with the user whether this destination is expected."],
        },
    )


def test_triage_incident_rejects_verdict_with_mismatched_anomaly_confidence(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant, _analysis, _events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup
    )
    caller = _ScriptedCaller(
        [_analysis_message(), _judgement_message(), _verdict_message(anomaly_confidence=42.0)]
    )

    session = get_session_factory()()
    try:
        row = triage_incident(
            session, tenant.id, incident.id, caller=caller, evidence_payloads=[payload]
        )
    finally:
        session.close()

    assert row.disposition == "needs_review"
    assert "anomaly_confidence integrity check failed" in row.summary


def test_triage_incident_accepts_verdict_with_unchanged_anomaly_confidence(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant, _analysis, _events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup
    )
    expected = incident.anomaly_confidence
    caller = _ScriptedCaller(
        [
            _analysis_message(),
            _judgement_message(),
            _verdict_message(anomaly_confidence=round(expected, 1)),
        ]
    )

    session = get_session_factory()()
    try:
        row = triage_incident(
            session, tenant.id, incident.id, caller=caller, evidence_payloads=[payload]
        )
    finally:
        session.close()

    assert row.disposition == "true_positive"
    assert row.threat_confidence == "moderate"


def test_nothing_in_the_agent_path_can_write_anomaly_confidence(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    assert "anomaly_confidence" not in {c.name for c in TriageVerdict.__table__.columns}

    tenant, _analysis, _events, _signal, incident, payload = _setup_incident_with_evidence(
        tenant_cleanup
    )
    expected = round(incident.anomaly_confidence, 1)
    caller = _ScriptedCaller(
        [_analysis_message(), _judgement_message(), _verdict_message(anomaly_confidence=expected)]
    )

    session = get_session_factory()()
    try:
        row = triage_incident(
            session, tenant.id, incident.id, caller=caller, evidence_payloads=[payload]
        )
        assert not hasattr(row, "anomaly_confidence")
        with tenant_scope(session, tenant.id):
            refreshed = session.get(Incident, incident.id)
            assert refreshed is not None
            assert refreshed.anomaly_confidence == pytest.approx(incident.anomaly_confidence)
    finally:
        session.close()
