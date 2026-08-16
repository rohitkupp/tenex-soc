"""`app.agent.schemas` — the four-stage pipeline's structured-output models and dynamic tool
schemas (docs/v2_migration/MIGRATION-01-evidence-first.md changes 5, 6, 7).

This is the primary proof site for the anti-hallucination schema layer: `NO_KNOWN_MAPPING` is
mandatory in every `AnalystOutput.hypothesis_evaluations` set (change 5), a `Finding` cannot
report a technique it never evaluated, a fabricated technique id cannot survive validation, and a
`JudgeVerdict`'s `revised_finding` is coupled to its `decision` exactly as change 15 requires.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.agent.mitre import all_technique_ids
from app.agent.schemas import (
    JUDGE_RUBRIC,
    NO_KNOWN_MAPPING,
    AnalystOutput,
    Claim,
    Finding,
    HypothesisEvaluation,
    JudgeOutput,
    JudgeVerdict,
    MitreTechniqueRef,
    NarrativeStep,
    NarratorOutput,
    RubricItemResult,
    TimelinePhaseNarrative,
    TriageVerdictOut,
    build_narrate_tool,
    build_present_verdict_tool,
    build_submit_analysis_tool,
    build_submit_judgement_tool,
)

_REAL_TECHNIQUE = "T1071.001"
_OTHER_TECHNIQUE = "T1567.002"


def _claim(
    text: str = "63 requests to the same destination.", ids: tuple[str, ...] = ("EVIDENCE-1",)
) -> Claim:
    return Claim(text=text, evidence_ids=ids)


def _hypothesis_evaluation(
    technique_id: str = _REAL_TECHNIQUE, *, assessment: str = "supported"
) -> HypothesisEvaluation:
    return HypothesisEvaluation(
        technique_id=technique_id,
        evidence_for=(_claim(),),
        evidence_against=(),
        missing_evidence=("endpoint telemetry",),
        assessment=assessment,  # type: ignore[arg-type]
        threat_confidence="moderate",
    )


def _no_known_mapping_evaluation() -> HypothesisEvaluation:
    return HypothesisEvaluation(
        technique_id=NO_KNOWN_MAPPING,
        evidence_for=(),
        evidence_against=(_claim("No corroborating evidence found.", ()),),
        missing_evidence=(),
        assessment="unsupported",
        threat_confidence="low",
    )


def _finding(
    finding_id: str = "FINDING-1",
    *,
    attack_technique_id: str = _REAL_TECHNIQUE,
    attack_source_id: str | None = "MITRE-T1071.001",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        anomaly_ids=("EVIDENCE-1",),
        observation="63 requests observed over two hours.",
        hypothesis="Consistent with periodic beaconing.",
        supporting_evidence_ids=("EVIDENCE-1",),
        contradicting_evidence_ids=(),
        missing_evidence=("endpoint telemetry",),
        attack_technique_id=attack_technique_id,
        attack_source_id=attack_source_id,
        threat_confidence="moderate",
        confidence_reason="Regular interval strongly matches beaconing.",
        benign_alternatives=("Could be a scheduled health-check job.",),
    )


# ---------------------------------------------------------------------------- Claim / NarrativeStep


def test_claim_rejects_blank_text() -> None:
    with pytest.raises(ValidationError):
        Claim(text="   ", evidence_ids=())


def test_claim_evidence_ids_default_empty() -> None:
    assert Claim(text="x").evidence_ids == ()


def test_narrative_step_rejects_blank_claim() -> None:
    with pytest.raises(ValidationError):
        NarrativeStep(step=1, claim="  ", evidence_ids=("LOG-1",))


def test_narrative_step_rejects_zero_or_negative_step() -> None:
    with pytest.raises(ValidationError):
        NarrativeStep(step=0, claim="x", evidence_ids=())


def test_narrative_step_uses_string_citation_ids_not_bare_ints() -> None:
    """docs/v2_migration change 7: dual-namespace string citations replace the pre-migration
    bare-integer `evidence_event_ids`."""
    step = NarrativeStep(
        step=1, claim="x", evidence_ids=("EVIDENCE-1", "LOG-1291", "MITRE-T1071.001")
    )
    assert step.evidence_ids == ("EVIDENCE-1", "LOG-1291", "MITRE-T1071.001")


# ---------------------------------------------------------------------------- MitreTechniqueRef


def test_mitre_technique_ref_accepts_real_id() -> None:
    assert (
        MitreTechniqueRef(id=_REAL_TECHNIQUE, name="Web Protocols", rationale="ok").id
        == _REAL_TECHNIQUE
    )


def test_mitre_technique_ref_rejects_fabricated_id() -> None:
    with pytest.raises(ValidationError, match="does not exist in the MITRE corpus"):
        MitreTechniqueRef(id="T9999.999", name="Fake Technique", rationale="invented")


def test_mitre_technique_ref_rejects_no_known_mapping() -> None:
    """`NO_KNOWN_MAPPING` belongs on `Finding.attack_technique_id`, never inside a
    `MitreTechniqueRef` -- the Presenter's `mitre_techniques` list is real techniques only."""
    with pytest.raises(ValidationError, match="does not exist in the MITRE corpus"):
        MitreTechniqueRef(id=NO_KNOWN_MAPPING, name="x", rationale="x")


# ---------------------------------------------------------------------------- HypothesisEvaluation


def test_hypothesis_evaluation_accepts_no_known_mapping() -> None:
    h = _no_known_mapping_evaluation()
    assert h.technique_id == NO_KNOWN_MAPPING


def test_hypothesis_evaluation_accepts_real_technique() -> None:
    h = _hypothesis_evaluation()
    assert h.technique_id == _REAL_TECHNIQUE


def test_hypothesis_evaluation_rejects_fabricated_technique() -> None:
    with pytest.raises(ValidationError, match="does not exist in the MITRE corpus"):
        _hypothesis_evaluation("T0000.FAKE")


def test_hypothesis_evaluation_rejects_invalid_assessment_enum() -> None:
    with pytest.raises(ValidationError):
        HypothesisEvaluation(
            technique_id=_REAL_TECHNIQUE,
            evidence_for=(),
            evidence_against=(),
            missing_evidence=(),
            assessment="definitely_true",  # type: ignore[arg-type]
            threat_confidence="low",
        )


# ---------------------------------------------------------------------------- Finding


def test_finding_accepts_valid_payload() -> None:
    f = _finding()
    assert f.attack_technique_id == _REAL_TECHNIQUE
    assert f.benign_alternatives


def test_finding_requires_benign_alternatives() -> None:
    """change 6: the devil's-advocate function is mandatory, not optional. `model_copy` does not
    re-run validators, so this constructs directly rather than copying a valid instance."""
    with pytest.raises(ValidationError, match="benign_alternatives"):
        Finding(
            finding_id="FINDING-1",
            anomaly_ids=(),
            observation="x",
            hypothesis="x",
            supporting_evidence_ids=(),
            contradicting_evidence_ids=(),
            missing_evidence=(),
            attack_technique_id=NO_KNOWN_MAPPING,
            attack_source_id=None,
            threat_confidence="low",
            confidence_reason="x",
            benign_alternatives=(),
        )


def test_finding_no_known_mapping_forbids_attack_source_id() -> None:
    with pytest.raises(ValidationError, match="attack_source_id must be null"):
        _finding(attack_technique_id=NO_KNOWN_MAPPING, attack_source_id="MITRE-T1071.001")


def test_finding_real_technique_requires_attack_source_id() -> None:
    with pytest.raises(ValidationError, match="attack_source_id is required"):
        _finding(attack_source_id=None)


def test_finding_no_known_mapping_with_null_source_is_valid() -> None:
    f = _finding(attack_technique_id=NO_KNOWN_MAPPING, attack_source_id=None)
    assert f.attack_technique_id == NO_KNOWN_MAPPING
    assert f.attack_source_id is None


def test_finding_rejects_fabricated_technique() -> None:
    with pytest.raises(ValidationError, match="does not exist in the MITRE corpus"):
        _finding(attack_technique_id="T0000.FAKE", attack_source_id="MITRE-T0000.FAKE")


# ---------------------------------------------------------------------------- AnalystOutput


def test_analyst_output_requires_no_known_mapping_evaluation() -> None:
    """change 5, verbatim: NO_KNOWN_MAPPING is mandatory in every candidate set."""
    with pytest.raises(ValidationError, match="NO_KNOWN_MAPPING"):
        AnalystOutput(
            hypothesis_evaluations=(_hypothesis_evaluation(),),
            findings=(_finding(),),
        )


def test_analyst_output_accepts_no_known_mapping_only_set() -> None:
    """A seeded evidence package supporting nothing: NO_KNOWN_MAPPING must be reachable and
    correct, not forced toward a fabricated attribution."""
    out = AnalystOutput(
        hypothesis_evaluations=(_no_known_mapping_evaluation(),),
        findings=(_finding(attack_technique_id=NO_KNOWN_MAPPING, attack_source_id=None),),
    )
    assert out.findings[0].attack_technique_id == NO_KNOWN_MAPPING


def test_analyst_output_requires_at_least_one_finding() -> None:
    with pytest.raises(ValidationError, match="findings must be non-empty"):
        AnalystOutput(hypothesis_evaluations=(_no_known_mapping_evaluation(),), findings=())


def test_analyst_output_rejects_finding_technique_never_evaluated() -> None:
    """A finding cannot report a technique the Analyst never ran a change-5 evaluation for."""
    with pytest.raises(ValidationError, match="never evaluated"):
        AnalystOutput(
            hypothesis_evaluations=(_no_known_mapping_evaluation(),),
            findings=(
                _finding(attack_technique_id=_OTHER_TECHNIQUE, attack_source_id="MITRE-T1567.002"),
            ),
        )


def test_analyst_output_accepts_multiple_evaluations_and_findings() -> None:
    out = AnalystOutput(
        hypothesis_evaluations=(_no_known_mapping_evaluation(), _hypothesis_evaluation()),
        findings=(_finding(),),
    )
    assert len(out.hypothesis_evaluations) == 2


# ---------------------------------------------------------------------------- JudgeVerdict / JudgeOutput


def _rubric_full(*, all_satisfied: bool = True) -> tuple[RubricItemResult, ...]:
    return tuple(
        RubricItemResult(item=i, satisfied=all_satisfied, note=f"item {i} checked")
        for i in range(1, len(JUDGE_RUBRIC) + 1)
    )


def test_judge_verdict_pass_forbids_revised_finding() -> None:
    with pytest.raises(ValidationError, match="must be null"):
        JudgeVerdict(
            finding_id="FINDING-1",
            decision="PASS",
            rubric_assessment=_rubric_full(),
            rationale="Well supported.",
            revised_finding=_finding(),
        )


def test_judge_verdict_revise_requires_revised_finding() -> None:
    with pytest.raises(ValidationError, match="requires a revised_finding"):
        JudgeVerdict(
            finding_id="FINDING-1",
            decision="REVISE",
            rubric_assessment=_rubric_full(),
            rationale="Confidence too high for the evidence.",
            revised_finding=None,
        )


def test_judge_verdict_revised_finding_must_match_finding_id() -> None:
    with pytest.raises(ValidationError, match="must match the finding_id"):
        JudgeVerdict(
            finding_id="FINDING-1",
            decision="REVISE",
            rubric_assessment=_rubric_full(),
            rationale="x",
            revised_finding=_finding(finding_id="FINDING-2"),
        )


def test_judge_verdict_reject_accepts_no_revised_finding() -> None:
    v = JudgeVerdict(
        finding_id="FINDING-1",
        decision="REJECT",
        rubric_assessment=_rubric_full(all_satisfied=False),
        rationale="Insufficient evidence for the claimed mapping.",
        revised_finding=None,
    )
    assert v.decision == "REJECT"


def test_judge_verdict_rejects_incomplete_rubric() -> None:
    incomplete = tuple(
        RubricItemResult(item=i, satisfied=True, note="ok") for i in range(1, len(JUDGE_RUBRIC))
    )
    with pytest.raises(ValidationError, match="must cover every item"):
        JudgeVerdict(
            finding_id="FINDING-1", decision="PASS", rubric_assessment=incomplete, rationale="x"
        )


def test_judge_verdict_rejects_duplicate_rubric_item() -> None:
    dup = tuple(
        RubricItemResult(item=1, satisfied=True, note="ok") for _ in range(len(JUDGE_RUBRIC))
    )
    with pytest.raises(ValidationError, match="must cover every item"):
        JudgeVerdict(finding_id="FINDING-1", decision="PASS", rubric_assessment=dup, rationale="x")


def test_judge_output_requires_at_least_one_verdict() -> None:
    with pytest.raises(ValidationError, match="verdicts must be non-empty"):
        JudgeOutput(verdicts=())


# ---------------------------------------------------------------------------- TriageVerdictOut


def _valid_verdict_kwargs() -> dict:
    return {
        "disposition": "true_positive",
        "threat_confidence": "high",
        "threat_confidence_reason": "Beaconing pattern strongly matches known C2 cadence.",
        "anomaly_confidence": 87.3,
        "llm_severity_opinion": "high",
        "mitre_techniques": [
            {"id": _REAL_TECHNIQUE, "name": "Web Protocols", "rationale": "beaconing pattern"}
        ],
        "summary": "A real summary of what happened.",
        "narrative": [
            {"step": 1, "claim": "Something happened.", "evidence_ids": ["EVIDENCE-1", "LOG-42"]}
        ],
        "contradicting_evidence": "Could be a scheduled sync job, but timing rules it out.",
        "recommended_actions": ["Block evil.example at the proxy pending confirmation."],
    }


def test_triage_verdict_out_accepts_valid_payload() -> None:
    verdict = TriageVerdictOut(**_valid_verdict_kwargs())
    assert verdict.disposition == "true_positive"
    assert verdict.citation_valid is True  # default, filled in later by the verifier
    assert verdict.invalid_citations == ()


def test_triage_verdict_out_rejects_fabricated_technique_id() -> None:
    kwargs = _valid_verdict_kwargs()
    kwargs["mitre_techniques"] = [{"id": "T0000.FAKE", "name": "Not Real", "rationale": "invented"}]
    with pytest.raises(ValidationError, match="does not exist in the MITRE corpus"):
        TriageVerdictOut(**kwargs)


def test_triage_verdict_out_rejects_blank_recommended_action() -> None:
    kwargs = _valid_verdict_kwargs()
    kwargs["recommended_actions"] = ["   "]
    with pytest.raises(ValidationError, match="must not be blank"):
        TriageVerdictOut(**kwargs)


def test_triage_verdict_out_rejects_anomaly_confidence_out_of_range() -> None:
    kwargs = _valid_verdict_kwargs()
    kwargs["anomaly_confidence"] = 150.0
    with pytest.raises(ValidationError):
        TriageVerdictOut(**kwargs)


def test_triage_verdict_out_requires_narrative_unless_needs_review() -> None:
    kwargs = _valid_verdict_kwargs()
    kwargs["narrative"] = []
    with pytest.raises(ValidationError, match="narrative must have at least one step"):
        TriageVerdictOut(**kwargs)


def test_triage_verdict_out_allows_empty_narrative_for_needs_review() -> None:
    kwargs = _valid_verdict_kwargs()
    kwargs["disposition"] = "needs_review"
    kwargs["narrative"] = []
    assert TriageVerdictOut(**kwargs).narrative == ()


def test_triage_verdict_out_rejects_unknown_field() -> None:
    kwargs = _valid_verdict_kwargs()
    kwargs["confidence"] = 0.8  # the old, pre-migration blended field
    with pytest.raises(ValidationError):
        TriageVerdictOut(**kwargs)


# ---------------------------------------------------------------------------- NarratorOutput


def test_narrator_output_rejects_blank_executive_summary() -> None:
    with pytest.raises(ValidationError):
        NarratorOutput(executive_summary="   ", phase_narratives=())


def test_narrator_output_accepts_phase_narratives() -> None:
    out = NarratorOutput(
        executive_summary="83,241 events across 127 users.",
        phase_narratives=(
            TimelinePhaseNarrative(
                phase_index=0, narrative="Initial access window.", cited_log_ids=("LOG-1",)
            ),
        ),
    )
    assert out.phase_narratives[0].phase_index == 0


def test_timeline_phase_narrative_rejects_blank_narrative() -> None:
    with pytest.raises(ValidationError):
        TimelinePhaseNarrative(phase_index=0, narrative="  ", cited_log_ids=())


# ---------------------------------------------------------------------------- dynamic tool schemas


def test_submit_analysis_tool_is_strict_and_fully_closed() -> None:
    tool = build_submit_analysis_tool()
    assert tool["strict"] is True
    schema = tool["input_schema"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])


def test_submit_analysis_tool_technique_enum_includes_no_known_mapping() -> None:
    tool = build_submit_analysis_tool()
    eval_schema = tool["input_schema"]["properties"]["hypothesis_evaluations"]["items"]
    enum = eval_schema["properties"]["technique_id"]["enum"]
    assert set(enum) == set(all_technique_ids()) | {NO_KNOWN_MAPPING}

    finding_schema = tool["input_schema"]["properties"]["findings"]["items"]
    finding_enum = finding_schema["properties"]["attack_technique_id"]["enum"]
    assert set(finding_enum) == set(all_technique_ids()) | {NO_KNOWN_MAPPING}


def test_submit_judgement_tool_is_strict_and_fully_closed() -> None:
    tool = build_submit_judgement_tool()
    assert tool["strict"] is True
    schema = tool["input_schema"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])


def test_submit_judgement_tool_rubric_item_enum_matches_rubric_length() -> None:
    tool = build_submit_judgement_tool()
    verdict_schema = tool["input_schema"]["properties"]["verdicts"]["items"]
    rubric_item_schema = verdict_schema["properties"]["rubric_assessment"]["items"]
    assert rubric_item_schema["properties"]["item"]["enum"] == list(range(1, len(JUDGE_RUBRIC) + 1))


def test_present_verdict_tool_is_strict_and_fully_closed() -> None:
    tool = build_present_verdict_tool()
    assert tool["strict"] is True
    schema = tool["input_schema"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])


def test_present_verdict_tool_recommended_actions_is_free_text_no_enum() -> None:
    """docs/v2_migration change 20: no response action catalog to enumerate against."""
    tool = build_present_verdict_tool()
    action_schema = tool["input_schema"]["properties"]["recommended_actions"]["items"]
    assert action_schema == {"type": "string"}


def test_present_verdict_tool_narrative_citations_are_strings() -> None:
    tool = build_present_verdict_tool()
    step_schema = tool["input_schema"]["properties"]["narrative"]["items"]
    assert step_schema["properties"]["evidence_ids"] == {
        "type": "array",
        "items": {"type": "string"},
    }


def test_build_narrate_tool_is_strict_and_fully_closed() -> None:
    tool = build_narrate_tool()
    assert tool["strict"] is True
    schema = tool["input_schema"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])
