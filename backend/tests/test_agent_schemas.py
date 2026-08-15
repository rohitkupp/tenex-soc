"""`app.agent.schemas` — the structured-output models and the dynamic tool-schema builders.

This is the primary proof site for CLAUDE.md's build brief: "Prove no technique ID outside the
corpus can survive validation" — both at the JSON-Schema layer (`build_*_tool`'s enum) and the
independent pydantic layer (`MitreTechniqueRef`/`RecommendedAction`), which is what lets this be
proven without a live or fixture API call.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.agent.mitre import all_technique_ids
from app.agent.schemas import (
    MitreTechniqueRef,
    NarrativeStep,
    RecommendedAction,
    TriageVerdictOut,
    build_emit_verdict_tool,
    build_submit_findings_tool,
    build_submit_rebuttal_tool,
)
from app.response.catalog import get_catalog


def _valid_verdict_kwargs() -> dict:
    return {
        "disposition": "true_positive",
        "confidence": 0.8,
        "llm_severity_opinion": "high",
        "mitre_techniques": [
            {"id": "T1071.001", "name": "Web Protocols", "rationale": "beaconing pattern"}
        ],
        "summary": "A real summary of what happened.",
        "narrative": [{"step": 1, "claim": "Something happened.", "evidence_event_ids": [1, 2]}],
        "contradicting_evidence": "Could be a scheduled sync job, but timing rules it out.",
        "recommended_actions": [
            {"action": "block_domain_at_proxy", "target": "evil.example", "rationale": "stop C2"}
        ],
    }


# ---------------------------------------------------------------------------- MitreTechniqueRef


def test_mitre_technique_ref_accepts_real_id() -> None:
    ref = MitreTechniqueRef(id="T1071.001", name="Web Protocols", rationale="ok")
    assert ref.id == "T1071.001"


def test_mitre_technique_ref_rejects_fabricated_id() -> None:
    """The core anti-hallucination assertion, independent of any API response."""
    with pytest.raises(ValidationError, match="does not exist in the MITRE corpus"):
        MitreTechniqueRef(id="T9999.999", name="Fake Technique", rationale="invented")


def test_mitre_technique_ref_rejects_blank_fields() -> None:
    with pytest.raises(ValidationError):
        MitreTechniqueRef(id="T1071.001", name="", rationale="ok")
    with pytest.raises(ValidationError):
        MitreTechniqueRef(id="T1071.001", name="Web Protocols", rationale="   ")


# ---------------------------------------------------------------------------- RecommendedAction


def test_recommended_action_accepts_real_catalog_id() -> None:
    action = RecommendedAction(action="block_domain_at_proxy", target="evil.example", rationale="x")
    assert action.action == "block_domain_at_proxy"


def test_recommended_action_rejects_free_text_action() -> None:
    """docs/07: "recommended_actions[].action must be an action ID from the response action
    graph. Free-text actions are rejected." """
    with pytest.raises(ValidationError, match="not in the response action catalog"):
        RecommendedAction(action="block_domain", target="evil.example", rationale="x")


def test_recommended_action_rejects_blank_fields() -> None:
    with pytest.raises(ValidationError):
        RecommendedAction(action="block_domain_at_proxy", target="", rationale="x")


# ---------------------------------------------------------------------------- NarrativeStep


def test_narrative_step_rejects_blank_claim() -> None:
    with pytest.raises(ValidationError):
        NarrativeStep(step=1, claim="  ", evidence_event_ids=(1,))


def test_narrative_step_rejects_zero_or_negative_step() -> None:
    with pytest.raises(ValidationError):
        NarrativeStep(step=0, claim="x", evidence_event_ids=())


def test_narrative_step_evidence_event_ids_can_be_empty() -> None:
    step = NarrativeStep(step=1, claim="x", evidence_event_ids=())
    assert step.evidence_event_ids == ()


# ---------------------------------------------------------------------------- TriageVerdictOut


def test_triage_verdict_out_accepts_valid_payload() -> None:
    verdict = TriageVerdictOut(**_valid_verdict_kwargs())
    assert verdict.disposition == "true_positive"
    assert verdict.citation_valid is True  # default, filled in later by the verifier
    assert verdict.invalid_citations == ()


def test_triage_verdict_out_rejects_fabricated_technique_id() -> None:
    kwargs = _valid_verdict_kwargs()
    kwargs["mitre_techniques"] = [
        {"id": "T0000.FAKE", "name": "Not Real", "rationale": "invented by the model"}
    ]
    with pytest.raises(ValidationError, match="does not exist in the MITRE corpus"):
        TriageVerdictOut(**kwargs)


def test_triage_verdict_out_rejects_free_text_action() -> None:
    kwargs = _valid_verdict_kwargs()
    kwargs["recommended_actions"] = [
        {"action": "delete_everything", "target": "prod", "rationale": "oops"}
    ]
    with pytest.raises(ValidationError, match="not in the response action catalog"):
        TriageVerdictOut(**kwargs)


def test_triage_verdict_out_rejects_invalid_disposition_enum() -> None:
    kwargs = _valid_verdict_kwargs()
    kwargs["disposition"] = "definitely_malicious"  # not one of the four allowed values
    with pytest.raises(ValidationError):
        TriageVerdictOut(**kwargs)


def test_triage_verdict_out_rejects_confidence_out_of_range() -> None:
    kwargs = _valid_verdict_kwargs()
    kwargs["confidence"] = 1.5
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
    verdict = TriageVerdictOut(**kwargs)
    assert verdict.narrative == ()


def test_triage_verdict_out_rejects_blank_summary_or_contradicting_evidence() -> None:
    kwargs = _valid_verdict_kwargs()
    kwargs["summary"] = "   "
    with pytest.raises(ValidationError):
        TriageVerdictOut(**kwargs)

    kwargs = _valid_verdict_kwargs()
    kwargs["contradicting_evidence"] = ""
    with pytest.raises(ValidationError):
        TriageVerdictOut(**kwargs)


def test_triage_verdict_out_rejects_unknown_field() -> None:
    kwargs = _valid_verdict_kwargs()
    kwargs["some_field_the_model_made_up"] = "x"
    with pytest.raises(ValidationError):
        TriageVerdictOut(**kwargs)


# ---------------------------------------------------------------------------- dynamic tool schemas


def test_emit_verdict_tool_technique_enum_matches_corpus_exactly() -> None:
    tool = build_emit_verdict_tool()
    technique_schema = tool["input_schema"]["properties"]["mitre_techniques"]["items"]
    enum = technique_schema["properties"]["id"]["enum"]
    assert set(enum) == set(all_technique_ids())


def test_emit_verdict_tool_action_enum_matches_catalog_exactly() -> None:
    tool = build_emit_verdict_tool()
    action_schema = tool["input_schema"]["properties"]["recommended_actions"]["items"]
    enum = action_schema["properties"]["action"]["enum"]
    assert set(enum) == set(get_catalog().actions)


def test_emit_verdict_tool_is_strict_and_fully_closed() -> None:
    tool = build_emit_verdict_tool()
    assert tool["strict"] is True
    schema = tool["input_schema"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])


def test_submit_findings_and_submit_rebuttal_tools_are_strict_and_fully_closed() -> None:
    for tool in (build_submit_findings_tool(), build_submit_rebuttal_tool()):
        assert tool["strict"] is True
        schema = tool["input_schema"]
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])


def test_submit_findings_technique_enum_matches_corpus() -> None:
    tool = build_submit_findings_tool()
    technique_schema = tool["input_schema"]["properties"]["mitre_techniques"]["items"]
    assert set(technique_schema["properties"]["id"]["enum"]) == set(all_technique_ids())
