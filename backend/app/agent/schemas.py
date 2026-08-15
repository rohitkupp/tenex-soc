"""Structured-output schemas for the three-role flow — docs/07-AGENT.md "Output schema" and
docs/06-PRIVACY-SECURITY.md defense #4/#5 ("Structured output only" / "Output validation").

Two layers of defense against a fabricated technique/action id, deliberately redundant:

1. **Schema-level (this module, `build_*_tool`)**: the `mitre_techniques[].id` and
   `recommended_actions[].action` tool-parameter fields are JSON-Schema `enum`s built from
   `app.agent.mitre.all_technique_ids()` / `app.response.catalog.get_catalog()` at request time.
   With `strict: true` on the tool definition, the Messages API itself cannot produce a value
   outside the enum — a fabricated id is not just invalid, it is not a representable output.
2. **Pydantic-level (the models below)**: `MitreTechniqueRef`/`RecommendedAction` re-validate
   the same constraint independently of the API. This is not redundant paranoia — it is what
   lets `tests/test_agent_verifier.py` prove the rejection path works by constructing a bad
   payload directly, without needing a live (or even a fixture) API response that somehow
   defeats layer 1, and it is what protects a fixture-replay test path from ever silently
   accepting a corpus/catalog drift that layer 1 alone wouldn't catch offline.

Every model here is used for the *final* verdict and the two intermediate role outputs
(`InvestigationFindings`, `Rebuttal`) — see `app/agent/orchestrator.py`.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.agent.mitre import all_technique_ids, technique_exists
from app.response.catalog import get_catalog

__all__ = [
    "AgentRole",
    "Disposition",
    "InvestigationFindings",
    "MitreTechniqueRef",
    "NarrativeStep",
    "Rebuttal",
    "RecommendedAction",
    "SchemaValidationError",
    "ToolTraceEntry",
    "TriageVerdictOut",
    "build_emit_verdict_tool",
    "build_submit_findings_tool",
    "build_submit_rebuttal_tool",
]

Disposition = Literal["true_positive", "false_positive", "benign", "needs_review"]
Severity = Literal["critical", "high", "medium", "low"]
AgentRole = Literal["investigator", "devils_advocate", "reporter"]

_DISPOSITIONS: Final[tuple[str, ...]] = (
    "true_positive",
    "false_positive",
    "benign",
    "needs_review",
)
_SEVERITIES: Final[tuple[str, ...]] = ("critical", "high", "medium", "low")


class SchemaValidationError(Exception):
    """A structured-output payload failed post-hoc validation (bad technique id, bad action id,
    bad enum value, blank required field). docs/06 defense #5: "Failures are rejected, not
    coerced" — the orchestrator catches this and emits `needs_review`, it never tries to patch
    the payload into something valid."""


class MitreTechniqueRef(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    name: str
    rationale: str

    @field_validator("id")
    @classmethod
    def _must_exist_in_corpus(cls, v: str) -> str:
        if not technique_exists(v):
            raise ValueError(f"technique id {v!r} does not exist in the MITRE corpus")
        return v

    @field_validator("name", "rationale")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be blank")
        return v


class RecommendedAction(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str
    target: str
    rationale: str

    @field_validator("action")
    @classmethod
    def _must_exist_in_catalog(cls, v: str) -> str:
        if v not in get_catalog():
            raise ValueError(f"action id {v!r} is not in the response action catalog")
        return v

    @field_validator("target", "rationale")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be blank")
        return v


class NarrativeStep(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    step: int = Field(ge=1)
    claim: str
    evidence_event_ids: tuple[int, ...] = Field(default_factory=tuple)

    @field_validator("claim")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be blank")
        return v


class InvestigationFindings(BaseModel):
    """The Investigator role's terminal `submit_findings` tool call — docs/07's own output
    schema doesn't separately name this (it only specifies the *final* verdict shape), but the
    Reporter has no tools of its own, so the Investigator's citations have to reach it in a
    structurally-validated form rather than scraped from prose. See orchestrator.py's module
    docstring for the full three-role rationale."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    hypothesis: str
    disposition_lean: Disposition
    narrative: tuple[NarrativeStep, ...]
    mitre_techniques: tuple[MitreTechniqueRef, ...] = Field(default_factory=tuple)
    recommended_actions: tuple[RecommendedAction, ...] = Field(default_factory=tuple)

    @field_validator("hypothesis")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be blank")
        return v


class Rebuttal(BaseModel):
    """The Devil's Advocate role's terminal `submit_rebuttal` tool call. `contradicting_evidence`
    is the field docs/07 calls out as required on the *final* verdict — captured here, at the
    role that actually argues it, and carried forward verbatim by the Reporter."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    contradicting_evidence: str
    agrees_with_disposition: bool
    notes: str = ""

    @field_validator("contradicting_evidence")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be blank")
        return v


class ToolTraceEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    role: AgentRole
    tool_name: str
    tool_input: dict[str, Any]
    is_error: bool = False
    summary: str = ""  # short, human-readable result summary — not the full payload (cost control)


class TriageVerdictOut(BaseModel):
    """docs/07's final output schema, exactly, plus the fields
    `app.models.triage_verdict.TriageVerdict` needs for persistence (`tool_trace`,
    `citation_valid`, `invalid_citations`, `model`, token/cost/latency). Citation-verification
    fields default empty and are filled in by `app.agent.verifier` *after* this model validates —
    they are not part of what the LLM emits."""

    model_config = ConfigDict(extra="forbid")

    disposition: Disposition
    confidence: float = Field(ge=0.0, le=1.0)
    llm_severity_opinion: Severity | None = None
    mitre_techniques: tuple[MitreTechniqueRef, ...] = Field(default_factory=tuple)
    summary: str
    narrative: tuple[NarrativeStep, ...]
    contradicting_evidence: str
    recommended_actions: tuple[RecommendedAction, ...] = Field(default_factory=tuple)

    # --- filled in after construction, not part of the LLM's tool-use payload ---
    tool_trace: tuple[ToolTraceEntry, ...] = Field(default_factory=tuple)
    citation_valid: bool = True
    invalid_citations: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    model: str = ""
    tokens_in: int | None = None
    tokens_out: int | None = None
    cost_usd: Decimal | None = None
    latency_ms: int | None = None
    needs_review_reason: str | None = None
    created_at: datetime | None = None

    @field_validator("summary", "contradicting_evidence")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be blank")
        return v

    @model_validator(mode="after")
    def _narrative_required_unless_needs_review(self) -> TriageVerdictOut:
        # needs_review is a legitimate answer with insufficient evidence (docs/07): don't force a
        # fabricated narrative step just to satisfy a non-empty-list rule.
        if self.disposition != "needs_review" and not self.narrative:
            raise ValueError(
                "narrative must have at least one step unless disposition is needs_review"
            )
        return self


# ---------------------------------------------------------------------------- dynamic tool schemas


def _technique_ref_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "id": {"type": "string", "enum": list(all_technique_ids())},
            "name": {"type": "string"},
            "rationale": {"type": "string"},
        },
        "required": ["id", "name", "rationale"],
        "additionalProperties": False,
    }


def _action_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": sorted(get_catalog().actions)},
            "target": {"type": "string"},
            "rationale": {"type": "string"},
        },
        "required": ["action", "target", "rationale"],
        "additionalProperties": False,
    }


def _narrative_step_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "step": {"type": "integer"},
            "claim": {"type": "string"},
            "evidence_event_ids": {"type": "array", "items": {"type": "integer"}},
        },
        "required": ["step", "claim", "evidence_event_ids"],
        "additionalProperties": False,
    }


def build_submit_findings_tool() -> dict[str, Any]:
    """The Investigator's terminal tool. `strict: true` (like `emit_verdict` below) so the
    `mitre_techniques[].id` corpus enum is enforced at the API layer, not just by
    `InvestigationFindings`'s pydantic validator after the fact. Strict mode requires every
    property to appear in `required` — `mitre_techniques`/`recommended_actions` are still
    semantically optional; the model satisfies "required" by sending `[]` when it has none."""
    return {
        "name": "submit_findings",
        "description": (
            "Submit your investigation findings: a working hypothesis, a disposition lean, a "
            "step-by-step narrative where every factual claim cites the specific event ids that "
            "support it, any MITRE techniques you can defend from the search_mitre corpus "
            "(empty array if none apply), and any response actions you'd recommend from the "
            "catalog (empty array if none). Call this once, when your investigation is complete."
        ),
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "hypothesis": {"type": "string"},
                "disposition_lean": {"type": "string", "enum": list(_DISPOSITIONS)},
                "narrative": {"type": "array", "items": _narrative_step_schema()},
                "mitre_techniques": {"type": "array", "items": _technique_ref_schema()},
                "recommended_actions": {"type": "array", "items": _action_schema()},
            },
            "required": [
                "hypothesis",
                "disposition_lean",
                "narrative",
                "mitre_techniques",
                "recommended_actions",
            ],
            "additionalProperties": False,
        },
    }


def build_submit_rebuttal_tool() -> dict[str, Any]:
    return {
        "name": "submit_rebuttal",
        "description": (
            "Submit your devil's-advocate review: the strongest benign/false-positive "
            "explanation for this incident (required, even if you ultimately find it "
            "unpersuasive — state it and say why it fails), whether you agree with the "
            "investigator's disposition lean, and any additional notes (empty string if none)."
        ),
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "contradicting_evidence": {"type": "string"},
                "agrees_with_disposition": {"type": "boolean"},
                "notes": {"type": "string"},
            },
            "required": ["contradicting_evidence", "agrees_with_disposition", "notes"],
            "additionalProperties": False,
        },
    }


def build_emit_verdict_tool() -> dict[str, Any]:
    """The Reporter's forced terminal tool — docs/07: "Emitted via tool-use so it is
    schema-validated, not parsed from prose." `strict: true` closes every enum (disposition,
    severity opinion, technique id, action id) at the API layer."""
    return {
        "name": "emit_verdict",
        "description": (
            "Emit the final, reconciled triage verdict for this incident. This is the only "
            "acceptable way to answer — do not respond with plain text."
        ),
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "disposition": {"type": "string", "enum": list(_DISPOSITIONS)},
                "confidence": {"type": "number"},
                "llm_severity_opinion": {
                    "anyOf": [{"type": "string", "enum": list(_SEVERITIES)}, {"type": "null"}]
                },
                "mitre_techniques": {"type": "array", "items": _technique_ref_schema()},
                "summary": {"type": "string"},
                "narrative": {"type": "array", "items": _narrative_step_schema()},
                "contradicting_evidence": {"type": "string"},
                "recommended_actions": {"type": "array", "items": _action_schema()},
            },
            "required": [
                "disposition",
                "confidence",
                "llm_severity_opinion",
                "mitre_techniques",
                "summary",
                "narrative",
                "contradicting_evidence",
                "recommended_actions",
            ],
            "additionalProperties": False,
        },
    }
