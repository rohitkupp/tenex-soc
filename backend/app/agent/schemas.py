"""Structured-output schemas for the four-stage evidence-first pipeline --
docs/v2_migration/MIGRATION-01-evidence-first.md changes 5, 6, 7 and
docs/06-PRIVACY-SECURITY.md defense #4/#5 ("Structured output only" / "Output validation").

    Analyst -> Judge -> Deterministic verifier -> Presenter

replaces the old three-role Investigator -> Devil's Advocate -> Reporter flow entirely (change 6).
The devil's-advocate function survives as `Finding.benign_alternatives` (mandatory, non-empty)
and as judge rubric item 6 ("Are benign alternatives considered?").

## Change 5 -- hypothesis evaluation, not free generation

`HypothesisEvaluation` is change 5's required per-candidate output, verbatim in field name and
intent: `technique_id`, `evidence_for`, `evidence_against`, `missing_evidence`, `assessment`,
`threat_confidence`. `NO_KNOWN_MAPPING` (this module's own constant) is mandatory: `AnalystOutput`
rejects any payload whose `hypothesis_evaluations` never evaluates it, so "retrieve five
techniques, the model assumes one must be right" cannot silently happen -- the schema layer
forces the model to have actually considered "none of them" as a candidate answer, not just
permits it.

## Change 6 -- four fields lists, kept structurally separate

Change 6's Analyst field list (`finding_id`, `anomaly_ids`, `observation`, `hypothesis`,
`supporting_evidence_ids`, `contradicting_evidence_ids`, `missing_evidence`,
`attack_technique_id`, `attack_source_id`, `threat_confidence`, `confidence_reason`,
`benign_alternatives`) is `Finding` below, deliberately distinct from `HypothesisEvaluation`:
change 5 describes the Analyst's per-candidate *evaluation* (did the evidence support T1567.002,
yes/no/how), change 6 describes the Analyst's *terminal output* (the finding(s) it is actually
reporting). `AnalystOutput` carries both and cross-validates that every `Finding.
attack_technique_id` traces back to a `HypothesisEvaluation` the Analyst actually ran -- a finding
cannot report a technique the model never evaluated against the evidence.

`Judge` (`JudgeVerdict`/`JudgeOutput`) grades each `Finding` against the ten-item rubric verbatim
below (`JUDGE_RUBRIC`) and returns PASS/REVISE/REJECT. **The judge is a second opinion, not the
safeguard** -- the deterministic verifier (`app.agent.verifier`) is what actually prevents
hallucination; LLM judges have known self-preference and correlated-error problems (change 6's own
wording). Nothing in this module or `orchestrator.py` treats a judge PASS as sufficient on its
own -- verifier pass 2 always runs after, per change 15.

`Presenter`'s output keeps the name `TriageVerdictOut` for continuity with
`app.models.triage_verdict.TriageVerdict` and every existing caller of
`app.agent.orchestrator.triage_incident` -- it is the same "final, persisted verdict" concept the
pre-migration Reporter produced, now assembled by the Presenter from verified `Finding`s instead
of from a single free-form investigation.

## Change 7 -- dual citations

Every citation-bearing field in this module (`Claim.evidence_ids`, `Finding.
supporting_evidence_ids`/`contradicting_evidence_ids`/`anomaly_ids`, `NarrativeStep.evidence_ids`)
is a tuple of plain strings, not a typed union -- the two namespaces (`EVIDENCE-n`/`BASELINE-n`/
`LOG-n` for evidence, `MITRE-Txxx.xxx`/`ZSCALER-KB-*` for knowledge) are enforced and interpreted
by `app.agent.verifier`'s regexes, not by pydantic here. Keeping the wire type a plain string
(rather than a tagged union) is deliberate: `strict: true` tool schemas need one JSON Schema
`type: "string"` for this field regardless of which namespace a given citation happens to use, and
the verifier is the one place namespace-specific meaning (does this exist? does the number in the
claim match this object? was this technique actually retrieved?) belongs.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.agent.mitre import all_technique_ids, technique_exists

__all__ = [
    "ANOMALY_CONFIDENCE_MAX",
    "ANOMALY_CONFIDENCE_MIN",
    "JUDGE_RUBRIC",
    "NO_KNOWN_MAPPING",
    "AgentRole",
    "AnalystOutput",
    "Assessment",
    "Claim",
    "Disposition",
    "DomainAssessment",
    "DomainSemanticOutput",
    "EventTimelineOutput",
    "Finding",
    "HypothesisEvaluation",
    "JudgeDecision",
    "JudgeOutput",
    "JudgeVerdict",
    "MitreTechniqueRef",
    "NarrativeStep",
    "NarratorOutput",
    "RubricItemResult",
    "SchemaValidationError",
    "ThreatConfidence",
    "TimelinePhaseNarrative",
    "ToolTraceEntry",
    "TriageVerdictOut",
    "build_assess_domains_tool",
    "build_narrate_tool",
    "build_present_verdict_tool",
    "build_submit_analysis_tool",
    "build_submit_judgement_tool",
    "build_summarize_windows_tool",
]

Disposition = Literal["true_positive", "false_positive", "benign", "needs_review"]
Severity = Literal["critical", "high", "medium", "low"]
# docs/v2_migration change 3 ("two confidences, never mixed"): the LLM's own hypothesis-evaluation
# judgement of how well the evidence supports *this specific* security interpretation -- never a
# raw float, and never to be confused with `anomaly_confidence` (calibrated, 0-100, upstream-
# computed, see `TriageVerdictOut`'s docstring below).
ThreatConfidence = Literal["low", "moderate", "high"]
# change 5's required per-candidate verdict.
Assessment = Literal["supported", "plausible", "unsupported", "not_observable"]
# change 6 stage 2: "Returns PASS | REVISE | REJECT per finding". "Prefer REJECT over REVISE
# when evidence is insufficient" is enforced in the judge system prompt, not here -- a schema
# cannot know whether evidence was "insufficient".
JudgeDecision = Literal["PASS", "REVISE", "REJECT"]
# Which stage produced a `ToolTraceEntry` -- widened beyond the old three roles. "system" (not
# part of this literal) is still used for the recurrence-inheritance trace entry
# (`orchestrator._persist_inherited`); `ToolTraceEntry.role` is a plain `str` below for exactly
# that reason -- it is a display/debug field, not a security boundary, so a closed enum buys
# nothing and costs a widening every time a new trace producer is added.
AgentRole = Literal["analyst", "judge", "presenter", "narrator"]

_DISPOSITIONS: Final[tuple[str, ...]] = (
    "true_positive",
    "false_positive",
    "benign",
    "needs_review",
)
_SEVERITIES: Final[tuple[str, ...]] = ("critical", "high", "medium", "low")
_THREAT_CONFIDENCE_LEVELS: Final[tuple[str, ...]] = ("low", "moderate", "high")
_ASSESSMENTS: Final[tuple[str, ...]] = ("supported", "plausible", "unsupported", "not_observable")
_JUDGE_DECISIONS: Final[tuple[str, ...]] = ("PASS", "REVISE", "REJECT")

# docs/v2_migration change 3: `anomaly_confidence` is 0-100 (see `app.detection.fusion.
# anomaly_confidence_from_fused_score`), never the 0-1 scale `fused_score` uses.
ANOMALY_CONFIDENCE_MIN: Final[float] = 0.0
ANOMALY_CONFIDENCE_MAX: Final[float] = 100.0

# change 5, verbatim sentinel. Mandatory in every `AnalystOutput.hypothesis_evaluations` set --
# see `AnalystOutput`'s own validator and this module's docstring.
NO_KNOWN_MAPPING: Final[str] = "NO_KNOWN_MAPPING"

# change 6 stage 2's ten-item rubric, copied verbatim -- both the judge system prompt
# (`app.agent.prompts`) and `JudgeVerdict.rubric_assessment`'s completeness check below render
# from this single tuple, so the ten items can never drift between what the model is told to
# grade against and what a submitted verdict is checked to have actually graded.
#
# **Every item is phrased so that `satisfied=True` is the good answer.** Two originally were
# not ("Is required evidence missing?", "Has maliciousness been claimed where only anomaly is
# established?"), where a literal yes meant the finding was *worse*. That was survivable while
# the grades only informed a human-read PASS/REVISE/REJECT, but `app.agent.confidence` now
# computes a number from them, and a model answering either item literally would have pushed
# the score in exactly the wrong direction with nothing to catch it. Uniform polarity is a
# load-bearing invariant of this tuple now, asserted in tests -- do not add an item that reads
# well as a question but inverts it.
JUDGE_RUBRIC: Final[tuple[str, ...]] = (
    "Is every factual claim supported by supplied evidence?",
    "Do all numerical claims appear exactly in the evidence?",
    "Does each cited log line actually support the statement?",
    "Does the cited ATT&CK document support the mapping?",
    "Is observation clearly separated from inference?",
    "Are benign alternatives considered?",
    "Is all the evidence this finding requires actually present?",
    "Does confidence match evidence strength?",
    "Is the technique observable from Zscaler proxy telemetry?",
    "Is maliciousness claimed only where evidence establishes it, never for mere anomaly?",
)


class SchemaValidationError(Exception):
    """A structured-output payload failed post-hoc validation (bad technique id, bad enum value,
    blank required field, an incomplete rubric). docs/06 defense #5: "Failures are rejected, not
    coerced" -- the orchestrator catches this and falls back to `needs_review`, it never tries to
    patch the payload into something valid."""


def _validate_technique_or_no_mapping(v: str) -> str:
    """Shared by every field that can hold either a real, allowlisted MITRE technique id or the
    literal `NO_KNOWN_MAPPING` sentinel (change 5) -- `HypothesisEvaluation.technique_id` and
    `Finding.attack_technique_id`. Whether a given id was *actually retrieved* for this incident
    (as opposed to merely existing somewhere in the thirteen-technique corpus) is a runtime,
    per-triage-run fact this module cannot know statically -- that is `app.agent.verifier`'s
    retrieval-match check, deliberately not duplicated here."""
    if v == NO_KNOWN_MAPPING:
        return v
    if not technique_exists(v):
        raise ValueError(
            f"technique id {v!r} does not exist in the MITRE corpus and is not {NO_KNOWN_MAPPING!r}"
        )
    return v


def _not_blank(v: str) -> str:
    if not v or not v.strip():
        raise ValueError("must not be blank")
    return v


class MitreTechniqueRef(BaseModel):
    """A *real* technique reference only -- never `NO_KNOWN_MAPPING` (see `Finding.
    attack_technique_id` for the field that carries that sentinel). Used on the Presenter's final
    `mitre_techniques` list: when the surviving finding(s) for an incident all evaluate to
    `NO_KNOWN_MAPPING`, this list is simply empty, exactly like the old `_pick_top_technique`
    returning `None` did for the pre-agent pipeline."""

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
    def _fields_not_blank(cls, v: str) -> str:
        return _not_blank(v)


class Claim(BaseModel):
    """One atomic, citable assertion -- the unit `app.agent.verifier` checks for existence,
    numeric match, retrieval match, and scope (change 7). Used inside `HypothesisEvaluation.
    evidence_for`/`evidence_against` (change 5's own contract) and, via `NarrativeStep` below, in
    the Presenter's final narrative."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    text: str
    evidence_ids: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("text")
    @classmethod
    def _text_not_blank(cls, v: str) -> str:
        return _not_blank(v)


class NarrativeStep(BaseModel):
    """One step of the Presenter's final, human-readable narrative. `evidence_ids` replaces the
    pre-migration `evidence_event_ids: tuple[int, ...]` -- change 7's dual-namespace citation
    strings (`EVIDENCE-14`, `BASELINE-3`, `LOG-1291`, `MITRE-T1567.002`, `ZSCALER-KB-threat-cat`)
    supersede the old bare-event-id-only scheme entirely, not just extend it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    step: int = Field(ge=1)
    claim: str
    evidence_ids: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("claim")
    @classmethod
    def _claim_not_blank(cls, v: str) -> str:
        return _not_blank(v)


class HypothesisEvaluation(BaseModel):
    """Change 5's required output, per retrieved candidate technique (plus the mandatory
    `NO_KNOWN_MAPPING` entry -- see `AnalystOutput`'s validator). This is the Analyst's *evaluation*
    of one hypothesis, not its final report -- `Finding` below is what actually gets judged,
    verified, and presented."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    technique_id: str
    evidence_for: tuple[Claim, ...] = Field(default_factory=tuple)
    evidence_against: tuple[Claim, ...] = Field(default_factory=tuple)
    missing_evidence: tuple[str, ...] = Field(default_factory=tuple)
    assessment: Assessment
    threat_confidence: ThreatConfidence

    @field_validator("technique_id")
    @classmethod
    def _technique_id_valid(cls, v: str) -> str:
        return _validate_technique_or_no_mapping(v)


class Finding(BaseModel):
    """Change 6 stage 1's Analyst output fields, verbatim. `benign_alternatives` is required and
    non-empty -- the devil's-advocate function change 6 says "survives as the mandatory
    evidence_against field and in the judge rubric" lives here (the false-positive case the
    Analyst itself must articulate) and in `HypothesisEvaluation.evidence_against` (the
    per-technique counter-evidence)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    anomaly_ids: tuple[str, ...] = Field(default_factory=tuple)
    observation: str
    hypothesis: str
    supporting_evidence_ids: tuple[str, ...] = Field(default_factory=tuple)
    contradicting_evidence_ids: tuple[str, ...] = Field(default_factory=tuple)
    missing_evidence: tuple[str, ...] = Field(default_factory=tuple)
    attack_technique_id: str
    attack_source_id: str | None = None
    threat_confidence: ThreatConfidence
    confidence_reason: str
    benign_alternatives: tuple[str, ...]

    @field_validator("finding_id", "observation", "hypothesis", "confidence_reason")
    @classmethod
    def _text_fields_not_blank(cls, v: str) -> str:
        return _not_blank(v)

    @field_validator("attack_technique_id")
    @classmethod
    def _attack_technique_id_valid(cls, v: str) -> str:
        return _validate_technique_or_no_mapping(v)

    @field_validator("benign_alternatives")
    @classmethod
    def _benign_alternatives_required(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError(
                "benign_alternatives must be non-empty -- the devil's-advocate function is "
                "mandatory on every finding, even when the Analyst ultimately rejects it "
                "(docs/v2_migration change 6)"
            )
        if any(not item or not item.strip() for item in v):
            raise ValueError("benign_alternatives entries must not be blank")
        return v

    @model_validator(mode="after")
    def _attack_source_matches_technique(self) -> Finding:
        if self.attack_technique_id == NO_KNOWN_MAPPING:
            if self.attack_source_id is not None:
                raise ValueError(
                    "attack_source_id must be null when attack_technique_id is NO_KNOWN_MAPPING "
                    "-- there is no knowledge-base document backing a non-mapping"
                )
        elif not self.attack_source_id or not self.attack_source_id.strip():
            raise ValueError(
                "attack_source_id is required (a knowledge citation, e.g. 'MITRE-T1567.002') "
                "whenever attack_technique_id names a real technique"
            )
        return self


class AnalystOutput(BaseModel):
    """The Analyst's terminal `submit_analysis` tool call. Two cross-checks beyond each nested
    model's own validation, both structural anti-hallucination guarantees:

    1. **`NO_KNOWN_MAPPING` is mandatory** (change 5, verbatim): without at least one
       `hypothesis_evaluations` entry evaluating it, a schema-valid payload could still retrieve
       five techniques and silently assume one must be right.
    2. **Every finding's technique traces back to an evaluation.** A `Finding.attack_technique_id`
       that never appears in `hypothesis_evaluations` would let the Analyst report a mapping it
       never actually ran the change-5 evaluation for.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    hypothesis_evaluations: tuple[HypothesisEvaluation, ...]
    findings: tuple[Finding, ...]

    @model_validator(mode="after")
    def _no_known_mapping_is_mandatory(self) -> AnalystOutput:
        if not any(h.technique_id == NO_KNOWN_MAPPING for h in self.hypothesis_evaluations):
            raise ValueError(
                f"hypothesis_evaluations must include an entry evaluating {NO_KNOWN_MAPPING!r} "
                "-- docs/v2_migration change 5: retrieval must never force an attribution"
            )
        return self

    @model_validator(mode="after")
    def _findings_non_empty(self) -> AnalystOutput:
        if not self.findings:
            raise ValueError("findings must be non-empty -- at least one finding per incident")
        return self

    @model_validator(mode="after")
    def _finding_techniques_were_evaluated(self) -> AnalystOutput:
        evaluated = {h.technique_id for h in self.hypothesis_evaluations}
        for f in self.findings:
            if f.attack_technique_id not in evaluated:
                raise ValueError(
                    f"finding {f.finding_id!r} reports attack_technique_id "
                    f"{f.attack_technique_id!r}, which was never evaluated in "
                    "hypothesis_evaluations"
                )
        return self


class RubricItemResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    item: int = Field(ge=1, le=len(JUDGE_RUBRIC))
    satisfied: bool
    note: str

    @field_validator("note")
    @classmethod
    def _note_not_blank(cls, v: str) -> str:
        return _not_blank(v)


class JudgeVerdict(BaseModel):
    """One finding's judgement. `revised_finding` is populated if and only if `decision ==
    "REVISE"` -- change 15's whole reason for existing: a REVISE's replacement finding can
    introduce a number or citation verifier pass 1 never saw, and pass 2 (`app.agent.verifier`)
    checks it *after* this model validates, not instead of."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    decision: JudgeDecision
    rubric_assessment: tuple[RubricItemResult, ...]
    rationale: str
    revised_finding: Finding | None = None

    @field_validator("finding_id", "rationale")
    @classmethod
    def _text_fields_not_blank(cls, v: str) -> str:
        return _not_blank(v)

    @field_validator("rubric_assessment")
    @classmethod
    def _rubric_is_complete(cls, v: tuple[RubricItemResult, ...]) -> tuple[RubricItemResult, ...]:
        items = sorted(r.item for r in v)
        expected = list(range(1, len(JUDGE_RUBRIC) + 1))
        if items != expected:
            raise ValueError(
                f"rubric_assessment must cover every item 1..{len(JUDGE_RUBRIC)} exactly once; "
                f"got {items}"
            )
        return v

    @model_validator(mode="after")
    def _revised_finding_matches_decision(self) -> JudgeVerdict:
        if self.decision == "REVISE":
            if self.revised_finding is None:
                raise ValueError("decision REVISE requires a revised_finding")
            if self.revised_finding.finding_id != self.finding_id:
                raise ValueError(
                    "revised_finding.finding_id must match the finding_id being judged "
                    f"({self.finding_id!r} != {self.revised_finding.finding_id!r})"
                )
        elif self.revised_finding is not None:
            raise ValueError(
                f"revised_finding must be null when decision is {self.decision!r}, not REVISE"
            )
        return self


class JudgeOutput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    verdicts: tuple[JudgeVerdict, ...]

    @field_validator("verdicts")
    @classmethod
    def _verdicts_non_empty(cls, v: tuple[JudgeVerdict, ...]) -> tuple[JudgeVerdict, ...]:
        if not v:
            raise ValueError("verdicts must be non-empty -- one per finding submitted")
        return v


class ToolTraceEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    role: str
    tool_name: str
    tool_input: dict[str, Any]
    is_error: bool = False
    summary: str = ""  # short, human-readable result summary — not the full payload (cost control)


class TriageVerdictOut(BaseModel):
    """The Presenter's terminal `present_verdict` tool call, plus the fields
    `app.models.triage_verdict.TriageVerdict` needs for persistence (`tool_trace`,
    `citation_valid`, `invalid_citations`, `model`, token/cost/latency). Citation-verification
    fields default empty and are filled in by `app.agent.verifier` *after* this model validates.

    Kept as the final, persisted shape (same class name, same DB-facing fields) the pre-migration
    Reporter also produced -- change 6 replaces *how* this gets assembled (from verified `Finding`s
    via Analyst -> Judge -> verifier -> Presenter, not from one free-form investigation), not the
    shape every downstream consumer of a triage verdict already depends on.

    ## Two confidences, never mixed (docs/v2_migration change 3)

    - `threat_confidence` / `threat_confidence_reason` -- the Presenter's own synthesis of the
      surviving findings' hypothesis-evaluation judgements.
    - `anomaly_confidence` -- **not the LLM's opinion at all.** Passed into every stage's prompt
      and required back on this model unchanged; `app.agent.verifier.verify_anomaly_confidence` is
      the deterministic check. Transport only -- never persisted to `triage_verdicts` (no such
      column exists there) and never written back to `incidents.anomaly_confidence`.
    - `evidence_confidence` / `evidence_confidence_basis` -- a third value, and the only one of
      the three that measures *the triage itself* rather than the traffic. No LLM emits it: it
      is `app.agent.confidence` scoring the Judge's own rubric grades, attached by the
      orchestrator after the Presenter returns. It is therefore absent from
      `build_present_verdict_tool`'s schema on purpose -- a field the model cannot write is a
      field the model cannot inflate. `None` when the Judge never ran (a `needs_review`
      fallback), which is deliberately distinct from a graded-and-low score.
    """

    model_config = ConfigDict(extra="forbid")

    disposition: Disposition
    threat_confidence: ThreatConfidence
    threat_confidence_reason: str
    anomaly_confidence: float = Field(ge=ANOMALY_CONFIDENCE_MIN, le=ANOMALY_CONFIDENCE_MAX)
    llm_severity_opinion: Severity | None = None
    mitre_techniques: tuple[MitreTechniqueRef, ...] = Field(default_factory=tuple)
    summary: str
    narrative: tuple[NarrativeStep, ...]
    contradicting_evidence: str
    recommended_actions: tuple[str, ...] = Field(default_factory=tuple)

    # --- computed from the Judge's rubric grades, never emitted by any model ---
    evidence_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence_confidence_band: str | None = None
    evidence_confidence_basis: dict[str, Any] | None = None

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

    @field_validator("summary", "contradicting_evidence", "threat_confidence_reason")
    @classmethod
    def _text_fields_not_blank(cls, v: str) -> str:
        return _not_blank(v)

    @field_validator("recommended_actions")
    @classmethod
    def _actions_not_blank(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item or not item.strip() for item in v):
            raise ValueError("recommended_actions entries must not be blank")
        return v

    @model_validator(mode="after")
    def _narrative_required_unless_needs_review(self) -> TriageVerdictOut:
        # needs_review is a legitimate answer with insufficient evidence: don't force a
        # fabricated narrative step just to satisfy a non-empty-list rule.
        if self.disposition != "needs_review" and not self.narrative:
            raise ValueError(
                "narrative must have at least one step unless disposition is needs_review"
            )
        return self


# ---------------------------------------------------------------------------- Path A (narrator)


class TimelinePhaseNarrative(BaseModel):
    """One selected timeline phase's prose, change 14 Path A: "Timeline entry *selection* stays
    deterministic; the LLM writes prose for selected phases only." `phase_index` ties this back
    to the deterministically-chosen phase the caller supplied -- the Narrator may not introduce a
    phase that was not in its input."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    phase_index: int = Field(ge=0)
    narrative: str
    cited_log_ids: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("narrative")
    @classmethod
    def _narrative_not_blank(cls, v: str) -> str:
        return _not_blank(v)


class NarratorOutput(BaseModel):
    """Path A's single call: deterministic overview stats + incident list + timeline entries in,
    executive summary + per-phase prose out. **No judge stage** (change 14: "A judge pass over
    descriptive narrative is not worth the call") -- the deterministic verifier still runs over
    this output (numbers must match the overview stats, `cited_log_ids` must exist/scope-check),
    same as Path B's verifier, just without an intervening judge call."""

    model_config = ConfigDict(extra="forbid")

    executive_summary: str
    phase_narratives: tuple[TimelinePhaseNarrative, ...] = Field(default_factory=tuple)

    @field_validator("executive_summary")
    @classmethod
    def _summary_not_blank(cls, v: str) -> str:
        return _not_blank(v)


# ---------------------------------------------------------------------------- change 8 (domain semantics)


class DomainAssessment(BaseModel):
    """One candidate domain's semantic assessment -- docs/v2_migration change 8:
    `app.agent.orchestrator.assess_domain_semantics`'s single terminal-tool output, one entry per
    destination the deterministic rarity/baseline layer already flagged rare or first-seen
    (`app.api.analyses._compute_domain_semantic_candidates`).

    Deliberately carries no notion of `app.schemas.overview.DomainSemanticFinding.label` at all.
    That field is a UI/wire concept owned by `app.schemas.overview`, pinned to a `Literal` of
    exactly `SEMANTIC_INSIGHT_LABEL` there -- this module never imports that schema (`app.agent`
    has no dependency on `app.schemas` anywhere in this package), so there is no field here for a
    caller to even copy the wrong label out of. The label-safety guarantee change 8 asks for
    ("make it impossible for this pass to emit the ML label") therefore holds structurally, at
    two independent layers: this model never represents a label at all, and `app.schemas.
    overview.DomainSemanticFinding.label`'s `Literal` makes constructing it with any other string
    a `pydantic.ValidationError`, not a runtime possibility.

    `flagged` is the model's own yes/no on whether this domain earned a citable finding at all --
    `assessment`/`rationale` are only required to be non-blank when `flagged` is true, so an
    unflagged, ordinary rare domain never needs a strained justification, just a brief note on
    why none of the three questions (brand impersonation, typosquatting, contextual relevance)
    applied to it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    domain: str
    flagged: bool
    assessment: str
    rationale: str
    evidence_ids: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("domain")
    @classmethod
    def _domain_not_blank(cls, v: str) -> str:
        return _not_blank(v)

    @model_validator(mode="after")
    def _flagged_requires_text(self) -> DomainAssessment:
        if self.flagged and (not self.assessment.strip() or not self.rationale.strip()):
            raise ValueError(
                "a flagged domain assessment must include non-blank assessment and rationale "
                "text -- flagged=true is a citable finding, not a placeholder"
            )
        return self


class DomainSemanticOutput(BaseModel):
    """change 8's single terminal tool call: one `DomainAssessment` per candidate domain the
    caller supplied -- the model may not add, skip, or merge candidates. Mirrors `NarratorOutput.
    phase_narratives`'s own "may not introduce a phase that was not in its input" contract; the
    existence check itself (was every assessed domain actually one of the candidates supplied,
    was every candidate actually assessed) is `app.agent.verifier.verify_domain_semantic_output`'s
    job, in code, since a schema alone cannot know what candidates a given call was sent."""

    model_config = ConfigDict(extra="forbid")

    assessments: tuple[DomainAssessment, ...]

    @model_validator(mode="after")
    def _assessments_non_empty(self) -> DomainSemanticOutput:
        if not self.assessments:
            raise ValueError("assessments must be non-empty -- one entry per candidate domain")
        return self


# ---------------------------------------------------------------------------- dynamic tool schemas


def _claim_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "text": {"type": "string"},
            "evidence_ids": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["text", "evidence_ids"],
        "additionalProperties": False,
    }


def _narrative_step_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "step": {"type": "integer"},
            "claim": {"type": "string"},
            "evidence_ids": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["step", "claim", "evidence_ids"],
        "additionalProperties": False,
    }


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


def _technique_or_no_mapping_enum() -> list[str]:
    return [*all_technique_ids(), NO_KNOWN_MAPPING]


def _hypothesis_evaluation_schema(*, technique_id_const: str | None = None) -> dict[str, Any]:
    """`technique_id_const` pins `technique_id` to a single value, used for the mandatory
    null-hypothesis field so the model cannot label it as some other technique."""
    return {
        "type": "object",
        "properties": {
            "technique_id": (
                {"type": "string", "enum": [technique_id_const]}
                if technique_id_const is not None
                else {"type": "string", "enum": _technique_or_no_mapping_enum()}
            ),
            "evidence_for": {"type": "array", "items": _claim_schema()},
            "evidence_against": {"type": "array", "items": _claim_schema()},
            "missing_evidence": {"type": "array", "items": {"type": "string"}},
            "assessment": {"type": "string", "enum": list(_ASSESSMENTS)},
            "threat_confidence": {"type": "string", "enum": list(_THREAT_CONFIDENCE_LEVELS)},
        },
        "required": [
            "technique_id",
            "evidence_for",
            "evidence_against",
            "missing_evidence",
            "assessment",
            "threat_confidence",
        ],
        "additionalProperties": False,
    }


def _finding_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "finding_id": {"type": "string"},
            "anomaly_ids": {"type": "array", "items": {"type": "string"}},
            "observation": {"type": "string"},
            "hypothesis": {"type": "string"},
            "supporting_evidence_ids": {"type": "array", "items": {"type": "string"}},
            "contradicting_evidence_ids": {"type": "array", "items": {"type": "string"}},
            "missing_evidence": {"type": "array", "items": {"type": "string"}},
            "attack_technique_id": {"type": "string", "enum": _technique_or_no_mapping_enum()},
            "attack_source_id": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "threat_confidence": {"type": "string", "enum": list(_THREAT_CONFIDENCE_LEVELS)},
            "confidence_reason": {"type": "string"},
            "benign_alternatives": {"type": "array", "items": {"type": "string"}},
        },
        "required": [
            "finding_id",
            "anomaly_ids",
            "observation",
            "hypothesis",
            "supporting_evidence_ids",
            "contradicting_evidence_ids",
            "missing_evidence",
            "attack_technique_id",
            "attack_source_id",
            "threat_confidence",
            "confidence_reason",
            "benign_alternatives",
        ],
        "additionalProperties": False,
    }


def build_submit_analysis_tool() -> dict[str, Any]:
    """The Analyst's terminal tool (change 6 stage 1). `strict: true` closes every enum,
    including `technique_id`/`attack_technique_id`'s corpus-plus-NO_KNOWN_MAPPING enum, at the
    API layer -- the same anti-hallucination defense-in-depth `app.agent.schemas`'s pre-migration
    docstring described for the old `mitre_techniques[].id` field, now covering two fields
    instead of one."""
    return {
        "name": "submit_analysis",
        "description": (
            "Submit your evidence-first analysis: an evaluation of every retrieved candidate "
            "technique against the supplied evidence (hypothesis_evaluations -- always include "
            "an entry for NO_KNOWN_MAPPING; do not select a technique solely because it is the "
            "closest retrieved result), and the finding(s) you are actually reporting for this "
            "incident (findings -- at least one; every finding's attack_technique_id must be one "
            "you evaluated above). Call this once, when your investigation is complete."
        ),
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "hypothesis_evaluations": {
                    "type": "array",
                    "items": _hypothesis_evaluation_schema(),
                },
                # The null hypothesis is its own required field, not an entry the model has to
                # remember to append to the list above. As a list member it was omitted on
                # essentially every real call — every incident in a 15-incident run came back
                # "Triage did not complete: hypothesis_evaluations must include an entry
                # evaluating 'NO_KNOWN_MAPPING'", so no incident got a usable verdict at all.
                # `strict: true` makes a named required property structurally impossible to skip,
                # which a "one of these array items must have a particular id" rule can never be.
                # `_merged_hypothesis_evaluations` folds it back into one list, so `AnalystOutput`
                # and every consumer downstream are unchanged.
                "no_known_mapping_evaluation": _hypothesis_evaluation_schema(
                    technique_id_const=NO_KNOWN_MAPPING
                ),
                "findings": {"type": "array", "items": _finding_schema()},
            },
            "required": [
                "hypothesis_evaluations",
                "no_known_mapping_evaluation",
                "findings",
            ],
            "additionalProperties": False,
        },
    }


def _rubric_item_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "item": {"type": "integer", "enum": list(range(1, len(JUDGE_RUBRIC) + 1))},
            "satisfied": {"type": "boolean"},
            "note": {"type": "string"},
        },
        "required": ["item", "satisfied", "note"],
        "additionalProperties": False,
    }


def _judge_verdict_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "finding_id": {"type": "string"},
            "decision": {"type": "string", "enum": list(_JUDGE_DECISIONS)},
            "rubric_assessment": {"type": "array", "items": _rubric_item_schema()},
            "rationale": {"type": "string"},
            "revised_finding": {"anyOf": [_finding_schema(), {"type": "null"}]},
        },
        "required": ["finding_id", "decision", "rubric_assessment", "rationale", "revised_finding"],
        "additionalProperties": False,
    }


def build_submit_judgement_tool() -> dict[str, Any]:
    """The Judge's terminal tool (change 6 stage 2). One `JudgeVerdict` per finding it was
    handed. `revised_finding` is `required` (strict mode's rule) but semantically optional --
    the model satisfies it with `null` for PASS/REJECT and only populates it for REVISE
    (`JudgeVerdict`'s own validator enforces the pairing independently)."""
    return {
        "name": "submit_judgement",
        "description": (
            "Submit your judgement of each finding you were given, one verdict per finding, "
            "against the ten-item evidentiary rubric. Prefer REJECT over REVISE when the "
            "evidence is insufficient -- a REVISE should fix a specific, fixable defect (a "
            "citation, a confidence level, an overclaim), not paper over missing evidence."
        ),
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {"verdicts": {"type": "array", "items": _judge_verdict_schema()}},
            "required": ["verdicts"],
            "additionalProperties": False,
        },
    }


def build_present_verdict_tool() -> dict[str, Any]:
    """The Presenter's forced terminal tool (change 6 stage 4). `anomaly_confidence` is
    `required` like every other field here (strict mode's rule), but it is not something the
    model computes -- the incident context hands it the exact number and the Presenter system
    prompt instructs it to echo that value back unchanged; `app.agent.verifier.
    verify_anomaly_confidence` is the actual enforcement."""
    return {
        "name": "present_verdict",
        "description": (
            "Present the final, human-readable triage verdict for this incident, built only "
            "from the verified finding(s) you were given. Do not introduce a fact, a number, or "
            "a technique that did not survive verification -- this is presentation, not further "
            "investigation."
        ),
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "disposition": {"type": "string", "enum": list(_DISPOSITIONS)},
                "threat_confidence": {"type": "string", "enum": list(_THREAT_CONFIDENCE_LEVELS)},
                "threat_confidence_reason": {"type": "string"},
                "anomaly_confidence": {"type": "number"},
                "llm_severity_opinion": {
                    "anyOf": [{"type": "string", "enum": list(_SEVERITIES)}, {"type": "null"}]
                },
                "mitre_techniques": {"type": "array", "items": _technique_ref_schema()},
                "summary": {"type": "string"},
                "narrative": {"type": "array", "items": _narrative_step_schema()},
                "contradicting_evidence": {"type": "string"},
                "recommended_actions": {"type": "array", "items": {"type": "string"}},
            },
            "required": [
                "disposition",
                "threat_confidence",
                "threat_confidence_reason",
                "anomaly_confidence",
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


# ---------------------------------------------------------------------------- Path A tool schema


def _timeline_phase_narrative_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "phase_index": {"type": "integer"},
            "narrative": {"type": "string"},
            "cited_log_ids": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["phase_index", "narrative", "cited_log_ids"],
        "additionalProperties": False,
    }


def build_narrate_tool() -> dict[str, Any]:
    """The Narrator's terminal tool (change 14, Path A). One call per analysis, no judge, no
    investigation tools -- deterministic overview stats + incident list + timeline entries are
    already in the prompt in full (change 9: "do not ask a model to count 83,241 rows")."""
    return {
        "name": "narrate_analysis",
        "description": (
            "Write the executive summary for this analysis and prose for each of the selected "
            "timeline phases you were given. You may not select, reorder, or invent a timeline "
            "phase -- write prose only for the phase_index values you were shown, citing only "
            "the log lines / evidence ids attached to that phase."
        ),
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "executive_summary": {"type": "string"},
                "phase_narratives": {
                    "type": "array",
                    "items": _timeline_phase_narrative_schema(),
                },
            },
            "required": ["executive_summary", "phase_narratives"],
            "additionalProperties": False,
        },
    }


# ---------------------------------------------------------------------------- change 8 tool schema


def _domain_assessment_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "domain": {"type": "string"},
            "flagged": {"type": "boolean"},
            "assessment": {"type": "string"},
            "rationale": {"type": "string"},
            "evidence_ids": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["domain", "flagged", "assessment", "rationale", "evidence_ids"],
        "additionalProperties": False,
    }


def build_assess_domains_tool() -> dict[str, Any]:
    """change 8's terminal tool. One `DomainAssessment` per candidate domain supplied, forced via
    `tool_choice` exactly like `build_narrate_tool` -- no investigation tools, no judge, a single
    reduced-data-in / structured-judgement-out call (`app.agent.orchestrator.assess_domain_
    semantics`)."""
    return {
        "name": "assess_domains",
        "description": (
            "Submit your semantic assessment of every candidate domain you were given -- one "
            "entry per domain, in any order, with flagged=true only for a domain where brand "
            "impersonation, typosquatting intent, or contextual relevance gives a real, specific "
            "answer. Do not add, skip, or merge candidates. Call this once."
        ),
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {"assessments": {"type": "array", "items": _domain_assessment_schema()}},
            "required": ["assessments"],
            "additionalProperties": False,
        },
    }


# ------------------------------------------------------- event-window timeline tool schema


class WindowSummary(BaseModel):
    """One time window's plain-language summary. `window_index` must be one the model was
    given — it may not invent, merge, or reorder windows, the same discipline
    `NarratorOutput` applies to timeline phases."""

    window_index: int
    summary: str
    cited_log_ids: list[str] = Field(default_factory=list)


class EventTimelineOutput(BaseModel):
    overview: str
    windows: list[WindowSummary]


def build_summarize_windows_tool() -> dict[str, Any]:
    """The event-timeline summariser's terminal tool. Windowing is deterministic and happens
    upstream (`app.api.events._window_events`) — the model is handed already-bucketed counts and
    writes prose per bucket. It never sees raw log volume (CLAUDE.md rule 1): it sees per-window
    aggregates, not the events themselves."""
    return {
        "name": "summarize_windows",
        "description": (
            "Write one short, factual sentence per time window describing what the traffic in "
            "that window looks like, plus a two-to-three sentence overview of the whole period. "
            "You may only write about the window_index values you were shown, and may only cite "
            "log ids attached to that window. Use the counts you were given verbatim -- never "
            "estimate, round, or compute a figure that was not supplied."
        ),
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "overview": {"type": "string"},
                "windows": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "window_index": {"type": "integer"},
                            "summary": {"type": "string"},
                            "cited_log_ids": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["window_index", "summary", "cited_log_ids"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["overview", "windows"],
            "additionalProperties": False,
        },
    }
