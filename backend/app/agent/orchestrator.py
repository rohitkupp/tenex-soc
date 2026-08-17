"""Four-stage evidence-first pipeline -- docs/v2_migration/MIGRATION-01-evidence-first.md changes
5, 6, 7, 14, 15. Replaces the pre-migration three-role Investigator -> Devil's Advocate -> Reporter
flow entirely.

## Path B -- per-incident investigation (change 6, refined by change 15)

```
evidence package + retrieved KB
    -> Analyst LLM -> verifier pass 1 (cheap) -> Judge LLM -> verifier pass 2 (full) -> Presenter LLM
```

Three LLM calls per incident (Analyst, Judge, Presenter) -- **not four.** Change 6 is explicit that
the deterministic verifier is "code, not a model," so it is never counted as a call here even
though it runs twice. Change 14's own cost line ("1 narrator call + (4 x triaged incidents)")
implies four LLM calls per incident, which does not reconcile with change 6's three-LLM-stage
description of the *same* pipeline -- flagged as a doc inconsistency in this build's report rather
than silently invented around; this implementation follows change 6's unambiguous "verifier is
code" statement and makes three real API calls per incident.

**The devil's-advocate function did not get its own role.** Change 6 says it "survives as the
mandatory `evidence_against` field and in the judge rubric" -- there is no longer a second,
independent model call arguing the counter-case; `Finding.benign_alternatives` (required,
non-empty) and `HypothesisEvaluation.evidence_against` are what the single Analyst call is
required to produce, and judge rubric item 6 ("Are benign alternatives considered?") is what
checks it was done seriously, not rubber-stamped.

## Path A -- analysis-level narrative (change 14, once per upload)

```
deterministic overview stats + incident list + timeline entries -> Narrator LLM (one call)
    -> deterministic verifier -> executive summary + timeline phase narratives
```

No judge stage (change 14: "a judge pass over descriptive narrative is not worth the call"). The
verifier still runs -- `narrate_analysis` below, `app.agent.verifier.verify_narrator_output`.

## Cost control

`effort` is set per stage, not uniformly: `medium` for the Analyst (the role doing the real
reasoning and tool orchestration) and the Judge (careful evidentiary grading against a ten-item
rubric is not a narrow, mechanical task -- the pre-migration Devil's Advocate's `low` effort choice
does not transfer to a role now solely responsible for catching overclaims), `low` for the
Presenter (it is handed already-verified structured findings and asked to reformat them into
prose -- the narrowest, most mechanical stage in the pipeline) and the Narrator (Path A's single
call, over data that is already fully reduced). `AGENT_MAX_TOOL_CALLS`
(`app.core.config.Settings.agent_max_tool_calls`, default 8) belongs to the Analyst alone now --
it is the only stage with tools; the Judge and Presenter make exactly one forced tool-use call
each and never touch the shared budget.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Final

from pydantic import ValidationError
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.agent import prompts
from app.agent.client import LiveCaller, LLMCaller, estimate_cost_usd
from app.agent.context import (
    AgentContext,
    AgentContextError,
    build_agent_context,
    compute_evidence_payloads,
    log_citation_id,
)
from app.agent.retrieval import RetrievalCandidate, retrieve_candidates
from app.agent.schemas import (
    AnalystOutput,
    DomainSemanticOutput,
    EventTimelineOutput,
    Finding,
    JudgeOutput,
    NarratorOutput,
    SchemaValidationError,
    ToolTraceEntry,
    TriageVerdictOut,
    build_assess_domains_tool,
    build_narrate_tool,
    build_present_verdict_tool,
    build_submit_analysis_tool,
    build_submit_judgement_tool,
    build_summarize_windows_tool,
)
from app.agent.tools import TOOL_DEFINITIONS, ToolError, dispatch_tool
from app.agent.verifier import (
    AnomalyConfidenceIntegrityError,
    Pass1Result,
    Pass2Result,
    verify_anomaly_confidence,
    verify_citations,
    verify_domain_semantic_output,
    verify_event_timeline_output,
    verify_narrator_output,
    verify_pass1,
    verify_pass2,
)
from app.core.config import get_settings
from app.core.logging import get_logger
from app.detection.evidence.payload import EvidencePayload
from app.graph.timeline import build_timeline
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.triage_verdict import TriageVerdict

__all__ = [
    "MAX_SEMANTIC_DOMAINS_PER_CALL",
    "AgentRefusalError",
    "AgentTimeoutError",
    "DomainFinding",
    "DomainSemanticResult",
    "InsufficientEvidenceError",
    "MissingAPIKeyError",
    "NarrationResult",
    "assess_domain_semantics",
    "narrate_analysis",
    "summarize_event_windows",
    "triage_incident",
    "triage_top_incidents_for_analysis",
]

log = get_logger(__name__)

MAX_TOKENS_PER_TURN = 32768

# Per-role output ceilings. One shared 8192 was wrong for the narrator and only the narrator:
# Analyst/Judge/Presenter each run once per *incident* and emit a bounded verdict, so their output
# size does not grow with the upload. Path A's narrator runs once per *analysis* and writes prose
# over every incident and timeline phase in it, so its output scales with how busy the upload was.
# A 4,360-event upload correlating into 33 incidents ran past 8192 before it emitted its tool call
# and took the whole analysis down at the final stage, having already paid for every incident
# triaged before it. Raising the ceiling alone would only move the cliff, so the real bound is on
# the *input* (`prompts.MAX_NARRATOR_INCIDENTS`); this headroom is what keeps a legitimately large
# summary from clipping under that cap.
MAX_TOKENS_PER_TURN_BY_ROLE: Final[dict[str, int]] = {"narrator": 32768}
MAX_ROLE_TURNS = 12  # safety cap independent of the tool-call budget — see _run_tool_role
MAX_SIGNALS_IN_CONTEXT = 60  # highest-confidence first — see _build_incident_context_block
MAX_EVIDENCE_IDS_IN_CONTEXT = 40  # per signal/timeline-phase/evidence-payload, same reasoning
MAX_EVIDENCE_PAYLOADS_IN_CONTEXT = 80  # CLAUDE.md rule 1 — cap before the prompt, not after
MAX_RETRIEVED_CANDIDATES = 20  # change 4: "a small, evidence-relevant candidate set"


def _max_tokens_for(role: str) -> int:
    """Output ceiling for `role` — see `MAX_TOKENS_PER_TURN_BY_ROLE`."""
    return MAX_TOKENS_PER_TURN_BY_ROLE.get(role, MAX_TOKENS_PER_TURN)


# docs/07 "Bounds": "Input tokens | 60k per incident | Truncate oldest tool results." Checked
# after every turn against that turn's own `usage.input_tokens`.
MAX_INPUT_TOKENS = 180_000
_TRUNCATED_TOOL_RESULT_PLACEHOLDER = (
    "[earlier tool result omitted to stay within the 60k input-token budget — call the tool "
    "again if you need this data]"
)

ANALYST_TOOLS: list[dict[str, Any]] = TOOL_DEFINITIONS

ANALYST_EFFORT = "medium"
JUDGE_EFFORT = "medium"
PRESENTER_EFFORT = "low"
NARRATOR_EFFORT = "low"
# change 8: no investigation tools, no judge, over already-reduced candidate data -- the same
# "narrowest, most mechanical stage" bucket PRESENTER_EFFORT/NARRATOR_EFFORT occupy, not the
# ANALYST_EFFORT/JUDGE_EFFORT bucket reserved for tool-orchestration and ten-item evidentiary
# grading.
DOMAIN_SEMANTIC_EFFORT = "low"
# change 8 + CLAUDE.md rule 1 ("do not pass more than a few hundred events into a prompt") applied
# to domains: capped well before that, and capped by `app.api.analyses._compute_domain_semantic_
# candidates` *before* it does any of its own per-candidate row lookups, not just here -- this is
# the single source of truth both sides import from so the two caps can never drift apart.
MAX_SEMANTIC_DOMAINS_PER_CALL = 20


class AgentTimeoutError(Exception):
    """AGENT_TIMEOUT_SECONDS exceeded mid-run (docs/07 bound). Caught by `triage_incident`,
    which emits `needs_review` with whatever partial trace exists."""

    def __init__(self, role: str) -> None:
        super().__init__(f"agent timeout during {role}")
        self.role = role


class AgentRefusalError(Exception):
    """Claude Opus 5's safety classifiers declined a turn (`stop_reason == "refusal"`). Treated
    the same as a timeout: emit `needs_review`, never crash the triage run."""

    def __init__(self, role: str, category: str | None) -> None:
        super().__init__(f"model refused during {role} (category={category})")
        self.role = role
        self.category = category


class InsufficientEvidenceError(Exception):
    """Every finding either failed to survive judging (REJECT) or failed pass 2's full
    verification check -- there is nothing left that both a judge and code agree is trustworthy
    enough to present. Distinct from `SchemaValidationError`: the Analyst/Judge outputs were all
    individually well-formed, there is simply no verified finding left to hand the Presenter.
    Caught by `triage_incident` exactly like the other flow-failure exceptions, falling back to
    `needs_review` with `Pass2Result.invalid_citations` carried through so the reason is
    inspectable, not a bare string."""

    def __init__(self, reason: str, *, invalid_citations: tuple[dict[str, Any], ...] = ()) -> None:
        super().__init__(reason)
        self.invalid_citations = invalid_citations


class MissingAPIKeyError(RuntimeError):
    """Raised by `triage_incident` when it needs to make a live call (no `caller` was injected)
    and `Settings.anthropic_api_key` is unset. docs/v2_migration change 12 removed the old
    DEMO_MODE / no-key fallback entirely -- every upload now makes real calls, so a missing key is
    a configuration error, not a mode to degrade into."""

    def __init__(self) -> None:
        super().__init__(
            "ANTHROPIC_API_KEY is not configured. Agent triage now always makes a real "
            "call (DEMO_MODE and the no-key fallback were removed) — set ANTHROPIC_API_KEY "
            "before triaging an incident, or inject a caller explicitly (tests)."
        )


@dataclass(slots=True)
class _ToolBudget:
    remaining: int

    def consume(self) -> bool:
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0


@dataclass(slots=True)
class _UsageAccumulator:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    def add(self, usage: Any) -> None:
        self.input_tokens += usage.input_tokens
        self.output_tokens += usage.output_tokens
        self.cache_creation_input_tokens += getattr(usage, "cache_creation_input_tokens", 0) or 0
        self.cache_read_input_tokens += getattr(usage, "cache_read_input_tokens", 0) or 0


# ---------------------------------------------------------------------------- incident context


def _evidence_payload_for_prompt(p: EvidencePayload) -> dict[str, Any]:
    """One `EvidencePayload`, rendered for the prompt with its citable `LOG-n` line ids instead
    of bare integers (change 7) -- `evidence_id` itself (`EVIDENCE-n`) is already the citation the
    model uses to reference this whole object."""
    return {
        "evidence_id": p.evidence_id,
        "extractor": p.extractor,
        "entity": p.entity,
        "window_start": p.window[0].isoformat(),
        "window_end": p.window[1].isoformat(),
        "measurements": p.measurements,
        "historical": p.historical,
        "log_ids": [
            log_citation_id(n) for n in p.contributing_line_numbers[:MAX_EVIDENCE_IDS_IN_CONTEXT]
        ],
        "nominates_candidate": p.nominates_candidate,
        "nomination_score": p.nomination_score,
    }


def _retrieved_candidate_for_prompt(rc: RetrievalCandidate) -> dict[str, Any]:
    """One retrieved technique, with every change-4 detection-knowledge field the Analyst and
    Judge both need -- `observable_with_zscaler_proxy`/`evidence_that_weakens` are "load-bearing:
    the judge uses them to reject claims requiring telemetry we don't have" (change 4's own
    words), so they travel with the candidate rather than being looked up separately."""
    t = rc.technique
    return {
        "citation": f"MITRE-{t.id}",
        "id": t.id,
        "name": t.name,
        "tactics": list(t.tactics),
        "description": t.description,
        "observable_with_zscaler_proxy": t.observable_with_zscaler_proxy,
        "required_fields": list(t.required_fields),
        "useful_additional_evidence": list(t.useful_additional_evidence),
        "zscaler_observables": list(t.zscaler_observables),
        "supporting_detectors": list(t.supporting_detectors),
        "evidence_required": list(t.evidence_required),
        "evidence_that_weakens": list(t.evidence_that_weakens),
        "attack_detection_guidance": t.attack_detection_guidance,
        "score": t.score,
        "evidence_sources": list(rc.evidence_sources),
    }


def _build_incident_context_block(ctx: AgentContext) -> str:
    """Every stage's (Analyst directly; Judge/Presenter folded back in for their own first turns)
    view of the incident, computed upstream -- docs/05 correlation, docs/04 detection, change 2's
    evidence extractors, change 4/5's evidence-driven retrieval. Deterministic ordering
    (`app.graph.timeline.build_timeline`) means no stage ever has to order raw events itself.

    Has the side effect of running the automatic evidence-driven retrieval step
    (`app.agent.retrieval.retrieve_candidates`) and recording every technique it surfaces into
    `ctx.retrieved_technique_ids` -- this is the one call site upstream of the Analyst's first
    turn, so it must run before anything downstream can legitimately cite a retrieved technique.
    """
    with tenant_scope(ctx.session, ctx.tenant_id):
        incident = ctx.session.get(Incident, ctx.incident_id)
        if incident is None:  # pragma: no cover - build_agent_context already proved this exists
            raise AgentContextError(f"incident {ctx.incident_id} vanished mid-run")
        all_signals = (
            ctx.session.execute(select(Signal).where(Signal.id.in_(incident.signal_ids)))
            .scalars()
            .all()
            if incident.signal_ids
            else []
        )
        title, severity, fused_score = incident.title, incident.severity, incident.fused_score

    total_signal_count = len(all_signals)
    # Calibrated signals rank ahead of uncalibrated ones, confidence only breaking ties within
    # each group (docs/04 §Fusion "Calibration provenance") -- an uncalibrated `clamp01(raw_
    # score)` fallback can be numerically identical to a genuinely calibrated model's most
    # confident output (`signal.stl_residual`'s unbounded robust-z saturates at exactly 1.0), so
    # sorting on `confidence` alone here would let a fallback-inflated signal silently push a
    # real one out of the top `MAX_SIGNALS_IN_CONTEXT` slots the Analyst actually sees. This does
    # not touch `Incident.anomaly_confidence` (CLAUDE.md rule 5: the LLM never sets priority) --
    # only which of an incident's own signals are worth spending a context slot on.
    signals = sorted(all_signals, key=lambda s: (s.calibrated, s.confidence), reverse=True)[
        :MAX_SIGNALS_IN_CONTEXT
    ]
    timeline_phases = build_timeline(list(signals))

    all_event_ids: set[int] = set()
    for s in signals:
        all_event_ids.update(s.evidence_event_ids)
    for phase in timeline_phases:
        all_event_ids.update(phase.event_ids)
    log_ids_by_event_id = ctx.log_ids_for_event_ids(all_event_ids)

    signals_payload = [
        {
            "id": s.id,
            "detector_key": s.detector_key,
            "detector_layer": s.detector_layer,
            "confidence": s.confidence,
            "calibrated": s.calibrated,
            "entity_type": s.entity_type,
            "entity_value": ctx.pseudonymize_value(s.entity_value, s.entity_type),
            "mitre_technique": s.mitre_technique,
            "log_ids": [
                log_ids_by_event_id[eid]
                for eid in list(s.evidence_event_ids)[:MAX_EVIDENCE_IDS_IN_CONTEXT]
                if eid in log_ids_by_event_id
            ],
            "explanation": s.explanation,
        }
        for s in signals
    ]
    timeline_payload = [
        {
            "phase_index": i,
            "ts": p.ts.isoformat() if p.ts else None,
            "tactic": p.tactic,
            "log_ids": [
                log_ids_by_event_id[eid]
                for eid in p.event_ids[:MAX_EVIDENCE_IDS_IN_CONTEXT]
                if eid in log_ids_by_event_id
            ],
            "summary": p.summary,
        }
        for i, p in enumerate(timeline_phases)
    ]
    entity_scope_payload = [
        {"entity_type": t, "entity_value": ctx.pseudonymize_value(v, t)}
        for t, v in sorted(ctx.entity_scope)
    ]
    evidence_payloads_payload = [
        _evidence_payload_for_prompt(p)
        for p in list(ctx.evidence_payloads)[:MAX_EVIDENCE_PAYLOADS_IN_CONTEXT]
    ]

    candidates = retrieve_candidates(
        evidence=list(ctx.evidence_payloads), top_k=MAX_RETRIEVED_CANDIDATES
    )
    ctx.record_retrieved_techniques([c.technique.id for c in candidates])
    retrieved_payload = [_retrieved_candidate_for_prompt(c) for c in candidates]

    return prompts.build_incident_context(
        incident_title=title,
        severity=severity,
        fused_score=fused_score,
        anomaly_confidence=ctx.anomaly_confidence,
        signals=signals_payload,
        timeline=timeline_payload,
        entity_scope=entity_scope_payload,
        total_signal_count=total_signal_count,
        evidence_payloads=evidence_payloads_payload,
        retrieved_candidates=retrieved_payload,
    )


def _render_finding_flags(finding_flags: dict[str, tuple[str, ...]]) -> str:
    payload = {
        "automated_precheck_flags": {fid: list(notes) for fid, notes in finding_flags.items()}
    }
    return prompts.wrap_untrusted(payload)


def _wrap_presenter_findings(findings: list[Finding]) -> str:
    return prompts.wrap_untrusted(
        {"verified_findings": [f.model_dump(mode="json") for f in findings]}
    )


# ---------------------------------------------------------------------------- tool-calling loop (Analyst)


def _summarize_tool_result(name: str, result: Any) -> str:
    """A short, human-readable line for `tool_trace` — the trace records *that* a tool was
    called and roughly what came back, never the full payload (CLAUDE.md rule 1)."""
    if isinstance(result, list):
        return f"{len(result)} result(s)"
    if isinstance(result, dict) and name == "get_entity_baseline":
        return (
            f"value={result.get('value')} baseline_mean={result.get('baseline_mean')} "
            f"z_score={result.get('z_score')} n_baseline_windows={result.get('n_baseline_windows')} "
            f"baseline_id={result.get('baseline_id')}"
        )
    return "ok"


def _truncate_oldest_tool_result(messages: list[dict[str, Any]]) -> bool:
    """Finds the oldest not-yet-truncated `tool_result` content block anywhere in `messages`
    and collapses it to a short placeholder, in place. Returns `False` once every tool result is
    already collapsed."""
    for message in messages:
        if message.get("role") != "user":
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if (
                isinstance(block, dict)
                and block.get("type") == "tool_result"
                and block.get("content") != _TRUNCATED_TOOL_RESULT_PLACEHOLDER
            ):
                block["content"] = _TRUNCATED_TOOL_RESULT_PLACEHOLDER
                return True
    return False


def _enforce_input_token_budget(
    messages: list[dict[str, Any]], last_input_tokens: int, *, role: str
) -> None:
    """Called after every turn with that turn's own `usage.input_tokens`. Collapses exactly one
    oldest tool result per over-budget turn (see the pre-migration orchestrator's own reasoning,
    unchanged here)."""
    if last_input_tokens <= MAX_INPUT_TOKENS:
        return
    if _truncate_oldest_tool_result(messages):
        log.info(
            "agent.input_token_budget_truncated", role=role, last_input_tokens=last_input_tokens
        )


def _run_tool_role(
    *,
    caller: LLMCaller,
    ctx: AgentContext,
    role: str,
    system_prompt: str,
    first_user_content: str,
    investigation_tools: list[dict[str, Any]],
    terminal_tool: dict[str, Any],
    budget: _ToolBudget,
    deadline: float,
    trace: list[ToolTraceEntry],
    usage: _UsageAccumulator,
    model: str,
    effort: str,
) -> dict[str, Any]:
    """Drives one role's turn loop until it calls its terminal tool, or raises `AgentTimeoutError` /
    `AgentRefusalError` / `SchemaValidationError`. Returns the terminal tool call's raw `input` dict.
    Used only by the Analyst -- the Judge and Presenter have no investigation tools and go through
    `_run_notool_role` instead.

    ## Prompt caching: why `first_user_content` gets a `cache_control` marker here, and only here

    `first_user_content` is `_build_incident_context_block`'s output (plus the prior-decisions
    block, when present) -- the tens-of-thousands-of-token block CLAUDE.md's "the LLM never sees
    raw log volume" rule already forced to be reduced, computed once per incident in `_run_flow`
    and unchanged for the rest of this loop. Every turn after the first re-sends `messages[0]`
    verbatim as part of the growing history (tool calls and their results only ever *append*;
    nothing here ever rewrites or removes it -- see `_truncate_oldest_tool_result`, which
    collapses `tool_result` blocks and never touches this one). Marking it `cache_control:
    {"type": "ephemeral"}` here means turn 1 pays the ~1.25x write premium and every subsequent
    turn in *this same tool-calling loop* reads it back at ~0.1x instead of full price --
    a real, repeated saving whenever the Analyst actually spends more than one turn investigating
    (up to `agent_max_tool_calls` extra turns, `app.core.config.Settings`), and a wash (one write,
    zero reads) on the common case of a single-turn Analyst that submits immediately.

    This is deliberately **not** done for `_run_notool_role` (Judge, Presenter, Narrator,
    domain-semantic): each of those makes exactly one call per incident, so there is no
    subsequent turn in the same role to read the cache back, and the incident-context text they
    embed cannot be served from *this* cache entry either -- caching is a strict prefix match
    through tools -> system -> messages (`shared/prompt-caching.md`), Judge/Presenter/Narrator
    each carry their own distinct `system_prompt` (`app.agent.prompts`), and a differing `system`
    invalidates every cache tier that comes after it, incident-context bytes included, no matter
    how identical those bytes are to what the Analyst wrote. Marking it there would only add the
    write premium with nothing to read it back — see `app.agent.client.LiveCaller`'s own
    docstring for the fuller version of this same reasoning, applied to the system+tools marker
    every role *does* share the benefit of. `messages[0]` is wrapped as a one-block list purely
    to carry the marker -- the text itself, and everything appended in later turns, is
    unchanged."""
    terminal_name = terminal_tool["name"]
    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": first_user_content,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
        }
    ]

    for _turn in range(MAX_ROLE_TURNS):
        if time.monotonic() >= deadline:
            raise AgentTimeoutError(role)

        offer_investigation_tools = not budget.exhausted
        tools_for_call = (
            [*investigation_tools, terminal_tool] if offer_investigation_tools else [terminal_tool]
        )
        tool_choice = (
            {"type": "auto"}
            if offer_investigation_tools
            else {"type": "tool", "name": terminal_name}
        )

        response = caller.create(
            model=model,
            max_tokens=_max_tokens_for(role),
            system=system_prompt,
            messages=messages,
            tools=tools_for_call,
            tool_choice=tool_choice,
            effort=effort,
        )
        usage.add(response.usage)
        _enforce_input_token_budget(messages, response.usage.input_tokens, role=role)

        if response.stop_reason == "refusal":
            category = (
                getattr(response.stop_details, "category", None) if response.stop_details else None
            )
            raise AgentRefusalError(role, category)
        if response.stop_reason == "max_tokens":
            raise SchemaValidationError(f"{role} hit max_tokens before calling {terminal_name}")

        messages.append({"role": "assistant", "content": response.content})

        tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
        if not tool_use_blocks:
            messages.append(
                {
                    "role": "user",
                    "content": f"You must call a tool to continue. Call {terminal_name} when ready.",
                }
            )
            continue

        terminal_input: dict[str, Any] | None = None
        tool_results: list[dict[str, Any]] = []
        for block in tool_use_blocks:
            if block.name == terminal_name:
                terminal_input = block.input
                trace.append(
                    ToolTraceEntry(
                        role=role, tool_name=block.name, tool_input=block.input, summary="terminal"
                    )
                )
                tool_results.append(
                    {"type": "tool_result", "tool_use_id": block.id, "content": "recorded"}
                )
                continue

            if not budget.consume():
                trace.append(
                    ToolTraceEntry(
                        role=role,
                        tool_name=block.name,
                        tool_input=block.input,
                        is_error=True,
                        summary="tool budget exhausted",
                    )
                )
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": (
                            f"Tool call budget exhausted. Call {terminal_name} now with what "
                            "you already have."
                        ),
                        "is_error": True,
                    }
                )
                continue

            try:
                result = dispatch_tool(ctx, block.name, block.input)
            except ToolError as exc:
                trace.append(
                    ToolTraceEntry(
                        role=role,
                        tool_name=block.name,
                        tool_input=block.input,
                        is_error=True,
                        summary=str(exc),
                    )
                )
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": str(exc),
                        "is_error": True,
                    }
                )
                continue

            trace.append(
                ToolTraceEntry(
                    role=role,
                    tool_name=block.name,
                    tool_input=block.input,
                    summary=_summarize_tool_result(block.name, result),
                )
            )
            tool_results.append(
                {"type": "tool_result", "tool_use_id": block.id, "content": _to_json(result)}
            )

        if terminal_input is not None:
            return terminal_input

        messages.append({"role": "user", "content": tool_results})

    raise SchemaValidationError(
        f"{role} did not call {terminal_name} within {MAX_ROLE_TURNS} turns"
    )


def _to_json(value: Any) -> str:
    return json.dumps(value, default=str)


def _run_notool_role(
    *,
    caller: LLMCaller,
    role: str,
    system_prompt: str,
    user_content: str,
    terminal_tool: dict[str, Any],
    model: str,
    deadline: float,
    usage: _UsageAccumulator,
    effort: str,
) -> dict[str, Any]:
    """One forced tool-use call, no investigation tools -- the Judge, Presenter, and Narrator all
    go through here. Replaces the pre-migration `_run_reporter`, generalized to any single-shot
    terminal-tool role."""
    if time.monotonic() >= deadline:
        raise AgentTimeoutError(role)

    terminal_name = terminal_tool["name"]
    response = caller.create(
        model=model,
        max_tokens=_max_tokens_for(role),
        system=system_prompt,
        messages=[{"role": "user", "content": user_content}],
        tools=[terminal_tool],
        tool_choice={"type": "tool", "name": terminal_name},
        effort=effort,
    )
    usage.add(response.usage)

    if response.stop_reason == "refusal":
        category = (
            getattr(response.stop_details, "category", None) if response.stop_details else None
        )
        raise AgentRefusalError(role, category)
    if response.stop_reason == "max_tokens":
        raise SchemaValidationError(f"{role} hit max_tokens before calling {terminal_name}")

    tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
    if not tool_use_blocks or tool_use_blocks[0].name != terminal_name:
        raise SchemaValidationError(f"{role} did not call {terminal_name}")
    return tool_use_blocks[0].input


# ---------------------------------------------------------------------------- Path B: full flow


def _run_flow(
    *,
    caller: LLMCaller,
    ctx: AgentContext,
    model: str,
    budget: _ToolBudget,
    deadline: float,
    usage: _UsageAccumulator,
    trace: list[ToolTraceEntry],
) -> TriageVerdictOut:
    incident_context = _build_incident_context_block(ctx)

    # ---- stage 1: Analyst ----
    analysis_raw = _run_tool_role(
        caller=caller,
        ctx=ctx,
        role="analyst",
        system_prompt=prompts.ANALYST_SYSTEM_PROMPT,
        first_user_content=incident_context,
        investigation_tools=ANALYST_TOOLS,
        terminal_tool=build_submit_analysis_tool(),
        budget=budget,
        deadline=deadline,
        trace=trace,
        usage=usage,
        model=model,
        effort=ANALYST_EFFORT,
    )
    try:
        analyst_output = AnalystOutput.model_validate(analysis_raw)
    except ValidationError as exc:
        raise SchemaValidationError(f"analyst submit_analysis invalid: {exc}") from exc

    # ---- verifier pass 1 (cheap, no LLM) — change 15 ----
    pass1: Pass1Result = verify_pass1(ctx, analyst_output)
    trace.append(
        ToolTraceEntry(
            role="verifier",
            tool_name="verify_pass1",
            tool_input={"n_findings": len(analyst_output.findings)},
            summary=(
                f"dropped {len(pass1.dropped_claim_checks)} hypothesis-evaluation claim(s) "
                f"before the judge; flagged {len(pass1.finding_flags)} finding(s)"
            ),
        )
    )

    # ---- stage 2: Judge ----
    judge_content = (
        incident_context
        + "\n\n"
        + prompts.wrap_analyst_output(pass1.sanitized_output.model_dump(mode="json"))
    )
    if pass1.finding_flags:
        judge_content += "\n\n" + _render_finding_flags(pass1.finding_flags)

    judgement_raw = _run_notool_role(
        caller=caller,
        role="judge",
        system_prompt=prompts.JUDGE_SYSTEM_PROMPT,
        user_content=judge_content,
        terminal_tool=build_submit_judgement_tool(),
        model=model,
        deadline=deadline,
        usage=usage,
        effort=JUDGE_EFFORT,
    )
    try:
        judge_output = JudgeOutput.model_validate(judgement_raw)
    except ValidationError as exc:
        raise SchemaValidationError(f"judge submit_judgement invalid: {exc}") from exc

    submitted_ids = {f.finding_id for f in analyst_output.findings}
    verdict_ids = {v.finding_id for v in judge_output.verdicts}
    if verdict_ids != submitted_ids:
        raise SchemaValidationError(
            f"judge verdicts {sorted(verdict_ids)} do not match submitted findings "
            f"{sorted(submitted_ids)}"
        )
    trace.append(
        ToolTraceEntry(
            role="judge",
            tool_name="submit_judgement",
            tool_input=judgement_raw,
            summary=", ".join(f"{v.finding_id}={v.decision}" for v in judge_output.verdicts),
        )
    )

    findings_by_id = {f.finding_id: f for f in analyst_output.findings}
    judge_survived: list[Finding] = []
    for v in judge_output.verdicts:
        if v.decision == "PASS":
            judge_survived.append(findings_by_id[v.finding_id])
        elif v.decision == "REVISE":
            assert v.revised_finding is not None  # JudgeVerdict's own validator guarantees this
            judge_survived.append(v.revised_finding)
        # REJECT: excluded entirely from what reaches the Presenter.

    # ---- verifier pass 2 (full, incl. scope + confidence integrity) — change 15 ----
    pass2: Pass2Result = verify_pass2(ctx, judge_survived)
    trace.append(
        ToolTraceEntry(
            role="verifier",
            tool_name="verify_pass2",
            tool_input={"n_findings": len(judge_survived)},
            summary=(
                f"{len(pass2.invalid_citations)} invalid citation(s) across "
                f"{len(judge_survived)} judge-surviving finding(s)"
            ),
        )
    )

    presenter_findings = [
        f for f, check in zip(judge_survived, pass2.finding_checks, strict=True) if check.valid
    ]
    if not presenter_findings:
        raise InsufficientEvidenceError(
            f"no finding survived judging and full verification ({len(analyst_output.findings)} "
            f"submitted, {len(judge_survived)} passed/revised by the judge, 0 passed the final "
            "verifier check)",
            invalid_citations=pass2.invalid_citations,
        )

    # ---- stage 4: Presenter ----
    presenter_content = (
        incident_context
        + "\n\n"
        + prompts.wrap_judge_output(
            {"verdicts": [v.model_dump(mode="json") for v in judge_output.verdicts]}
        )
        + "\n\n"
        + _wrap_presenter_findings(presenter_findings)
    )
    verdict_raw = _run_notool_role(
        caller=caller,
        role="presenter",
        system_prompt=prompts.PRESENTER_SYSTEM_PROMPT,
        user_content=presenter_content,
        terminal_tool=build_present_verdict_tool(),
        model=model,
        deadline=deadline,
        usage=usage,
        effort=PRESENTER_EFFORT,
    )
    trace.append(
        ToolTraceEntry(
            role="presenter",
            tool_name="present_verdict",
            tool_input=verdict_raw,
            summary="final verdict",
        )
    )

    try:
        verdict = TriageVerdictOut.model_validate(verdict_raw)
    except ValidationError as exc:
        raise SchemaValidationError(f"presenter present_verdict invalid: {exc}") from exc

    # docs/v2_migration change 3: hard rejection, not a warning — see verifier.verify_anomaly_
    # confidence's own docstring for why this gets different treatment from citation verification.
    confidence_check = verify_anomaly_confidence(ctx, verdict)
    if not confidence_check.ok:
        log.warning(
            "agent.anomaly_confidence_integrity_failed",
            incident_id=str(ctx.incident_id),
            expected=confidence_check.expected,
            actual=confidence_check.actual,
        )
        raise AnomalyConfidenceIntegrityError(confidence_check.reason)

    return verdict


# ---------------------------------------------------------------------------- public entry points (Path B)


def _latest_verdict(session: Session, incident_id: uuid.UUID) -> TriageVerdict | None:
    return session.execute(
        select(TriageVerdict)
        .where(TriageVerdict.incident_id == incident_id)
        .order_by(TriageVerdict.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def _needs_review_fallback(
    *,
    reason: str,
    trace: list[ToolTraceEntry],
    usage: _UsageAccumulator,
    elapsed_ms: int,
    model: str,
    anomaly_confidence: float,
    citation_valid: bool = True,
    invalid_citations: tuple[dict[str, Any], ...] = (),
) -> TriageVerdictOut:
    return TriageVerdictOut(
        disposition="needs_review",
        threat_confidence="low",
        threat_confidence_reason=(
            f"Triage did not complete, so there is no hypothesis-evaluation judgment to report: "
            f"{reason}"
        ),
        anomaly_confidence=anomaly_confidence,
        llm_severity_opinion=None,
        mitre_techniques=(),
        summary=f"Triage did not complete: {reason}",
        narrative=(),
        contradicting_evidence=f"Investigation could not be completed to weigh a counter-case: {reason}",
        recommended_actions=(),
        tool_trace=tuple(trace),
        citation_valid=citation_valid,
        invalid_citations=invalid_citations,
        model=model,
        tokens_in=usage.input_tokens,
        tokens_out=usage.output_tokens,
        cost_usd=estimate_cost_usd(usage),
        latency_ms=elapsed_ms,
        needs_review_reason=reason,
    )


def _accumulate_analysis_cost(
    session: Session, tenant_id: uuid.UUID, incident_id: uuid.UUID, cost_usd: Decimal | None
) -> None:
    """docs/v2_migration change 14 ("surface spend per analysis"): every persisted verdict's real
    per-call cost rolls up into `analyses.llm_cost_usd`. An atomic `UPDATE ... SET x = x + delta`
    so concurrent triage runs against the same analysis never lose an increment."""
    if not cost_usd:
        return
    with tenant_scope(session, tenant_id):
        analysis_id = session.execute(
            select(Incident.analysis_id).where(Incident.id == incident_id)
        ).scalar_one_or_none()
        if analysis_id is None:  # pragma: no cover - the incident was just triaged, must exist
            return
        session.execute(
            update(Analysis)
            .where(Analysis.id == analysis_id)
            .values(llm_cost_usd=func.coalesce(Analysis.llm_cost_usd, 0) + cost_usd)
        )
        session.commit()


def _persist(session: Session, incident_id: uuid.UUID, verdict: TriageVerdictOut) -> TriageVerdict:
    row = TriageVerdict(
        incident_id=incident_id,
        disposition=verdict.disposition,
        threat_confidence=verdict.threat_confidence,
        threat_confidence_reason=verdict.threat_confidence_reason,
        llm_severity_opinion=verdict.llm_severity_opinion,
        mitre_techniques=[t.model_dump(mode="json") for t in verdict.mitre_techniques],
        summary=verdict.summary,
        narrative=[n.model_dump(mode="json") for n in verdict.narrative],
        contradicting_evidence=verdict.contradicting_evidence,
        recommended_actions=list(verdict.recommended_actions),
        tool_trace=[t.model_dump(mode="json") for t in verdict.tool_trace],
        citation_valid=verdict.citation_valid,
        invalid_citations=list(verdict.invalid_citations),
        model=verdict.model,
        tokens_in=verdict.tokens_in,
        tokens_out=verdict.tokens_out,
        cost_usd=verdict.cost_usd,
        latency_ms=verdict.latency_ms,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def triage_incident(
    session: Session,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    *,
    caller: LLMCaller | None = None,
    force: bool = False,
    evidence_payloads: list[EvidencePayload] | None = None,
) -> TriageVerdict:
    """Triage one incident end to end and persist the verdict. Idempotent by default.

    `evidence_payloads`, when given, is passed straight through to `build_agent_context` instead
    of being recomputed — `triage_top_incidents_for_analysis` uses this to compute an analysis's
    evidence once and share it across every incident it triages.

    Dispatch order:
    1. Existing verdict (unless `force`) — return it.
    3. Otherwise, the real Analyst -> Judge -> verifier -> Presenter flow — raises
       `MissingAPIKeyError` if no `caller` was injected and `Settings.anthropic_api_key` is unset.
    """
    settings = get_settings()

    if not force:
        existing = _latest_verdict(session, incident_id)
        if existing is not None:
            return existing

    if caller is None and not settings.llm_enabled:
        raise MissingAPIKeyError

    ctx = build_agent_context(session, tenant_id, incident_id, evidence_payloads=evidence_payloads)
    active_caller = caller or LiveCaller(api_key=settings.anthropic_api_key.get_secret_value())

    start = time.monotonic()
    deadline = start + settings.agent_timeout_seconds
    budget = _ToolBudget(remaining=settings.agent_max_tool_calls)
    usage = _UsageAccumulator()
    trace: list[ToolTraceEntry] = []

    try:
        verdict_out = _run_flow(
            caller=active_caller,
            ctx=ctx,
            model=settings.anthropic_model,
            budget=budget,
            deadline=deadline,
            usage=usage,
            trace=trace,
        )
    except (
        AgentTimeoutError,
        AgentRefusalError,
        SchemaValidationError,
        ToolError,
        AnomalyConfidenceIntegrityError,
        InsufficientEvidenceError,
    ) as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        log.warning(
            "agent.triage_failed",
            incident_id=str(incident_id),
            reason=str(exc),
            exc_type=type(exc).__name__,
        )
        verdict_out = _needs_review_fallback(
            reason=str(exc),
            trace=trace,
            usage=usage,
            elapsed_ms=elapsed_ms,
            model=settings.anthropic_model,
            anomaly_confidence=ctx.anomaly_confidence,
            invalid_citations=getattr(exc, "invalid_citations", ()),
            citation_valid=not getattr(exc, "invalid_citations", ()),
        )
        row = _persist(session, incident_id, verdict_out)
        _accumulate_analysis_cost(session, tenant_id, incident_id, verdict_out.cost_usd)
        return row

    elapsed_ms = int((time.monotonic() - start) * 1000)
    citation_valid, invalid_citations, _checks = verify_citations(ctx, verdict_out)
    total_input_tokens = (
        usage.input_tokens + usage.cache_creation_input_tokens + usage.cache_read_input_tokens
    )
    verdict_out = verdict_out.model_copy(
        update={
            "tool_trace": tuple(trace),
            "citation_valid": citation_valid,
            "invalid_citations": tuple(invalid_citations),
            "model": settings.anthropic_model,
            "tokens_in": total_input_tokens,
            "tokens_out": usage.output_tokens,
            "cost_usd": estimate_cost_usd(usage),
            "latency_ms": elapsed_ms,
        }
    )
    log.info(
        "agent.triage_complete",
        incident_id=str(incident_id),
        disposition=verdict_out.disposition,
        citation_valid=citation_valid,
        n_invalid_citations=len(invalid_citations),
        cost_usd=str(verdict_out.cost_usd),
        latency_ms=elapsed_ms,
    )
    row = _persist(session, incident_id, verdict_out)
    _accumulate_analysis_cost(session, tenant_id, incident_id, verdict_out.cost_usd)
    return row


def triage_top_incidents_for_analysis(
    session: Session,
    tenant_id: uuid.UUID,
    analysis_id: uuid.UUID,
    *,
    caller: LLMCaller | None = None,
    force: bool = False,
) -> list[TriageVerdict]:
    """docs/07 "Scope discipline": "Only the top MAX_TRIAGE_INCIDENTS (15) by fused_score."
    Computes this analysis's
    `EvidencePayload`s exactly once (`compute_evidence_payloads`) and shares them across every
    incident's `triage_incident` call — `app.agent.context`'s own module docstring on why
    recomputing per-incident would otherwise happen `MAX_TRIAGE_INCIDENTS` times over."""
    settings = get_settings()
    with tenant_scope(session, tenant_id):
        incident_ids = list(
            session.execute(
                select(Incident.id)
                .where(Incident.analysis_id == analysis_id)
                .order_by(Incident.fused_score.desc())
                .limit(settings.max_triage_incidents)
            ).scalars()
        )
    evidence_payloads = compute_evidence_payloads(
        session, analysis_id=analysis_id, tenant_id=tenant_id
    )
    return [
        triage_incident(
            session,
            tenant_id,
            incident_id,
            caller=caller,
            force=force,
            evidence_payloads=evidence_payloads,
        )
        for incident_id in incident_ids
    ]


# ---------------------------------------------------------------------------- Path A: narrator


@dataclass(slots=True)
class NarrationResult:
    """change 14 Path A's output. `citation_valid`/`invalid_citations` mirror the Path B
    verdict's own fields — "Verifier still runs" applies here exactly as it does for the
    per-incident pipeline.

    Persisted to `analyses.narrative*` by both of its producers, via `narrative_columns` below;
    this module still does not write the row itself (that stays with the stage and the route
    that own their sessions), it only owns the mapping from result to columns."""

    executive_summary: str
    phase_narratives: tuple[dict[str, Any], ...]
    citation_valid: bool
    invalid_citations: tuple[dict[str, Any], ...]
    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal
    latency_ms: int


def narrative_columns(result: NarrationResult) -> dict[str, Any]:
    """`NarrationResult` -> the `analyses.narrative*` column values, as an `update().values()`
    mapping.

    Both producers of a narration — the `triage` stage's automatic Path A call and the manual
    `POST /api/analyses/{id}/narrate` — write through this one function, so a stored narrative
    means the same thing regardless of which produced it. Previously they agreed on nothing:
    the stage discarded its result entirely and only the route returned one, over the wire, to
    a single browser tab that lost it on reload.

    `narrative_generated_at` is stamped here rather than defaulted in the database so it records
    when the model actually produced the text, not when the row happened to be written."""
    return {
        "narrative": result.executive_summary,
        "narrative_phases": list(result.phase_narratives),
        "narrative_citation_valid": result.citation_valid,
        "narrative_invalid_citations": list(result.invalid_citations),
        "narrative_model": result.model,
        "narrative_cost_usd": result.cost_usd,
        "narrative_generated_at": datetime.now(UTC),
    }


def narrate_analysis(
    *,
    overview: dict[str, Any],
    incidents: list[dict[str, Any]],
    timeline_phases: list[dict[str, Any]],
    caller: LLMCaller,
    model: str,
    timeout_seconds: float = 60.0,
) -> NarrationResult:
    """change 14 Path A, the single LLM call in the analysis-level narrative path:

        deterministic overview stats + incident list + analysis timeline entries
            -> Narrator LLM (one call)
            -> deterministic verifier
            -> executive summary + timeline phase narratives

    **No judge stage** (change 14: "a judge pass over descriptive narrative is not worth the
    call"). `overview`/`incidents`/`timeline_phases` are deterministic, pre-computed inputs — this
    function does no detection, correlation, or SQL of its own; it is the LLM-and-verifier half of
    Path A only. `timeline_phases` entries are expected to already carry a stable `phase_index`
    and their own citable ids (`log_ids`/`evidence_ids`) — *selection* of which phases matter is
    deterministic and happens upstream (docs/05), never here.
    """
    start = time.monotonic()
    deadline = start + timeout_seconds
    usage = _UsageAccumulator()

    context_block = prompts.build_narrator_context(
        overview=overview, incidents=incidents, timeline_phases=timeline_phases
    )
    raw = _run_notool_role(
        caller=caller,
        role="narrator",
        system_prompt=prompts.NARRATOR_SYSTEM_PROMPT,
        user_content=context_block,
        terminal_tool=build_narrate_tool(),
        model=model,
        deadline=deadline,
        usage=usage,
        effort=NARRATOR_EFFORT,
    )
    try:
        output = NarratorOutput.model_validate(raw)
    except ValidationError as exc:
        raise SchemaValidationError(f"narrator narrate_analysis invalid: {exc}") from exc

    citation_valid, invalid_citations = verify_narrator_output(
        overview=overview, incidents=incidents, timeline_phases=timeline_phases, output=output
    )
    elapsed_ms = int((time.monotonic() - start) * 1000)
    log.info(
        "agent.narrate_complete",
        citation_valid=citation_valid,
        n_invalid_citations=len(invalid_citations),
        cost_usd=str(estimate_cost_usd(usage)),
        latency_ms=elapsed_ms,
    )
    return NarrationResult(
        executive_summary=output.executive_summary,
        phase_narratives=tuple(p.model_dump(mode="json") for p in output.phase_narratives),
        citation_valid=citation_valid,
        invalid_citations=tuple(invalid_citations),
        model=model,
        tokens_in=usage.input_tokens,
        tokens_out=usage.output_tokens,
        cost_usd=estimate_cost_usd(usage),
        latency_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------- change 8: domain semantics


@dataclass(slots=True)
class DomainFinding:
    """One flagged domain from change 8's semantic pass. Deliberately carries no `label` field of
    any kind -- see `app.agent.schemas.DomainAssessment`'s own docstring for the full reasoning.
    `app.api.analyses` is the only caller that turns this into `app.schemas.overview.
    DomainSemanticFinding` (the wire schema, owned outside this package), and that schema's
    `label` is a `Literal` defaulted to `SEMANTIC_INSIGHT_LABEL` -- there is no field on *this*
    dataclass a caller could copy the wrong value out of, because this dataclass never represents
    a label at all."""

    domain: str
    assessment: str
    rationale: str
    evidence_id: str | None


@dataclass(slots=True)
class DomainSemanticResult:
    """`app.agent.orchestrator.assess_domain_semantics`'s return value. `findings` already
    excludes both unflagged assessments and any flagged assessment that failed `app.agent.
    verifier.verify_domain_semantic_output` -- unlike Path A's `NarrationResult` (which surfaces
    invalid citations but still returns the narrative they were attached to), this pass drops a
    citation-invalid finding outright, because `app.schemas.overview.DomainSemanticFinding` (the
    wire schema) has no field to carry a per-finding validity flag to the UI -- CLAUDE.md rule 6
    ("unverified claims get flagged, not silently rendered") applied to a schema that has no way
    to flag one: the safe reading is "not silently rendered", so an unverified finding is dropped,
    not shown as if it had passed. `citation_valid`/`invalid_citations` remain on this result for
    logging/eval/tests even though the current wire schema has nowhere to carry them forward."""

    findings: tuple[DomainFinding, ...]
    citation_valid: bool
    invalid_citations: tuple[dict[str, Any], ...]
    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal
    latency_ms: int


def assess_domain_semantics(
    *,
    candidates: list[dict[str, Any]],
    caller: LLMCaller,
    model: str,
    timeout_seconds: float = 60.0,
) -> DomainSemanticResult:
    """change 8's LLM semantic domain-analysis pass: brand impersonation, typosquatting intent,
    and contextual relevance for destinations the deterministic rarity/baseline layer already
    flagged rare or first-seen -- the half the DGA classifier's lexical-randomness model cannot
    catch. Does not replace that classifier (its score, when known, travels through in each
    candidate's own `dga_score` field, read-only, never touched here) and never sets severity,
    priority, or `anomaly_confidence` -- see `app.agent.prompts.DOMAIN_SEMANTIC_SYSTEM_PROMPT`.

    `candidates` is a deterministic, pre-computed input the caller hands in, exactly like Path A's
    `narrate_analysis` (`overview`/`incidents`/`timeline_phases`) -- this function does no SQL of
    its own; gathering the candidate list (rarity/first-seen selection, contributing line ids, the
    events that preceded a user's first visit) is `app.api.analyses._compute_domain_semantic_
    candidates`'s job, out of this package's ownership boundary the same way `app.agent`'s own
    module docstrings describe for every other piece of pipeline wiring.

    ## Zero-candidate short-circuit

    When `candidates` is empty -- the common case; most uploads have no rare/first-seen
    destination at all -- this makes no LLM call and returns an empty result at zero cost. This
    matters because, unlike the Narrator (called explicitly, once, from its own `POST /narrate`
    route specifically *because* an LLM call is never free), this pass is wired into
    `GET /analyses/{id}/overview` -- a route documented elsewhere as "safe to call on every page
    load". The empty-candidate short-circuit is what keeps that promise true for the overwhelming
    majority of analyses; `app.api.analyses`'s own module comments document the cost tradeoff that
    remains on the non-empty path, which does spend real tokens on every call, same as any other
    real LLM call in this system (CLAUDE.md/change 12: "cost is real per upload").

    `candidates` is additionally bounded to `MAX_SEMANTIC_DOMAINS_PER_CALL` here as a second,
    defensive cap even though the caller is expected to have already applied the same bound --
    CLAUDE.md rule 1's "the LLM never sees raw log volume" is enforced at every stage that could
    violate it, not only the first one.
    """
    if not candidates:
        return DomainSemanticResult(
            findings=(),
            citation_valid=True,
            invalid_citations=(),
            model=model,
            tokens_in=0,
            tokens_out=0,
            cost_usd=Decimal("0"),
            latency_ms=0,
        )

    bounded = candidates[:MAX_SEMANTIC_DOMAINS_PER_CALL]
    start = time.monotonic()
    deadline = start + timeout_seconds
    usage = _UsageAccumulator()

    context_block = prompts.build_domain_semantic_context(candidates=bounded)
    raw = _run_notool_role(
        caller=caller,
        role="domain_semantic",
        system_prompt=prompts.DOMAIN_SEMANTIC_SYSTEM_PROMPT,
        user_content=context_block,
        terminal_tool=build_assess_domains_tool(),
        model=model,
        deadline=deadline,
        usage=usage,
        effort=DOMAIN_SEMANTIC_EFFORT,
    )
    try:
        output = DomainSemanticOutput.model_validate(raw)
    except ValidationError as exc:
        raise SchemaValidationError(f"domain_semantic assess_domains invalid: {exc}") from exc

    citation_valid, invalid_citations = verify_domain_semantic_output(
        candidates=bounded, output=output
    )
    invalid_domains = {entry["domain"] for entry in invalid_citations if "domain" in entry}
    findings = tuple(
        DomainFinding(
            domain=a.domain,
            assessment=a.assessment,
            rationale=a.rationale,
            evidence_id=a.evidence_ids[0] if a.evidence_ids else None,
        )
        for a in output.assessments
        if a.flagged and a.domain not in invalid_domains
    )
    elapsed_ms = int((time.monotonic() - start) * 1000)
    log.info(
        "agent.domain_semantic_complete",
        n_candidates=len(bounded),
        n_flagged=sum(1 for a in output.assessments if a.flagged),
        n_findings=len(findings),
        citation_valid=citation_valid,
        cost_usd=str(estimate_cost_usd(usage)),
        latency_ms=elapsed_ms,
    )
    return DomainSemanticResult(
        findings=findings,
        citation_valid=citation_valid,
        invalid_citations=tuple(invalid_citations),
        model=model,
        tokens_in=usage.input_tokens,
        tokens_out=usage.output_tokens,
        cost_usd=estimate_cost_usd(usage),
        latency_ms=elapsed_ms,
    )


@dataclass(slots=True)
class EventTimelineResult:
    """The event-view timeline summary. Windowing is deterministic and upstream; this is only the
    prose over it, plus the same numeric verification every other LLM output here gets."""

    overview: str
    windows: tuple[dict[str, Any], ...]
    citation_valid: bool
    invalid_citations: tuple[dict[str, Any], ...]
    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal
    latency_ms: int


def summarize_event_windows(
    *,
    windows: list[dict[str, Any]],
    caller: LLMCaller,
    model: str,
    timeout_seconds: float = 60.0,
) -> EventTimelineResult:
    """One LLM call over already-bucketed event windows -> readable prose per window.

    `windows` must be the deterministic aggregates `app.api.events` computed in SQL. This function
    never receives raw events (CLAUDE.md rule 1) and never chooses the windows -- same division of
    labour as Path A, where selection is deterministic and only the writing is delegated.

    Verification reuses `verify_narrator_output`'s numeric machinery via the same
    `numeric_leaves`/`extract_numbers` pair: every number in a window's prose must appear in that
    window's own aggregates. A model that totals two windows together, or estimates a figure it
    was not given, is flagged rather than rendered as fact (rule 6).
    """
    start = time.monotonic()
    deadline = start + timeout_seconds
    usage = _UsageAccumulator()

    raw = _run_notool_role(
        caller=caller,
        role="event_timeline",
        system_prompt=prompts.EVENT_TIMELINE_SYSTEM_PROMPT,
        user_content=prompts.wrap_untrusted({"windows": windows}),
        terminal_tool=build_summarize_windows_tool(),
        model=model,
        deadline=deadline,
        usage=usage,
        effort=NARRATOR_EFFORT,
    )
    try:
        output = EventTimelineOutput.model_validate(raw)
    except ValidationError as exc:
        raise SchemaValidationError(f"summarize_windows invalid: {exc}") from exc

    citation_valid, invalid = verify_event_timeline_output(windows=windows, output=output)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    log.info(
        "agent.event_timeline_complete",
        n_windows=len(windows),
        citation_valid=citation_valid,
        n_invalid=len(invalid),
        cost_usd=str(estimate_cost_usd(usage)),
        latency_ms=elapsed_ms,
    )
    return EventTimelineResult(
        overview=output.overview,
        windows=tuple(w.model_dump(mode="json") for w in output.windows),
        citation_valid=citation_valid,
        invalid_citations=tuple(invalid),
        model=model,
        tokens_in=usage.input_tokens,
        tokens_out=usage.output_tokens,
        cost_usd=estimate_cost_usd(usage),
        latency_ms=elapsed_ms,
    )
