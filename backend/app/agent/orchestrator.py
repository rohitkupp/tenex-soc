"""Three-role agentic triage flow — docs/07-AGENT.md "Multi-agent flow":

    Investigator -> Devil's Advocate -> Reporter

| Role | Job | Tools |
|---|---|---|
| Investigator | Gather evidence, form a hypothesis | all five (`app.agent.tools.TOOL_DEFINITIONS`) |
| Devil's Advocate | Argue the false-positive case against the hypothesis | read-only subset |
| Reporter | Reconcile both and emit the final structured verdict | none |

**"Read-only subset" for the Devil's Advocate.** Every tool in this package is already
read-only (docs/07: "the agent cannot mutate anything") — so docs/07's "subset" has to mean a
subset of the *five tools*, not a stricter mutation guarantee. This build's choice: the Devil's
Advocate gets everything except `query_events` (`DEVILS_ADVOCATE_TOOLS` below). Rationale: the
Investigator's job is open-ended discovery — it doesn't yet know what it's looking for, so
`query_events`'s free-form filtering matters. The Devil's Advocate's job is to re-examine
*already-surfaced* evidence and run *targeted* verification against it
(`get_entity_timeline`/`get_entity_baseline`/`get_related_signals`/`search_mitre` all take a
specific entity or query, no open-ended search) — giving it a fresh fishing expedition would
both cost more of the shared tool budget and dilute its actual job, which is critiquing what's
already on the table, not re-discovering the incident from scratch.

## Why the Investigator and Devil's Advocate each get their own terminal tool

docs/07 specifies the *final* verdict's schema (`app.agent.schemas.TriageVerdictOut`,
`emit_verdict`) but the Reporter has **no tools** and therefore cannot re-derive citations
itself. For `narrative[].evidence_event_ids` to reach the Reporter in a form it can carry
forward faithfully (not invent), the Investigator's own conclusion has to already be
structured — hence `submit_findings` (`InvestigationFindings`). Symmetrically,
`contradicting_evidence` is a *required* field on the final verdict (docs/07); the Devil's
Advocate is the role that actually argues it, so it is forced to produce that argument in
structured form (`submit_rebuttal` / `Rebuttal`) rather than leaving the Reporter to summarize
free text it might get wrong. Every role boundary in this file is a schema boundary, not a
prose hand-off.

## Cost control (CLAUDE.md "Budget discipline")

`effort` is set per role, not uniformly at the API default: `medium` for the Investigator (the
role doing the real reasoning and tool orchestration) and Reporter (the role whose output is
graded), `low` for the Devil's Advocate (a narrower, more mechanical task — read what's already
there, run a few targeted checks, argue the counter-case). `AGENT_MAX_TOOL_CALLS`
(`app.core.config.Settings.agent_max_tool_calls`, default 8) is a **shared** budget across the
Investigator and Devil's Advocate, enforced by one `_ToolBudget` instance threaded through both
— not eight calls *each*. When it hits zero, the next request from either role offers only the
role's terminal tool (`tool_choice` forced), so the run always reaches a verdict rather than
erroring out mid-investigation.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.agent import prompts
from app.agent.client import LiveCaller, LLMCaller, estimate_cost_usd
from app.agent.context import AgentContext, AgentContextError, build_agent_context
from app.agent.schemas import (
    AgentRole,
    InvestigationFindings,
    Rebuttal,
    SchemaValidationError,
    ToolTraceEntry,
    TriageVerdictOut,
    build_emit_verdict_tool,
    build_submit_findings_tool,
    build_submit_rebuttal_tool,
)
from app.agent.tools import TOOL_DEFINITIONS, ToolError, dispatch_tool
from app.agent.verifier import (
    AnomalyConfidenceIntegrityError,
    verify_anomaly_confidence,
    verify_citations,
)
from app.core.config import get_settings
from app.core.logging import get_logger
from app.graph.timeline import build_timeline
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.triage_verdict import TriageVerdict

try:  # M13, concurrent — see this module's own docstring and CLAUDE.md's build brief item 8.
    from app.learning.memory import (
        get_prior_analyst_decisions_for_incident,
        render_prior_analyst_decisions_block,
    )

    _HAS_FEW_SHOT_MEMORY = True
except ImportError:  # pragma: no cover - integration point for when app/learning isn't present
    _HAS_FEW_SHOT_MEMORY = False

__all__ = [
    "AgentRefusalError",
    "AgentTimeoutError",
    "MissingAPIKeyError",
    "triage_incident",
    "triage_top_incidents_for_analysis",
]

log = get_logger(__name__)

MAX_TOKENS_PER_TURN = 8192
MAX_ROLE_TURNS = 12  # safety cap independent of the tool-call budget — see _run_tool_role
MAX_SIGNALS_IN_CONTEXT = 30  # highest-confidence first — see _build_incident_context_block
MAX_EVIDENCE_IDS_IN_CONTEXT = 20  # per signal/timeline-phase, same reasoning

# docs/07 "Bounds": "Input tokens | 60k per incident | Truncate oldest tool results." Checked
# after every turn against that turn's own `usage.input_tokens` (the size of the request that
# was just sent — the best available proxy for what the *next* request would cost before it's
# built) — a live run without this measured 64.5k input tokens on a 9-signal incident, so this
# is not a theoretical bound.
MAX_INPUT_TOKENS = 60_000
_TRUNCATED_TOOL_RESULT_PLACEHOLDER = (
    "[earlier tool result omitted to stay within the 60k input-token budget — call the tool "
    "again if you need this data]"
)

INVESTIGATOR_TOOLS: list[dict[str, Any]] = TOOL_DEFINITIONS
DEVILS_ADVOCATE_TOOLS: list[dict[str, Any]] = [
    t for t in TOOL_DEFINITIONS if t["name"] != "query_events"
]

INVESTIGATOR_EFFORT = "medium"
DEVILS_ADVOCATE_EFFORT = "low"
REPORTER_EFFORT = "medium"


class AgentTimeoutError(Exception):
    """AGENT_TIMEOUT_SECONDS exceeded mid-run (docs/07 bound). Caught by `triage_incident`,
    which emits `needs_review` with whatever partial trace exists."""

    def __init__(self, role: str) -> None:
        super().__init__(f"agent timeout during {role}")
        self.role = role


class AgentRefusalError(Exception):
    """Claude Opus 5's safety classifiers declined a turn (`stop_reason == "refusal"`) — see the
    claude-api skill's Claude Opus 5 migration notes. Treated the same as a timeout: emit
    `needs_review`, never crash the triage run."""

    def __init__(self, role: str, category: str | None) -> None:
        super().__init__(f"model refused during {role} (category={category})")
        self.role = role
        self.category = category


class MissingAPIKeyError(RuntimeError):
    """Raised by `triage_incident` when it needs to make a live call (no `caller` was injected)
    and `Settings.anthropic_api_key` is unset. docs/v2_migration change 12 removed the old
    DEMO_MODE / no-key fallback (`app.agent.demo.synthesize_demo_verdict`) entirely — every
    upload now makes real calls, so a missing key is a configuration error, not a mode to
    degrade into. Raised here, at the one call site that would otherwise construct a
    `LiveCaller`, rather than at process startup: `api`/`orchestrator`/`parser`/`enricher`/
    `anonymizer`/`detector`/`correlator`/`tier2-sync` never need a key at all (docs/01), so
    refusing to *boot* without one would fail healthy services for a key only the `agent`
    worker (and its `POST /api/incidents/{id}/triage` callers) actually needs. This is also
    the one path every test that wants live-call behavior already has to inject a `caller`
    for (`tests/fixtures/llm/`, recorded fixtures) — see this module's own docstring."""

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


def _build_incident_context_block(ctx: AgentContext) -> str:
    """The Investigator's (and, folded in again for the Devil's Advocate / Reporter's own first
    turns, everyone's) view of the incident as computed upstream — docs/05 correlation, docs/04
    detection, docs/05 timeline. Deterministic ordering (`app.graph.timeline.build_timeline`,
    read-only import, M10's own public function — never reimplemented here) means the model
    never has to order raw events itself.

    Signals are capped at `MAX_SIGNALS_IN_CONTEXT`, highest-confidence first — CLAUDE.md rule 1
    ("The LLM never sees raw log volume... more than a few hundred events into a prompt, stop")
    applies just as much to a large incident's signal list as to raw events: a real correlated
    incident can carry thousands of signals (a whole beaconing/burst campaign on one entity, one
    signal per window), and passing all of them would blow the 60k input-token budget on context
    alone before the model ever calls a tool. `total_signal_count` tells the model the true size
    so it knows to reach for `get_related_signals` on a specific entity for anything not shown
    here, rather than assuming the shown list is exhaustive."""
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
    signals = sorted(all_signals, key=lambda s: s.confidence, reverse=True)[:MAX_SIGNALS_IN_CONTEXT]

    timeline_phases = build_timeline(list(signals))

    signals_payload = [
        {
            "id": s.id,
            "detector_key": s.detector_key,
            "detector_layer": s.detector_layer,
            "confidence": s.confidence,
            "entity_type": s.entity_type,
            "entity_value": ctx.pseudonymize_value(s.entity_value, s.entity_type),
            "mitre_technique": s.mitre_technique,
            "evidence_event_ids": list(s.evidence_event_ids)[:MAX_EVIDENCE_IDS_IN_CONTEXT],
            "explanation": s.explanation,
        }
        for s in signals
    ]
    timeline_payload = [
        {
            "ts": p.ts.isoformat() if p.ts else None,
            "tactic": p.tactic,
            "event_ids": p.event_ids[:MAX_EVIDENCE_IDS_IN_CONTEXT],
            "summary": p.summary,
        }
        for p in timeline_phases
    ]
    entity_scope_payload = [
        {"entity_type": t, "entity_value": ctx.pseudonymize_value(v, t)}
        for t, v in sorted(ctx.entity_scope)
    ]

    return prompts.build_incident_context(
        incident_title=title,
        severity=severity,
        fused_score=fused_score,
        anomaly_confidence=ctx.anomaly_confidence,
        signals=signals_payload,
        timeline=timeline_payload,
        entity_scope=entity_scope_payload,
        total_signal_count=total_signal_count,
    )


def _prior_analyst_decisions_block(ctx: AgentContext) -> str:
    """M13's few-shot memory integration point (CLAUDE.md build brief item 8). Used exactly as
    `app.learning.memory`'s own module docstring specifies it will be, if the module is present;
    degrades to an empty string (no block spliced in) on any failure, including the module not
    existing at all — few-shot memory is a quality enhancement, never a triage blocker."""
    if not _HAS_FEW_SHOT_MEMORY:
        return ""
    try:
        decisions = get_prior_analyst_decisions_for_incident(
            ctx.session, tenant_id=ctx.tenant_id, incident_id=ctx.incident_id
        )
        if not decisions:
            return ""
        return render_prior_analyst_decisions_block(decisions)
    except Exception:  # degrade, never fail the run over a memory lookup
        log.warning("agent.prior_decisions_failed", incident_id=str(ctx.incident_id), exc_info=True)
        return ""


# ---------------------------------------------------------------------------- tool-calling loop


def _summarize_tool_result(name: str, result: Any) -> str:
    """A short, human-readable line for `tool_trace` — the trace records *that* a tool was
    called and roughly what came back, not the full payload (that would defeat the point of
    keeping the LLM's own context, and this trace, small — CLAUDE.md rule 1)."""
    if isinstance(result, list):
        return f"{len(result)} result(s)"
    if isinstance(result, dict) and name == "get_entity_baseline":
        return (
            f"value={result.get('value')} baseline_mean={result.get('baseline_mean')} "
            f"z_score={result.get('z_score')} n_baseline_windows={result.get('n_baseline_windows')}"
        )
    return "ok"


def _truncate_oldest_tool_result(messages: list[dict[str, Any]]) -> bool:
    """Finds the oldest not-yet-truncated `tool_result` content block anywhere in `messages`
    and collapses it to a short placeholder, in place. Returns `False` once every tool result is
    already collapsed (nothing left to shrink) so the caller can stop looping instead of spinning
    forever on a conversation that's grown large for reasons other than tool-result bulk (e.g. a
    naturally long system prompt or narrative — `_run_flow`'s per-role system prompts are static
    and small, so this should not be the steady state, but the loop bounds itself regardless)."""
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
    messages: list[dict[str, Any]], last_input_tokens: int, *, role: AgentRole
) -> None:
    """Called after every turn with that turn's own `usage.input_tokens` — the size of the
    request that produced it, and the best available proxy for what the *next* request would
    cost before it's built (a `count_tokens` call to measure precisely would itself spend
    against the same budget it's trying to protect). Collapses exactly one oldest tool result
    per over-budget turn rather than guessing how many to collapse at once: growth is
    incremental (one tool call at a time), so shrinking incrementally and re-checking on the
    next real `usage.input_tokens` converges without ever needing a precise token count."""
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
    role: AgentRole,
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
    `AgentRefusalError` / `SchemaValidationError`. Returns the terminal tool call's raw `input` dict
    (parsed into a pydantic model by the caller, not here — this function only knows about the
    Messages API, not the domain schema)."""
    terminal_name = terminal_tool["name"]
    messages: list[dict[str, Any]] = [{"role": "user", "content": first_user_content}]

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
            max_tokens=MAX_TOKENS_PER_TURN,
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
            # Model responded with plain text instead of a tool call. Nudge it back on track —
            # the shared system prompt already says tools are the only acceptable path, so this
            # is recovery from an occasional deviation, not the expected steady state.
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


def _run_reporter(
    *,
    caller: LLMCaller,
    system_prompt: str,
    user_content: str,
    model: str,
    deadline: float,
    usage: _UsageAccumulator,
) -> dict[str, Any]:
    if time.monotonic() >= deadline:
        raise AgentTimeoutError("reporter")

    emit_tool = build_emit_verdict_tool()
    response = caller.create(
        model=model,
        max_tokens=MAX_TOKENS_PER_TURN,
        system=system_prompt,
        messages=[{"role": "user", "content": user_content}],
        tools=[emit_tool],
        tool_choice={"type": "tool", "name": "emit_verdict"},
        effort=REPORTER_EFFORT,
    )
    usage.add(response.usage)

    if response.stop_reason == "refusal":
        category = (
            getattr(response.stop_details, "category", None) if response.stop_details else None
        )
        raise AgentRefusalError("reporter", category)
    if response.stop_reason == "max_tokens":
        raise SchemaValidationError("reporter hit max_tokens before calling emit_verdict")

    tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
    if not tool_use_blocks or tool_use_blocks[0].name != "emit_verdict":
        raise SchemaValidationError("reporter did not call emit_verdict")
    return tool_use_blocks[0].input


# ---------------------------------------------------------------------------- full flow


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
    prior_block = _prior_analyst_decisions_block(ctx)
    prior_suffix = f"\n\n{prompts.wrap_prior_analyst_decisions(prior_block)}" if prior_block else ""

    findings_raw = _run_tool_role(
        caller=caller,
        ctx=ctx,
        role="investigator",
        system_prompt=prompts.INVESTIGATOR_SYSTEM_PROMPT,
        first_user_content=incident_context + prior_suffix,
        investigation_tools=INVESTIGATOR_TOOLS,
        terminal_tool=build_submit_findings_tool(),
        budget=budget,
        deadline=deadline,
        trace=trace,
        usage=usage,
        model=model,
        effort=INVESTIGATOR_EFFORT,
    )
    try:
        InvestigationFindings.model_validate(findings_raw)
    except ValidationError as exc:
        raise SchemaValidationError(f"investigator submit_findings invalid: {exc}") from exc

    rebuttal_raw = _run_tool_role(
        caller=caller,
        ctx=ctx,
        role="devils_advocate",
        system_prompt=prompts.DEVILS_ADVOCATE_SYSTEM_PROMPT,
        first_user_content=incident_context
        + "\n\n"
        + prompts.wrap_investigator_findings(findings_raw),
        investigation_tools=DEVILS_ADVOCATE_TOOLS,
        terminal_tool=build_submit_rebuttal_tool(),
        budget=budget,
        deadline=deadline,
        trace=trace,
        usage=usage,
        model=model,
        effort=DEVILS_ADVOCATE_EFFORT,
    )
    try:
        Rebuttal.model_validate(rebuttal_raw)
    except ValidationError as exc:
        raise SchemaValidationError(f"devils_advocate submit_rebuttal invalid: {exc}") from exc

    reporter_content = (
        incident_context
        + "\n\n"
        + prompts.wrap_investigator_findings(findings_raw)
        + "\n\n"
        + prompts.wrap_rebuttal(rebuttal_raw)
        + prior_suffix
    )
    verdict_raw = _run_reporter(
        caller=caller,
        system_prompt=prompts.REPORTER_SYSTEM_PROMPT,
        user_content=reporter_content,
        model=model,
        deadline=deadline,
        usage=usage,
    )
    trace.append(
        ToolTraceEntry(
            role="reporter",
            tool_name="emit_verdict",
            tool_input=verdict_raw,
            summary="final verdict",
        )
    )

    try:
        verdict = TriageVerdictOut.model_validate(verdict_raw)
    except ValidationError as exc:
        raise SchemaValidationError(f"reporter emit_verdict invalid: {exc}") from exc

    # docs/v2_migration change 3: hard rejection, not a warning -- see app.agent.verifier's own
    # docstring for why this gets different treatment from citation verification below. Checked
    # here (inside _run_flow, before the caller sees a "successful" verdict) so the exception
    # flows through triage_incident's existing AgentTimeoutError/AgentRefusalError/
    # SchemaValidationError/ToolError handling and produces a needs_review fallback with the
    # failure reason recorded, exactly like every other way this flow can fail to produce a
    # trustworthy verdict.
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


# ---------------------------------------------------------------------------- public entry points


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
) -> TriageVerdictOut:
    return TriageVerdictOut(
        disposition="needs_review",
        threat_confidence="low",
        threat_confidence_reason=(
            f"Triage did not complete, so there is no hypothesis-evaluation judgment to report: "
            f"{reason}"
        ),
        # Still the incident's own, untouched value (app.agent.context.AgentContext.
        # anomaly_confidence) -- a failed run never had a chance to change it, and this field is
        # never persisted onto triage_verdicts regardless (TriageVerdictOut's own docstring).
        anomaly_confidence=anomaly_confidence,
        llm_severity_opinion=None,
        mitre_techniques=(),
        summary=f"Triage did not complete: {reason}",
        narrative=(),
        contradicting_evidence=f"Investigation could not be completed to weigh a counter-case: {reason}",
        recommended_actions=(),
        tool_trace=tuple(trace),
        citation_valid=True,
        invalid_citations=(),
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
    """docs/v2_migration change 12 ("surface spend per analysis"): every persisted verdict's
    real per-call cost (`app.agent.client.estimate_cost_usd`) rolls up into
    `analyses.llm_cost_usd`, which `GET /api/analyses/{id}` already exposes
    (`app.schemas.uploads.AnalysisOut`) — this is the write side that was missing. An atomic
    `UPDATE ... SET x = x + delta` rather than read-modify-write so concurrent triage runs
    against the same analysis (not how this codebase drives triage today —
    `triage_top_incidents_for_analysis` triages sequentially — but not guaranteed to stay that
    way) can never lose an increment to a last-write-wins race. Skipped for zero/None cost
    (inherited-recurrence verdicts, `_persist_inherited`, cost 0 by construction) to avoid a
    pointless write."""
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


def _persist_inherited(
    session: Session, incident_id: uuid.UUID, parent: TriageVerdict
) -> TriageVerdict:
    """docs/07 "Scope discipline": "Recurrences are skipped and inherit their parent's
    verdict." No LLM call, no cost — the inherited row's `tool_trace` records the inheritance
    itself so the provenance is visible in the UI rather than looking like an independent run."""
    row = TriageVerdict(
        incident_id=incident_id,
        disposition=parent.disposition,
        threat_confidence=parent.threat_confidence,
        threat_confidence_reason=parent.threat_confidence_reason,
        llm_severity_opinion=parent.llm_severity_opinion,
        mitre_techniques=parent.mitre_techniques,
        summary=parent.summary,
        narrative=parent.narrative,
        contradicting_evidence=parent.contradicting_evidence,
        recommended_actions=parent.recommended_actions,
        tool_trace=[
            {
                "role": "system",
                "tool_name": "inherit_recurrence",
                "tool_input": {
                    "parent_verdict_id": str(parent.id),
                    "parent_incident_id": str(parent.incident_id),
                },
                "is_error": False,
                "summary": f"inherited disposition from recurrence parent verdict {parent.id}",
            }
        ],
        citation_valid=parent.citation_valid,
        invalid_citations=parent.invalid_citations,
        model=f"inherited:{parent.model}",
        tokens_in=0,
        tokens_out=0,
        cost_usd=Decimal("0"),
        latency_ms=0,
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
) -> TriageVerdict:
    """Triage one incident end to end and persist the verdict. Idempotent by default: if a
    verdict already exists and `force` is false, it is returned unchanged rather than
    re-triaged (re-running costs real money — CLAUDE.md "Budget discipline" — and a caller that
    wants a fresh opinion says so explicitly).

    Dispatch order:
    1. Existing verdict (unless `force`) — return it.
    2. Recurrence with an already-triaged parent — inherit, no API call (docs/07 scope discipline).
    3. Otherwise, the real three-role flow — raises `MissingAPIKeyError` if no `caller` was
       injected and `Settings.anthropic_api_key` is unset (docs/v2_migration change 12: no more
       silent demo-verdict fallback).
    """
    settings = get_settings()

    if not force:
        existing = _latest_verdict(session, incident_id)
        if existing is not None:
            return existing

    with tenant_scope(session, tenant_id):
        incident = session.get(Incident, incident_id)
        if incident is None:
            raise AgentContextError(f"incident {incident_id} not found for tenant {tenant_id}")
        recurrence_of = incident.recurrence_of

    if recurrence_of is not None:
        parent_verdict = _latest_verdict(session, recurrence_of)
        if parent_verdict is not None:
            log.info(
                "agent.triage_inherited",
                incident_id=str(incident_id),
                parent_incident_id=str(recurrence_of),
            )
            return _persist_inherited(session, incident_id, parent_verdict)
        # Parent has no verdict of its own yet (not triaged, or outside the top-N window) —
        # fall through and triage this incident on its own merits rather than blocking on it.

    if caller is None and not settings.llm_enabled:
        raise MissingAPIKeyError

    ctx = build_agent_context(session, tenant_id, incident_id)
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
    Recurrences among them inherit rather than re-triage (`triage_incident` handles that per
    incident). Returns one verdict per incident, in the same fused_score-descending order."""
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
    return [
        triage_incident(session, tenant_id, incident_id, caller=caller, force=force)
        for incident_id in incident_ids
    ]
