"""Prompt caching (`cache_control`) — `app.agent.client.LiveCaller` and
`app.agent.orchestrator._run_tool_role`.

Three things this file proves, matching the three deliverables of the caching change itself:

1. `cache_control` markers land exactly where intended: the `system` block on every real
   `LiveCaller.create` call (all five roles), plus the Analyst's own first user message
   (`_run_tool_role`, tool-calling loop only) — and nowhere else.
2. The assembled prompt is unchanged wherever a marker was added — stripping `cache_control` and
   unwrapping a single-text-block list back to a bare string recovers byte-identical text to what
   the pre-caching code sent. This is the same round-trip this package's own before/after payload
   diff used to prove the change (see the migration report); here it is pinned as a regression
   test so a future edit cannot silently start mutating prompt text under the caching wrapper.
3. Cost accounting (`estimate_cost_usd`) prices `cache_creation_input_tokens` at the write
   multiplier and `cache_read_input_tokens` at the read multiplier, not at the full input rate.

No live API calls anywhere in this file — every `LiveCaller.create` call here has its underlying
SDK method monkeypatched to a stub that never touches the network, per CLAUDE.md's "tests must
never need a key" and this task's "DO NOT make live API calls" constraint.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from anthropic.types import Message

from app.agent import prompts
from app.agent.client import (
    _MODEL_RATES,
    LiveCaller,
    estimate_cost_usd,
    min_cacheable_prefix_tokens,
    model_rates,
)
from app.agent.orchestrator import ANALYST_TOOLS, triage_incident
from app.agent.schemas import build_present_verdict_tool, build_submit_judgement_tool
from app.core.db import get_session_factory
from app.detection.evidence.payload import EvidencePayload
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.agent import make_event
from tests.fixtures.response import make_incident, make_signal

WINDOW_START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
WINDOW_END = WINDOW_START + timedelta(hours=1)

# The five system prompts every real LiveCaller.create call is built from — see
# app.agent.prompts's own module docstring: none is built from an f-string touching incident
# data, so each is a fixed, cacheable string.
_ALL_SYSTEM_PROMPTS = (
    prompts.ANALYST_SYSTEM_PROMPT,
    prompts.JUDGE_SYSTEM_PROMPT,
    prompts.PRESENTER_SYSTEM_PROMPT,
    prompts.NARRATOR_SYSTEM_PROMPT,
    prompts.DOMAIN_SEMANTIC_SYSTEM_PROMPT,
)

_ANY_MESSAGE = Message.model_validate(
    {
        "id": "msg_stub",
        "content": [],
        "model": "claude-opus-5",
        "role": "assistant",
        "stop_reason": "max_tokens",
        "stop_sequence": None,
        "type": "message",
        "usage": {"input_tokens": 10, "output_tokens": 1},
    }
)


def _count_cache_control(obj: Any) -> int:
    """Recursively count `cache_control` occurrences anywhere in a request payload — the
    Anthropic API caps this at 4 per request (`shared/prompt-caching.md`, "Max 4 breakpoints")."""
    if isinstance(obj, dict):
        return ("cache_control" in obj) + sum(_count_cache_control(v) for v in obj.values())
    if isinstance(obj, list):
        return sum(_count_cache_control(v) for v in obj)
    return 0


# ---------------------------------------------------------------------------- LiveCaller (no DB)


def test_live_caller_wraps_system_as_cached_block(monkeypatch: pytest.MonkeyPatch) -> None:
    """The one marker every role's real call gets: `system` becomes a one-block list with
    `cache_control: {"type": "ephemeral"}` — never a raw string once it reaches the SDK."""
    caller = LiveCaller(api_key="sk-ant-not-a-real-key")
    captured: dict[str, Any] = {}

    def fake_create(**kwargs: Any) -> Message:
        captured.update(kwargs)
        return _ANY_MESSAGE

    monkeypatch.setattr(caller._client.messages, "create", fake_create)

    caller.create(
        model="claude-opus-5",
        max_tokens=8192,
        system=prompts.JUDGE_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": "hello"}],
        tools=[build_submit_judgement_tool()],
        tool_choice={"type": "tool", "name": "submit_judgement"},
        effort="medium",
    )

    assert captured["system"] == [
        {
            "type": "text",
            "text": prompts.JUDGE_SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }
    ]


def test_live_caller_system_cache_control_text_is_byte_identical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Round-trip proof: strip `cache_control` and unwrap the single-block list, and the
    recovered text equals the original `system` string exactly — the wrapper carries the marker,
    it does not touch a single character of the prompt."""
    caller = LiveCaller(api_key="sk-ant-not-a-real-key")
    captured: dict[str, Any] = {}

    def fake_create(**kwargs: Any) -> Message:
        captured.update(kwargs)
        return _ANY_MESSAGE

    monkeypatch.setattr(caller._client.messages, "create", fake_create)

    for system_prompt in _ALL_SYSTEM_PROMPTS:
        captured.clear()
        caller.create(
            model="claude-opus-5",
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": "x"}],
        )
        blocks = captured["system"]
        assert len(blocks) == 1
        assert blocks[0]["type"] == "text"
        assert blocks[0]["text"] == system_prompt  # byte-identical, not just equal length


def test_live_caller_does_not_add_cache_control_to_messages_or_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`LiveCaller.create` only ever marks `system`. Whatever `messages`/`tools` shape it is
    handed passes through completely unmodified — no marker added, no key changed. This is what
    lets `_run_tool_role` (orchestrator.py) be the *only* place a messages-level marker appears,
    and only for the Analyst — see that function's own docstring."""
    caller = LiveCaller(api_key="sk-ant-not-a-real-key")
    captured: dict[str, Any] = {}

    def fake_create(**kwargs: Any) -> Message:
        captured.update(kwargs)
        return _ANY_MESSAGE

    monkeypatch.setattr(caller._client.messages, "create", fake_create)

    messages_in = [{"role": "user", "content": "plain string, unmarked"}]
    tools_in = [build_present_verdict_tool()]
    caller.create(
        model="claude-opus-5",
        max_tokens=1024,
        system=prompts.PRESENTER_SYSTEM_PROMPT,
        messages=messages_in,
        tools=tools_in,
        tool_choice={"type": "tool", "name": "present_verdict"},
    )

    assert captured["messages"] == messages_in
    assert _count_cache_control(captured["messages"]) == 0
    assert captured["tools"] == tools_in
    assert _count_cache_control(captured["tools"]) == 0


def test_live_caller_real_analyst_call_stays_under_max_breakpoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Analyst's real call shape (full `ANALYST_TOOLS` + terminal tool, plus a cache-marked
    first message the way `_run_tool_role` builds it) carries exactly 2 `cache_control`
    occurrences — 1 on `system`, 1 on the message block — comfortably under the API's 4-breakpoint
    cap, with headroom to spare."""
    caller = LiveCaller(api_key="sk-ant-not-a-real-key")
    captured: dict[str, Any] = {}

    def fake_create(**kwargs: Any) -> Message:
        captured.update(kwargs)
        return _ANY_MESSAGE

    monkeypatch.setattr(caller._client.messages, "create", fake_create)

    caller.create(
        model="claude-opus-5",
        max_tokens=8192,
        system=prompts.ANALYST_SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "<incident context>",
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
            }
        ],
        tools=[*ANALYST_TOOLS, build_submit_judgement_tool()],  # any terminal tool for the count
        tool_choice={"type": "auto"},
    )

    assert _count_cache_control(captured) == 2


# ---------------------------------------------------------------------------- min cacheable prefix


@pytest.mark.parametrize(
    "name",
    [
        "ANALYST_SYSTEM_PROMPT",
        "JUDGE_SYSTEM_PROMPT",
        "PRESENTER_SYSTEM_PROMPT",
        "NARRATOR_SYSTEM_PROMPT",
        "DOMAIN_SEMANTIC_SYSTEM_PROMPT",
    ],
)
@pytest.mark.parametrize("model", sorted(_MODEL_RATES))
def test_system_prompts_clear_min_cacheable_prefix(name: str, model: str) -> None:
    """claude-api skill, shared/prompt-caching.md: a `cache_control` marker on a block below the
    model's minimum cacheable prefix is a silent no-op (no error, just
    `cache_creation_input_tokens: 0` forever).

    Parametrized over *every* model in the rate card, not just the configured one, because the
    floor is model-specific and non-monotonic across generations: Sonnet 5's is 1024, twice Opus
    5's 512. A switch between the two must not be able to silently disable caching, so both are
    asserted at all times and adding a model to `_MODEL_RATES` automatically extends this guard.

    No live call is allowed here (CI must never need a key), so this estimates from character
    count. The 4-chars-per-token divisor is still deliberately conservative -- these prompts were
    measured against the real tokenizer at ~3.1 chars/token (1,546 tokens for the smallest,
    `DOMAIN_SEMANTIC_SYSTEM_PROMPT`) -- so the bound under-states the true count and keeps the
    assertion safe in the direction that matters: a false *pass* would mean caching silently
    no-ops in production. The previous 5-chars-per-token divisor was over-conservative to the
    point of being misleading, estimating that same prompt at 969 tokens and making it look like
    it failed a 1024 floor it in fact clears by 50%.
    """
    text = getattr(prompts, name)
    conservative_token_estimate = len(text) // 4
    floor = min_cacheable_prefix_tokens(model)
    assert conservative_token_estimate > floor, (
        f"{name} is only ~{conservative_token_estimate} conservative-estimated tokens "
        f"({len(text)} chars) — too close to {model}'s {floor}-token minimum "
        "for the cache_control marker on it to reliably take effect"
    )


# ---------------------------------------------------------------------------- orchestrator-level


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
            "usage": {"input_tokens": 500, "output_tokens": 100},
        }
    )


_ANALYSIS_TOOL_INPUT: dict[str, Any] = {
    "hypothesis_evaluations": [
        {
            "technique_id": "NO_KNOWN_MAPPING",
            "evidence_for": [],
            "evidence_against": [{"text": "No corroborating evidence.", "evidence_ids": []}],
            "missing_evidence": [],
            "assessment": "unsupported",
            "threat_confidence": "low",
        }
    ],
    "findings": [
        {
            "finding_id": "FINDING-1",
            "anomaly_ids": ["EVIDENCE-1"],
            "observation": "63 requests observed at regular intervals.",
            "hypothesis": "No known technique fits this pattern.",
            "supporting_evidence_ids": ["EVIDENCE-1"],
            "contradicting_evidence_ids": [],
            "missing_evidence": [],
            "attack_technique_id": "NO_KNOWN_MAPPING",
            "attack_source_id": None,
            "threat_confidence": "low",
            "confidence_reason": "Evidence is too thin to map to a known technique.",
            "benign_alternatives": ["Could be a scheduled health-check job."],
        }
    ],
}
_JUDGEMENT_TOOL_INPUT: dict[str, Any] = {
    "verdicts": [
        {
            "finding_id": "FINDING-1",
            "decision": "PASS",
            "rubric_assessment": [
                {"item": i, "satisfied": True, "note": "checked"} for i in range(1, 11)
            ],
            "rationale": "Evidence is well-cited and proportionate.",
            "revised_finding": None,
        }
    ]
}


def _verdict_tool_input(*, anomaly_confidence: float) -> dict[str, Any]:
    return {
        "disposition": "benign",
        "threat_confidence": "low",
        "threat_confidence_reason": "No corroborating evidence.",
        "anomaly_confidence": anomaly_confidence,
        "llm_severity_opinion": "low",
        "mitre_techniques": [],
        "summary": "Unexplained anomaly, not malicious.",
        "narrative": [
            {
                "step": 1,
                "claim": "63 requests observed at regular intervals.",
                "evidence_ids": ["EVIDENCE-1"],
            }
        ],
        "contradicting_evidence": "No corroborating evidence found.",
        "recommended_actions": ["Confirm expected behavior with the user."],
    }


class _RecordingCaller:
    """Scripted `LLMCaller` -- same shape as `tests/test_agent_orchestrator.py`'s own, kept
    self-contained here rather than imported cross-module (this file only needs a minimal,
    always-NO_KNOWN_MAPPING script, not that module's rich per-scenario builders)."""

    def __init__(self, *, anomaly_confidence: float) -> None:
        self._anomaly_confidence = anomaly_confidence
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Message:
        self.calls.append(kwargs)
        tool_choice = kwargs.get("tool_choice") or {}
        name = tool_choice.get("name")
        if name is None and tool_choice.get("type") == "auto":
            name = "submit_analysis"  # Analyst: go straight to submit_analysis, no investigation
        if name == "submit_analysis":
            return _tool_message(tool_name="submit_analysis", tool_input=_ANALYSIS_TOOL_INPUT)
        if name == "submit_judgement":
            return _tool_message(tool_name="submit_judgement", tool_input=_JUDGEMENT_TOOL_INPUT)
        if name == "present_verdict":
            return _tool_message(
                tool_name="present_verdict",
                tool_input=_verdict_tool_input(anomaly_confidence=self._anomaly_confidence),
            )
        raise AssertionError(f"unscripted tool_choice in caching test: {tool_choice!r}")


def _setup_incident(cleanup: list[uuid.UUID]) -> tuple[Any, Any, EvidencePayload]:
    tenant = make_tenant()
    cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"{uuid.uuid4()}@example.com")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    events = [
        make_event(
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            ts=WINDOW_START + timedelta(minutes=i),
            raw_line_no=3000 + i,
            principal="bob@corp.example",
            domain="another-rare-destination.example",
            bytes_out=100,
        )
        for i in range(3)
    ]
    signal = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="user",
        entity_value="bob@corp.example",
        detector_key="signal.beaconing",
        evidence_event_ids=[e.id for e in events],
        explanation={"interval_s": 60, "cv": 0.02},
    )
    incident = make_incident(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signal_ids=[signal.id],
        title="Caching test incident",
        severity="high",
        fused_score=0.9,
    )
    payload = EvidencePayload(
        evidence_id="EVIDENCE-1",
        extractor="beaconing",
        entity={"type": "user", "value": "bob@corp.example"},
        window=(WINDOW_START, WINDOW_END),
        measurements={"requests": 63, "bytes_out": 1_800_000_000.0},
        historical={"beaconing_percentile": 99.7},
        contributing_line_numbers=[e.raw_line_no for e in events],
        nominates_candidate=False,
    )
    return tenant, incident, payload


def test_analyst_first_message_carries_cache_control_judge_and_presenter_do_not(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """The intended breakpoint layout, proven end to end through a real `triage_incident` run:
    the Analyst's own first user turn (`_run_tool_role`) is a one-block cached list; Judge's and
    Presenter's first (and only) user turns (`_run_notool_role`, never touched by this change)
    are still plain strings with no `cache_control` anywhere -- see
    `app.agent.orchestrator._run_tool_role`'s docstring for why marking those would only add the
    write premium with nothing to read it back."""
    tenant, incident, payload = _setup_incident(tenant_cleanup)
    expected = round(incident.anomaly_confidence, 1)
    caller = _RecordingCaller(anomaly_confidence=expected)

    session = get_session_factory()()
    try:
        triage_incident(session, tenant.id, incident.id, caller=caller, evidence_payloads=[payload])
    finally:
        session.close()

    assert len(caller.calls) == 3  # Analyst, Judge, Presenter

    analyst_call, judge_call, presenter_call = caller.calls

    # Analyst: messages[0]["content"] is the one-block cached list.
    analyst_content = analyst_call["messages"][0]["content"]
    assert isinstance(analyst_content, list)
    assert len(analyst_content) == 1
    assert analyst_content[0]["type"] == "text"
    assert analyst_content[0]["cache_control"] == {"type": "ephemeral"}
    assert "<untrusted_log_data>" in analyst_content[0]["text"]

    # Judge and Presenter: unchanged plain-string first turn, no cache_control anywhere.
    for call in (judge_call, presenter_call):
        content = call["messages"][0]["content"]
        assert isinstance(content, str)
        assert _count_cache_control(call["messages"]) == 0

    # Orchestrator-level calls never touch `system` at all -- that wrapping happens only inside
    # `LiveCaller.create` (a real SDK boundary), which `_RecordingCaller` here deliberately
    # bypasses, exactly like `tests/test_agent_orchestrator.py`'s own scripted caller does. Every
    # call's `system` therefore arrives as the plain prompt string, proving the orchestrator
    # itself never mutates `system` -- only `LiveCaller.create` does, per its own docstring.
    assert analyst_call["system"] == prompts.ANALYST_SYSTEM_PROMPT
    assert judge_call["system"] == prompts.JUDGE_SYSTEM_PROMPT
    assert presenter_call["system"] == prompts.PRESENTER_SYSTEM_PROMPT


def test_analyst_cached_incident_context_text_matches_uncached_baseline(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    """Round-trip proof at the orchestrator level: the text inside the Analyst's cached block is
    exactly the same string Judge and Presenter receive as a plain, unwrapped user turn for the
    *shared* incident-context portion -- i.e. wrapping it for caching didn't drop, reorder, or
    alter a single character of it."""
    tenant, incident, payload = _setup_incident(tenant_cleanup)
    expected = round(incident.anomaly_confidence, 1)
    caller = _RecordingCaller(anomaly_confidence=expected)

    session = get_session_factory()()
    try:
        triage_incident(session, tenant.id, incident.id, caller=caller, evidence_payloads=[payload])
    finally:
        session.close()

    analyst_call, judge_call, _presenter_call = caller.calls
    analyst_text = analyst_call["messages"][0]["content"][0]["text"]
    judge_text = judge_call["messages"][0]["content"]

    # Judge's own first turn is `incident_context + "\n\n" + wrap_analyst_output(...)` — the
    # incident_context is its own prefix, byte-identical to the Analyst's (see
    # `app.agent.orchestrator._run_flow`: both are built from the same `incident_context`
    # variable, computed once). Assert the Analyst's cached text IS that shared prefix.
    assert judge_text.startswith(analyst_text)


# ---------------------------------------------------------------------------- cost accounting


class _Usage:
    """Minimal stand-in for `anthropic.types.Usage` — `estimate_cost_usd` only reads these four
    attributes via `getattr`, so a plain object with them is sufficient and avoids constructing a
    full SDK `Usage` (which requires a live-response-shaped payload)."""

    def __init__(
        self,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_creation_input_tokens: int = 0,
        cache_read_input_tokens: int = 0,
    ) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cache_creation_input_tokens = cache_creation_input_tokens
        self.cache_read_input_tokens = cache_read_input_tokens


# Published list rates from the claude-api skill's rate card (SKILL.md "Current Models"), written
# out as literals rather than read from `_MODEL_RATES` so that this genuinely pins the table to
# the rate card. Deriving the expectation from the table under test would make these tautologies
# that pass no matter how wrong the numbers get. Sonnet 5's $2/$10 introductory rate through
# 2026-08-31 is deliberately not encoded -- see `_MODEL_RATES`' comment on why the app prices at
# list.
_PUBLISHED_RATES = [
    ("claude-opus-5", Decimal("5.00"), Decimal("25.00")),
    ("claude-sonnet-5", Decimal("3.00"), Decimal("15.00")),
]


@pytest.mark.parametrize(("model", "input_rate", "output_rate"), _PUBLISHED_RATES)
def test_estimate_cost_usd_prices_cache_write_at_1_25x_input_rate(
    model: str, input_rate: Decimal, output_rate: Decimal
) -> None:
    """A cache-write token costs 25% more than a fresh input token, never the same and never
    less -- at whichever model's input rate applies."""
    fresh = estimate_cost_usd(_Usage(input_tokens=1_000_000), model=model)
    written = estimate_cost_usd(_Usage(cache_creation_input_tokens=1_000_000), model=model)
    assert fresh == input_rate.quantize(Decimal("0.000001"))
    assert written == (input_rate * Decimal("1.25")).quantize(Decimal("0.000001"))
    assert written == fresh * Decimal("1.25")


@pytest.mark.parametrize(("model", "input_rate", "output_rate"), _PUBLISHED_RATES)
def test_estimate_cost_usd_prices_cache_read_at_0_1x_input_rate(
    model: str, input_rate: Decimal, output_rate: Decimal
) -> None:
    """A cache-read token costs a tenth of a fresh input token. This is the multiplier that makes
    the whole optimization pay off."""
    fresh = estimate_cost_usd(_Usage(input_tokens=1_000_000), model=model)
    read = estimate_cost_usd(_Usage(cache_read_input_tokens=1_000_000), model=model)
    assert fresh == input_rate.quantize(Decimal("0.000001"))
    assert read == (input_rate * Decimal("0.1")).quantize(Decimal("0.000001"))
    assert read == fresh * Decimal("0.1")


@pytest.mark.parametrize(("model", "input_rate", "output_rate"), _PUBLISHED_RATES)
def test_estimate_cost_usd_sums_all_four_token_classes(
    model: str, input_rate: Decimal, output_rate: Decimal
) -> None:
    """A real post-caching response usually carries all three input classes at once (a fresh
    delta, a cache write, and/or a cache read) plus output — `estimate_cost_usd` must price and
    sum every one of them, not just `input_tokens`/`output_tokens`."""
    usage = _Usage(
        input_tokens=1_000,
        output_tokens=200,
        cache_creation_input_tokens=6_000,
        cache_read_input_tokens=44_000,
    )
    expected = (
        Decimal(1_000) * input_rate
        + Decimal(200) * output_rate
        + Decimal(6_000) * input_rate * Decimal("1.25")
        + Decimal(44_000) * input_rate * Decimal("0.1")
    ) / Decimal(1_000_000)
    assert estimate_cost_usd(usage, model=model) == expected.quantize(Decimal("0.000001"))


def test_model_rates_rejects_unknown_model() -> None:
    """An unrecognised model id must raise, not fall back to some default rate. A silent fallback
    is how a model swap keeps billing at the previous model's price -- the exact failure this
    table was introduced to prevent."""
    with pytest.raises(ValueError, match="no rate card for model"):
        model_rates("claude-not-a-real-model")


def test_estimate_cost_usd_matches_pre_caching_behavior_when_cache_fields_absent() -> None:
    """Old fixtures / any `Usage`-like object with no cache fields at all must still price
    correctly (the `getattr(..., 0)` defaults) -- caching must not break cost accounting for
    responses that never used it."""

    class _BareUsage:
        def __init__(self, input_tokens: int, output_tokens: int) -> None:
            self.input_tokens = input_tokens
            self.output_tokens = output_tokens

    bare = _BareUsage(input_tokens=1_000, output_tokens=500)
    full = _Usage(input_tokens=1_000, output_tokens=500)
    # Pinned to Opus 5 explicitly: the point of the assertion is that a missing cache attribute
    # defaults to 0, which needs a fixed rate to compare against, not whichever model happens to
    # be configured.
    assert (
        estimate_cost_usd(bare, model="claude-opus-5")
        == estimate_cost_usd(full, model="claude-opus-5")
        == Decimal("0.017500")
    )
