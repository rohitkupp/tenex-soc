"""Anthropic API access — the one place `client.messages.create(...)` is actually called, and
the one place fixture recording/replay happens (docs/07 "Determinism"; CLAUDE.md's build brief
"9. Recorded fixtures — CI must never need a key").

## The docs/07 correction this milestone is authorized to make

docs/07 says `temperature=0` for determinism. **That is wrong for the model this build targets.**
Sampling parameters (`temperature`, `top_p`, `top_k`) are removed on `claude-opus-5` — sending
`temperature` returns a 400. `LiveCaller.create` below never sends it, under any circumstance;
`docs/07-AGENT.md`'s "Determinism" section has been corrected to say so (the one doc edit this
package is authorized to make). Determinism instead comes from schema-validated tool output
(`app.agent.schemas`) plus recorded fixtures (`FixtureCaller` below) — never from the sampling
parameters themselves, which were never a real determinism guarantee on any model (nothing
`temperature=0` promises "byte-identical output" — see `shared/error-codes.md` in the
claude-api skill).

## Recording format

A fixture file (`tests/fixtures/llm/<name>.json`) is `{"responses": [<Message dict>, ...]}` —
one entry per `messages.create` call, in call order, each the exact `Message.model_dump(mode=
"json")` of a real response. `FixtureCaller` replays them in order via
`anthropic.types.Message.model_validate(...)`, so a replayed response is indistinguishable, at
the attribute-access level the orchestrator uses (`.stop_reason`, `.content[i].type`, `.usage`,
...), from a live one. `RecordingCaller` wraps a live caller and writes the growing list after
every call, so a run that fails partway through still leaves a usable partial fixture on disk
rather than losing every call that succeeded before the failure.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any, Final, Protocol, cast

import anthropic
from anthropic.types import Message

__all__ = [
    "MIN_CACHEABLE_PREFIX_TOKENS",
    "FixtureCaller",
    "FixtureExhaustedError",
    "LLMCaller",
    "LiveCaller",
    "RecordingCaller",
    "estimate_cost_usd",
]

# Claude Opus 5 pricing, per the claude-api skill's cached rate card (SKILL.md "Current Models"):
# $5.00 / 1M input tokens, $25.00 / 1M output tokens. Cache write/read multipliers are the
# standard ones documented in shared/prompt-caching.md (1.25x write for the default 5-minute
# TTL, 0.1x read). `LiveCaller.create` below now actually sets `cache_control` (see its own
# docstring) -- these multipliers are what make `estimate_cost_usd` charge the real, cheaper
# rate for the tokens that landed in cache instead of silently over-reporting cost at the full
# input rate.
_INPUT_RATE_PER_MTOK = Decimal("5.00")
_OUTPUT_RATE_PER_MTOK = Decimal("25.00")
_CACHE_WRITE_MULTIPLIER = Decimal("1.25")
_CACHE_READ_MULTIPLIER = Decimal("0.1")
_MTOK = Decimal(1_000_000)

# claude-api skill, shared/prompt-caching.md: minimum cacheable prefix for claude-opus-5 is 512
# tokens (down from 1024 on Opus 4.8) -- a `cache_control` marker on a shorter block is a silent
# no-op (`cache_creation_input_tokens` stays 0, no error). Every one of `app.agent.prompts`'
# five system prompts is 4.8k-7.4k chars -- at a deliberately conservative 5 chars/token estimate
# (real English/JSON text runs closer to ~4, so this under-counts tokens, never over-counts) the
# smallest still clears roughly 950 estimated tokens, comfortably above this floor before even
# counting the tool schemas the same breakpoint also covers; the incident-context block Analyst
# additionally caches (`app.agent.orchestrator._run_tool_role`) runs tens of thousands of chars.
# See `tests/test_agent_prompt_caching.py::test_system_prompts_clear_min_cacheable_prefix`.
MIN_CACHEABLE_PREFIX_TOKENS = 512

_CACHE_CONTROL_EPHEMERAL: Final[dict[str, str]] = {"type": "ephemeral"}


def estimate_cost_usd(usage: Any) -> Decimal:
    """`usage` is an `anthropic.types.Usage` (or anything with the same four attributes, e.g. a
    running total accumulated across several turns). Cache fields default to 0 when unset."""
    input_tokens = Decimal(getattr(usage, "input_tokens", 0) or 0)
    output_tokens = Decimal(getattr(usage, "output_tokens", 0) or 0)
    cache_creation = Decimal(getattr(usage, "cache_creation_input_tokens", 0) or 0)
    cache_read = Decimal(getattr(usage, "cache_read_input_tokens", 0) or 0)

    cost = (
        input_tokens * _INPUT_RATE_PER_MTOK
        + output_tokens * _OUTPUT_RATE_PER_MTOK
        + cache_creation * _INPUT_RATE_PER_MTOK * _CACHE_WRITE_MULTIPLIER
        + cache_read * _INPUT_RATE_PER_MTOK * _CACHE_READ_MULTIPLIER
    ) / _MTOK
    return cost.quantize(Decimal("0.000001"))


class LLMCaller(Protocol):
    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: dict[str, Any] | None = None,
        effort: str = "medium",
    ) -> Message: ...


@dataclass(slots=True)
class LiveCaller:
    """Real `POST /v1/messages`, real spend. `api_key` is threaded in explicitly (rather than
    relying on the SDK's ambient `ANTHROPIC_API_KEY` env-var resolution) so the orchestrator's
    own no-key check (`app.agent.orchestrator.MissingAPIKeyError`, gated on
    `app.core.config.Settings.llm_enabled`) is the only place that decides whether this class
    is ever constructed at all.

    ## Prompt caching (`cache_control`)

    Every one of the five roles (Analyst, Judge, Presenter, Narrator, domain-semantic) calls
    this class with its own static `system` prompt (`app.agent.prompts`) and its own static
    `tools` list -- both are Python module-level constants / pure functions of no per-call
    input, byte-identical on every call for a given role, across every incident this process
    ever triages. `create` below marks the `system` block `cache_control: {"type": "ephemeral"}`
    (5-minute TTL), which — per the claude-api skill's caching docs, "render order is tools ->
    system -> messages; a breakpoint on the last system block caches both tools and system
    together" — caches the *entire* tools+system prefix as one unit for every role in one
    marker. The first call for a given role within the TTL pays the ~1.25x cache-write premium;
    every subsequent call for that same role (the Analyst's own next tool-loop turn, or the next
    incident's Judge/Presenter/Narrator/domain-semantic call, or the next incident's Analyst
    call) reads it back at ~0.1x instead of full price. `MIN_CACHEABLE_PREFIX_TOKENS` documents
    why every one of these blocks is safely above the model's minimum cacheable size.

    ## Why the incident-context block is *not* also marked here

    The obvious next target is the large, literally-shared incident-context block
    (`app.agent.orchestrator._build_incident_context_block`) that opens the Analyst's, Judge's,
    and Presenter's first user turn for a given incident. It is **not** cached at this layer,
    and deliberately not cached at all for Judge/Presenter/Narrator/domain-semantic — see
    `app.agent.orchestrator._run_tool_role`'s own docstring for why (short version: caching is a
    strict prefix match through tools -> system -> messages, each role's `system` differs, and a
    differing `system` invalidates every cache tier after it — so the identical incident-context
    bytes sitting behind Judge's or Presenter's own distinct `system` can never be served from
    the Analyst's cache entry no matter how the marker is placed, without rewriting the prompts
    themselves, which this change is not authorized to do). Marking it here anyway would only
    add the write premium with no matching read for those two roles. The Analyst's own
    tool-calling loop is the one place a repeat read is real, and that block lives in
    `messages[0]`, which `app.agent.orchestrator._run_tool_role` — not this class — constructs;
    see that function for the marker on the incident-context block itself.
    """

    api_key: str
    _client: anthropic.Anthropic = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._client = anthropic.Anthropic(api_key=self.api_key)

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: dict[str, Any] | None = None,
        effort: str = "medium",
    ) -> Message:
        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            # Wrapped as a one-block list, not the bare string, purely to carry `cache_control`
            # — the text the model receives is unchanged either way (the Messages API treats a
            # plain string and a single-block `[{"type": "text", "text": ...}]` list
            # identically). See this class's own docstring for why this is the one marker set
            # here, and why every role benefits from it even though `system` differs per role.
            "system": [{"type": "text", "text": system, "cache_control": _CACHE_CONTROL_EPHEMERAL}],
            "messages": messages,
            # "medium" balances quality against CLAUDE.md's "use sparingly" budget discipline —
            # see orchestrator.py's module docstring for the per-role reasoning. Never
            # temperature/top_p/top_k — see this module's docstring. Claude Opus 5 is on
            # adaptive thinking by default; omitting `thinking` entirely is correct and is what
            # every call below does.
            "output_config": {"effort": effort},
        }
        if tools:
            kwargs["tools"] = tools
        if tool_choice:
            kwargs["tool_choice"] = tool_choice
        # **kwargs erases the SDK's overload resolution (stream=True/False), which is what
        # actually pins the return type to Message vs Stream[...] — this call never sets
        # `stream`, so it always resolves to the non-streaming Message overload at runtime.
        return cast(Message, self._client.messages.create(**kwargs))


class FixtureExhaustedError(RuntimeError):
    """A test tried to make more `messages.create` calls than the fixture has recorded
    responses for. Almost always means the orchestrator's tool-call-budget logic changed since
    the fixture was recorded — re-record with `--record`, don't hand-edit the fixture file."""


@dataclass(slots=True)
class FixtureCaller:
    """Replays a recorded conversation deterministically. CI's whole reason for existing here:
    no network call, no API key, byte-identical `Message` objects every run."""

    path: Path
    _responses: list[dict[str, Any]] = field(init=False, repr=False)
    _index: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self._responses = data["responses"]

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: dict[str, Any] | None = None,
        effort: str = "medium",
    ) -> Message:
        if self._index >= len(self._responses):
            raise FixtureExhaustedError(
                f"{self.path} has only {len(self._responses)} recorded responses; "
                f"call {self._index + 1} was requested"
            )
        raw = self._responses[self._index]
        self._index += 1
        return Message.model_validate(raw)


@dataclass(slots=True)
class RecordingCaller:
    """Wraps a `LiveCaller`, appends every real response to `path` in `Message.model_dump`
    form after each call (not just at the end) so a run that dies partway through still leaves
    a usable, replayable partial fixture — `--record` is meant to be run against a small, known
    number of incidents (CLAUDE.md "Budget discipline"), and losing a fixture because the last
    of several calls errored would waste the spend already made on the earlier ones."""

    inner: LiveCaller
    path: Path
    _responses: list[dict[str, Any]] = field(default_factory=list, init=False)

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: dict[str, Any] | None = None,
        effort: str = "medium",
    ) -> Message:
        response = self.inner.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
            tools=tools,
            tool_choice=tool_choice,
            effort=effort,
        )
        self._responses.append(response.model_dump(mode="json"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"responses": self._responses}, indent=2, default=str), encoding="utf-8"
        )
        return response
