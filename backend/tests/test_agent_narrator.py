"""`app.agent.orchestrator.narrate_analysis` -- change 14's Path A, the single-call analysis-level
narrative path. No DB needed: `overview`/`incidents`/`timeline_phases` are deterministic,
pre-computed inputs the caller hands in (change 9's "do not ask a model to count 83,241 rows"),
so this module is pure LLM-call-plus-verifier and tests accordingly.
"""

from __future__ import annotations

from typing import Any

from anthropic.types import Message

from app.agent.orchestrator import narrate_analysis


class _RecordingCaller:
    def __init__(self, messages: list[Message]) -> None:
        self._messages = list(messages)
        self._index = 0
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Message:
        self.calls.append(kwargs)
        message = self._messages[self._index]
        self._index += 1
        return message


def _narrate_message(*, executive_summary: str, phase_narratives: list[dict[str, Any]]) -> Message:
    return Message.model_validate(
        {
            "id": "msg_narrate",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_narrate",
                    "name": "narrate_analysis",
                    "input": {
                        "executive_summary": executive_summary,
                        "phase_narratives": phase_narratives,
                    },
                }
            ],
            "model": "claude-opus-5",
            "role": "assistant",
            "stop_reason": "tool_use",
            "stop_sequence": None,
            "type": "message",
            "usage": {"input_tokens": 800, "output_tokens": 150},
        }
    )


_OVERVIEW = {
    "period": ["2026-08-14T09:00Z", "2026-08-14T17:00Z"],
    "events": 83241,
    "users": 127,
    "src_ips": 139,
    "unique_domains": 4921,
    "allowed": 78201,
    "blocked": 5040,
}
_INCIDENTS: list[dict[str, Any]] = [{"id": "inc-1", "severity": "high", "fused_score": 0.91}]
_TIMELINE_PHASES = [
    {
        "phase_index": 0,
        "tactic": "initial-access",
        "summary": "First contact",
        "log_ids": ["LOG-100", "LOG-101"],
    },
    {
        "phase_index": 1,
        "tactic": "exfiltration",
        "summary": "Bulk upload",
        "log_ids": ["LOG-200"],
        "bytes_out": 500,
    },
]


def test_narrate_analysis_makes_exactly_one_call_no_judge() -> None:
    """change 14: "No judge stage. A judge pass over descriptive narrative is not worth the
    call." -- the single call is the whole contract, not an implementation detail to re-derive."""
    caller = _RecordingCaller(
        [
            _narrate_message(
                executive_summary="83,241 events across 127 users were processed between 09:00 and 17:00.",
                phase_narratives=[
                    {
                        "phase_index": 0,
                        "narrative": "First contact with the environment.",
                        "cited_log_ids": ["LOG-100"],
                    },
                    {
                        "phase_index": 1,
                        "narrative": "500 bytes moved out in the exfiltration phase.",
                        "cited_log_ids": ["LOG-200"],
                    },
                ],
            )
        ]
    )

    result = narrate_analysis(
        overview=_OVERVIEW,
        incidents=_INCIDENTS,
        timeline_phases=_TIMELINE_PHASES,
        caller=caller,
        model="claude-opus-5",
    )

    assert len(caller.calls) == 1
    assert result.citation_valid is True
    assert result.invalid_citations == ()
    assert "83,241" in result.executive_summary


def test_narrate_analysis_rejects_mismatched_number() -> None:
    """change 14: "Verifier still runs... descriptive prose hallucinating a byte count is still a
    hallucination.\""""
    caller = _RecordingCaller(
        [
            _narrate_message(
                executive_summary="999,999 events were processed today.",  # not in the overview
                phase_narratives=[],
            )
        ]
    )

    result = narrate_analysis(
        overview=_OVERVIEW,
        incidents=_INCIDENTS,
        timeline_phases=_TIMELINE_PHASES,
        caller=caller,
        model="claude-opus-5",
    )

    assert result.citation_valid is False
    assert result.invalid_citations
    assert result.invalid_citations[0]["section"] == "executive_summary"


def test_narrate_analysis_rejects_phase_citation_outside_its_own_scope() -> None:
    caller = _RecordingCaller(
        [
            _narrate_message(
                executive_summary="83,241 events across 127 users were processed.",
                phase_narratives=[
                    # cites LOG-200 (phase 1's own line) while narrating phase 0 -- out of scope.
                    {"phase_index": 0, "narrative": "First contact.", "cited_log_ids": ["LOG-200"]},
                ],
            )
        ]
    )

    result = narrate_analysis(
        overview=_OVERVIEW,
        incidents=_INCIDENTS,
        timeline_phases=_TIMELINE_PHASES,
        caller=caller,
        model="claude-opus-5",
    )

    assert result.citation_valid is False
    assert any("phase_0" in entry.get("section", "") for entry in result.invalid_citations)
