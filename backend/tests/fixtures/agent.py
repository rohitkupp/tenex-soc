"""Shared, non-test factory helper for `tests/test_agent_*.py` — this milestone's own addition
to the test-fixture-per-owning-module convention `tests/fixtures/response.py` established.

Only `make_event` lives here: `make_tenant`/`make_user`/`make_analysis`/`tenant_cleanup` already
exist in `tests/conftest.py`, and `make_signal`/`make_incident` already exist in
`tests/fixtures/response.py` — both fully generic, nothing response-specific about them, so
agent tests import them directly rather than duplicating. `tenant_cleanup` (conftest.py) is
sufficient for agent tests too, with no changes needed: it explicitly deletes `analyses` before
`uploads`, and `events`/`signals`/`incidents` all carry `ON DELETE CASCADE` back to
`analyses.id` (`app.models.event.Event`, `app.models.signal.Signal`,
`app.models.incident.Incident`), with `triage_verdicts.incident_id` cascading from `incidents.id`
in turn (`app.models.triage_verdict.TriageVerdict`) — deleting `analyses` sweeps the whole chain.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from anthropic.types import Message

from app.core.db import get_session_factory
from app.models.base import tenant_scope
from app.models.event import Event


def make_event(
    *,
    tenant_id: uuid.UUID,
    analysis_id: uuid.UUID,
    ts: datetime,
    raw_line_no: int = 1,
    principal: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    domain: str | None = None,
    url_path: str | None = None,
    action: str | None = "allowed",
    http_method: str | None = "GET",
    status_code: int | None = 200,
    bytes_in: int | None = 100,
    bytes_out: int | None = 100,
    user_agent: str | None = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
    event_key: str | None = None,
    ocsf: dict[str, Any] | None = None,
    hostname: str | None = None,
    device_name: str | None = None,
    device_owner: str | None = None,
    os_type: str | None = None,
    os_version: str | None = None,
    bypassed_traffic: bool | None = None,
    flow_type: str | None = None,
) -> Event:
    """A real `events` row (docs/02) for agent-tool and citation-verifier tests. Every hot
    column defaults to a plausible, boring value so a test only has to override what it cares
    about; `ocsf_class_uid=6003` is OCSF's HTTP Activity class, matching what the ZScaler parser
    (M3) actually emits for proxy events."""
    session = get_session_factory()()
    try:
        with tenant_scope(session, tenant_id):
            event = Event(
                analysis_id=analysis_id,
                tenant_id=tenant_id,
                ts=ts,
                source_type="zscaler",
                raw_line_no=raw_line_no,
                ocsf_class_uid=6003,
                principal=principal,
                src_ip=src_ip,
                dst_ip=dst_ip,
                domain=domain,
                url_path=url_path,
                action=action,
                http_method=http_method,
                status_code=status_code,
                bytes_in=bytes_in,
                bytes_out=bytes_out,
                user_agent=user_agent,
                event_key=event_key,
                ocsf=ocsf or {},
                hostname=hostname,
                device_name=device_name,
                device_owner=device_owner,
                os_type=os_type,
                os_version=os_version,
                bypassed_traffic=bypassed_traffic,
                flow_type=flow_type,
            )
            session.add(event)
            session.commit()
            session.refresh(event)
        return event
    finally:
        session.close()


_MAX_TOKENS_MESSAGE = Message.model_validate(
    {
        "id": "msg_max_tokens",
        "content": [],
        "model": "claude-opus-5",
        "role": "assistant",
        "stop_reason": "max_tokens",
        "stop_sequence": None,
        "type": "message",
        "usage": {"input_tokens": 100, "output_tokens": 10},
    }
)


def _narrate_message(*, executive_summary: str) -> Message:
    return Message.model_validate(
        {
            "id": "msg_narrate",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_narrate",
                    "name": "narrate_analysis",
                    "input": {"executive_summary": executive_summary, "phase_narratives": []},
                }
            ],
            "model": "claude-opus-5",
            "role": "assistant",
            "stop_reason": "tool_use",
            "stop_sequence": None,
            "type": "message",
            "usage": {"input_tokens": 200, "output_tokens": 40},
        }
    )


class SafeFallbackCaller:
    """The one `LLMCaller` test double `app.pipeline.stages.triage` tests need — used wherever a
    test must drive the *real* triage stage to completion without a live `ANTHROPIC_API_KEY`
    (CLAUDE.md: "recorded fixtures ... CI must never need an API key"), for an incident whose
    specific evidence/entities the test does not want to hand-script citations against.

    Every Path B (Analyst/Judge/Presenter) turn gets `stop_reason="max_tokens"` back, which
    `app.agent.orchestrator._run_tool_role` turns into a `SchemaValidationError` on the very first
    call — `triage_incident` already catches exactly that (and `AgentTimeoutError`/
    `AgentRefusalError`/...) and persists a `needs_review` `TriageVerdict` instead of crashing
    (see that function's own docstring: this is a *real*, tested fallback path, not a shortcut
    invented for tests). That makes this caller correct for *any* incident, regardless of its
    real evidence ids, entities, or anomaly_confidence — nothing about the response depends on
    what was actually asked.

    Path A (`narrate_analysis`) has no such fallback (`app.pipeline.stages.triage`'s own module
    docstring: it does not catch its own schema/citation failures), so this caller answers that
    one call for real, with a citation-free, number-free executive summary that trivially passes
    `app.agent.verifier.verify_narrator_output` regardless of the real overview/incident/timeline
    data it was given.
    """

    def __init__(self, *, executive_summary: str = "Analysis complete.") -> None:
        self.calls: list[dict[str, Any]] = []
        self._executive_summary = executive_summary

    def create(self, **kwargs: Any) -> Message:
        self.calls.append(kwargs)
        tool_choice = kwargs.get("tool_choice") or {}
        if tool_choice.get("name") == "narrate_analysis":
            return _narrate_message(executive_summary=self._executive_summary)
        return _MAX_TOKENS_MESSAGE
