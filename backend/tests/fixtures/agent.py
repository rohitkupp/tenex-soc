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
            )
            session.add(event)
            session.commit()
            session.refresh(event)
        return event
    finally:
        session.close()
