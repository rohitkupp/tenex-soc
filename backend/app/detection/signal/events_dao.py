"""DB access for the L2 signal layer -- the only module in this package that imports
`app.models`/`sqlalchemy`. Every detector (`beaconing.py`, `dga.py`, `burst.py`, `rarity.py`) is
a pure function from `list[EventRow]` to `list[SignalDraft]`; this module is what fetches the
former and persists the latter, so the detectors' own unit tests never need a database.

Tenant scoping follows the rest of the codebase (`app.models.base`): every function here takes
an already tenant-bound `Session` (via `tenant_scope`/`tenant_session`) rather than a bare
`tenant_id` parameter, so a caller cannot accidentally query across tenants by forgetting to
scope -- the guard raises `MissingTenantScopeError` before any SQL runs, exactly as it does
everywhere else in the app.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.signal.drafts import SignalDraft
from app.models.event import Event
from app.models.signal import Signal

__all__ = ["EventRow", "fetch_event_rows", "persist_signals", "rows_with_domain"]


@dataclass(frozen=True, slots=True)
class EventRow:
    """The five `events` columns every L2 detector needs. Deliberately narrow -- none of the
    four detectors touch `bytes_in`/`bytes_out`/`status_code`/etc., and a wider row type would
    invite a detector to reach for a column docs/04 never asked it to use.
    """

    id: int
    ts: datetime
    src_ip: str | None
    domain: str | None
    principal: str | None


def fetch_event_rows(session: Session, analysis_id: uuid.UUID) -> list[EventRow]:
    """All events for one analysis, ordered by `ts` -- every detector needs its own group
    sorted chronologically, so sorting once here saves each of the four from re-sorting.

    No `source_type` filter: `domain` is a proxy-only hot column (docs/02) and would simply be
    `NULL` on a non-proxy source's rows if one were ever registered again (Okta and CloudTrail,
    the only two this pipeline ever had, are both removed today), so beaconing/DGA/rarity's
    `domain IS NOT NULL` grouping and burst's per-`src_ip` pass naturally see only proxy traffic
    without this query having to know that.
    """
    stmt = (
        select(
            Event.id,
            Event.ts,
            Event.src_ip,
            Event.domain,
            Event.principal,
        )
        .where(Event.analysis_id == analysis_id)
        .order_by(Event.ts)
    )
    rows = session.execute(stmt).all()
    return [
        EventRow(
            id=r.id,
            ts=r.ts,
            src_ip=str(r.src_ip) if r.src_ip is not None else None,
            domain=r.domain,
            principal=r.principal,
        )
        for r in rows
    ]


def persist_signals(
    session: Session,
    *,
    analysis_id: uuid.UUID,
    tenant_id: uuid.UUID,
    drafts: Iterable[SignalDraft],
) -> list[Signal]:
    """Build and `session.add` one `Signal` ORM row per draft, then `flush` (so callers can
    read back `.id` immediately). Does not commit -- same convention as
    `app.storage.event_writer.bulk_copy_events`: the caller controls the transaction boundary.
    """
    signals: list[Signal] = []
    for draft in drafts:
        kwargs: dict[str, Any] = draft.to_signal_kwargs()
        signal = Signal(analysis_id=analysis_id, tenant_id=tenant_id, **kwargs)
        session.add(signal)
        signals.append(signal)
    session.flush()
    return signals


def rows_with_domain(rows: Sequence[EventRow]) -> Iterable[EventRow]:
    """`rows` restricted to proxy traffic (`domain IS NOT NULL`) -- shared by every
    domain-keyed detector (`dga.py`, part of `rarity.py`) so each doesn't repeat the filter."""
    return (r for r in rows if r.domain)
