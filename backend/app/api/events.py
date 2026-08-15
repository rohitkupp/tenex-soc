"""GET /api/analyses/{id}/events, GET /api/events/{event_id} — docs/09.

Every route requires an authenticated, tenant-scoped caller (docs/06); tenant scoping
is structural (`app.models.base`), not a filter a handler could forget — see
`app.models.event` for why `Event` mixes in `TenantScopedMixin` the same way the M1
tables do despite its `tenant_id` column itself carrying no FK/index.

**Sort order and keyset pagination.** The list endpoint orders by `(ts ASC, id ASC)` —
chronological, matching how an analyst reconstructs a narrative and how
`raw_line_no`/ingestion order naturally lines up within a source. Pagination is keyset
(`WHERE (ts, id) > (cursor_ts, cursor_id)`), never `OFFSET`: docs/13's M3 acceptance is
"paginates 1M+ rows without timing out", and `OFFSET` degrades linearly with page depth
on a table this size. `(ts, id)` is a strict total order (the `id` tiebreak covers the
common case of many events sharing one `ts` down to whatever timestamp precision the
source log had), so the cursor is stable: no row is ever skipped or repeated across
pages, even if new events are written between two page fetches (a genuinely new event
that sorts before the cursor position simply isn't visible on a page that has already
moved past that point).

**`has_signal` is a documented stub.** docs/02's `signals` table doesn't exist until
M6/M7 (docs/13) — this milestone is `events` only. No event can be signal-linked yet,
so `has_signal=true` correctly returns an empty page (not an error, not silently
ignored) and `has_signal=false`/unset needs no predicate at all, since every event
currently satisfies "has no signal". Once `signals` lands, this becomes a join/`EXISTS`
against `signals.evidence_event_ids` — grep for `has_signal` here when that milestone
starts.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import false, select, tuple_
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.errors import ApiError
from app.core.security import CurrentUser, require_user
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.event import Event
from app.schemas.event import EventListItem, EventListResponse, EventOut

router = APIRouter()


def _analysis_not_found() -> ApiError:
    return ApiError(status_code=404, code="not_found", detail="Analysis not found.")


def _event_not_found() -> ApiError:
    return ApiError(status_code=404, code="not_found", detail="Event not found.")


def _invalid_src_ip() -> ApiError:
    return ApiError(
        status_code=400, code="invalid_filter", detail="src_ip is not a valid IP address."
    )


def _encode_cursor(ts: datetime, event_id: int) -> str:
    raw = f"{ts.isoformat()}|{event_id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, int]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        ts_str, id_str = raw.split("|", 1)
        return datetime.fromisoformat(ts_str), int(id_str)
    except (ValueError, binascii.Error) as exc:
        raise ApiError(status_code=400, code="invalid_cursor", detail="Invalid cursor.") from exc


@router.get("/analyses/{analysis_id}/events", response_model=EventListResponse)
def list_events(
    analysis_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
    principal: str | None = None,
    domain: str | None = None,
    src_ip: str | None = None,
    action: str | None = None,
    ts_from: datetime | None = None,
    ts_to: datetime | None = None,
    has_signal: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    cursor: str | None = None,
) -> EventListResponse:
    if src_ip is not None:
        try:
            ipaddress.ip_address(src_ip)
        except ValueError as exc:
            raise _invalid_src_ip() from exc

    with tenant_scope(db, current.tenant.id):
        analysis = db.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        ).scalar_one_or_none()
        if analysis is None:
            raise _analysis_not_found()

        stmt = select(Event).where(Event.analysis_id == analysis_id)
        if principal is not None:
            stmt = stmt.where(Event.principal == principal)
        if domain is not None:
            stmt = stmt.where(Event.domain == domain)
        if src_ip is not None:
            stmt = stmt.where(Event.src_ip == src_ip)
        if action is not None:
            stmt = stmt.where(Event.action == action)
        if ts_from is not None:
            stmt = stmt.where(Event.ts >= ts_from)
        if ts_to is not None:
            stmt = stmt.where(Event.ts <= ts_to)
        if has_signal:
            stmt = stmt.where(false())  # see module docstring: documented stub

        stmt = stmt.order_by(Event.ts.asc(), Event.id.asc())
        if cursor is not None:
            cursor_ts, cursor_id = _decode_cursor(cursor)
            stmt = stmt.where(tuple_(Event.ts, Event.id) > (cursor_ts, cursor_id))
        stmt = stmt.limit(limit + 1)

        rows = db.execute(stmt).scalars().all()

    has_more = len(rows) > limit
    page = rows[:limit]
    items = [EventListItem.model_validate(e) for e in page]
    next_cursor = _encode_cursor(page[-1].ts, page[-1].id) if has_more and page else None
    return EventListResponse(items=items, next_cursor=next_cursor)


@router.get("/events/{event_id}", response_model=EventOut)
def get_event(
    event_id: int,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> EventOut:
    with tenant_scope(db, current.tenant.id):
        event = db.execute(select(Event).where(Event.id == event_id)).scalar_one_or_none()
    if event is None:
        raise _event_not_found()
    return EventOut.model_validate(event)
