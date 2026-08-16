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

**`has_signal`** is a real predicate against `signals.evidence_event_ids` (docs/02), scoped to
the same `analysis_id` the rest of the query is already scoped to. `has_signal=true` keeps
only events cited by at least one signal's evidence; `has_signal=false` keeps only events no
signal ever cited — a genuinely useful "show me what got ignored" view, not just the inverse
of an error case. Both are a correlated `EXISTS`/`NOT EXISTS` using Postgres's array
containment operator (`evidence_event_ids @> ARRAY[events.id]`), not `events.id = ANY(...)`:
`@>` is one of the operators the default `array_ops` GIN opclass actually indexes (`&&`, `@>`,
`<@`, `=`) — `= ANY(array_column)` is not, so writing it that way would silently fall back to a
sequential scan of `signals` per outer row. The GIN index itself is
`ix_signals_evidence_event_ids_gin`
(`alembic/versions/6ba739579d4b_signals_evidence_event_ids_gin_index.py`); without it this
degrades badly on large analyses, and docs/13's M3 acceptance is "paginates 1M+ rows without
timing out".

**Signal stats on the list row** (`signal_count`/`max_confidence`/`detectors`, docs/09 +
the take-home brief's "highlight the anomalous entries ... with a confidence score") are
folded on in Python after the page is fetched, from exactly one extra query per *page* — see
`_signal_stats_for_page`'s docstring for why that one query uses array *overlap* (`&&`)
against the whole page's event ids rather than one query per event.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import ColumnElement, exists, select, tuple_
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.errors import ApiError
from app.core.security import CurrentUser, require_user
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.event import Event
from app.models.signal import Signal
from app.schemas.event import EventListItem, EventListResponse, EventOut, EventSignalOut

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


def _has_signal_predicate(analysis_id: uuid.UUID, *, want_signal: bool) -> ColumnElement[bool]:
    """`EXISTS`/`NOT EXISTS` against `signals.evidence_event_ids`, correlated on `Event.id`.

    Written with the containment operator (`@>`) rather than `Event.id == any_(...)` on
    purpose: Postgres's default GIN opclass for arrays (`array_ops`) indexes `&&`, `@>`,
    `<@`, and `=` — not the `x = ANY(array_column)` form, which the planner cannot route
    through that index and falls back to scanning every `signals` row per outer event. See
    `ix_signals_evidence_event_ids_gin` (docs/09 module docstring above).
    """
    has_evidence = exists(
        select(Signal.id).where(
            Signal.analysis_id == analysis_id,
            Signal.evidence_event_ids.op("@>")(array([Event.id])),
        )
    )
    return has_evidence if want_signal else ~has_evidence


class _SignalStats:
    __slots__ = ("count", "detectors", "max_confidence")

    def __init__(self) -> None:
        self.count = 0
        self.max_confidence: float | None = None
        self.detectors: set[str] = set()

    def add(self, signal: Signal) -> None:
        self.count += 1
        self.detectors.add(signal.detector_key)
        if self.max_confidence is None or signal.confidence > self.max_confidence:
            self.max_confidence = signal.confidence


def _signal_stats_for_page(
    db: Session, analysis_id: uuid.UUID, event_ids: list[int]
) -> dict[int, _SignalStats]:
    """One query for a whole page (never per event, per docs/09's performance note).

    A page has up to 500 event ids; a single query using array *overlap* (`&&`) pulls every
    signal that cites *any* of them, then this function folds that (typically much smaller)
    result set onto individual event ids in Python. The alternative — one `EXISTS`/count
    query per event — is what "per event" performance would look like: up to 500 round trips
    for one page, versus exactly one here. `&&` (not `@>`) is correct for this direction: we
    are asking "which signals overlap this whole batch of ids", not "does this one signal
    contain this one id" — and `&&` is indexed by the same GIN opclass as `@>`.

    The right-hand side is the bare Python list, not `postgresql.array(event_ids)`: SQLAlchemy
    binds a plain list operand to a comparison as a single parameter typed from the *left*
    operand's column type (here `ARRAY(BigInteger)`, matching `evidence_event_ids`).
    `postgresql.array(...)` instead builds a literal `ARRAY[...]` with each element typed from
    the Python value alone (`int` -> `INTEGER`), which Postgres then refuses to compare against
    a `bigint[]` column (`operator does not exist: bigint[] && integer[]`) — `array(...)` is
    only needed below, in `_has_signal_predicate`, where the element is a column expression
    (`Event.id`) rather than a plain value.
    """
    if not event_ids:
        return {}
    page_ids = set(event_ids)
    signals = (
        db.execute(
            select(Signal).where(
                Signal.analysis_id == analysis_id,
                Signal.evidence_event_ids.op("&&")(event_ids),
            )
        )
        .scalars()
        .all()
    )
    stats: dict[int, _SignalStats] = {}
    for signal in signals:
        for event_id in signal.evidence_event_ids:
            if event_id not in page_ids:
                continue  # this signal also cites events outside this page — ignore those
            stats.setdefault(event_id, _SignalStats()).add(signal)
    return stats


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
        if has_signal is not None:
            stmt = stmt.where(_has_signal_predicate(analysis_id, want_signal=has_signal))

        stmt = stmt.order_by(Event.ts.asc(), Event.id.asc())
        if cursor is not None:
            cursor_ts, cursor_id = _decode_cursor(cursor)
            stmt = stmt.where(tuple_(Event.ts, Event.id) > (cursor_ts, cursor_id))
        stmt = stmt.limit(limit + 1)

        rows = db.execute(stmt).scalars().all()

        has_more = len(rows) > limit
        page = rows[:limit]
        stats = _signal_stats_for_page(db, analysis_id, [e.id for e in page])

    items = [
        EventListItem.model_validate(e).model_copy(
            update={
                "signal_count": s.count,
                "max_confidence": s.max_confidence,
                "detectors": sorted(s.detectors),
            }
        )
        if (s := stats.get(e.id)) is not None
        else EventListItem.model_validate(e)
        for e in page
    ]
    next_cursor = _encode_cursor(page[-1].ts, page[-1].id) if has_more and page else None
    return EventListResponse(items=items, next_cursor=next_cursor)


def _event_out(db: Session, event: Event) -> EventOut:
    """Shared by `get_event` and `get_event_by_line`: full OCSF + enrichment + every signal
    citing this event. Single-event detail view — a per-event query here is fine (docs/09's "do
    not query per event" note is about the paged list, which can carry up to 500 rows). `[event.
    id]` is a bare Python list (`event.id` already loaded as a plain int, not a column expression
    here) — see `_signal_stats_for_page`'s docstring for why that must not be wrapped in
    `postgresql.array(...)`."""
    with tenant_scope(db, event.tenant_id):
        signals = (
            db.execute(
                select(Signal).where(
                    Signal.analysis_id == event.analysis_id,
                    Signal.evidence_event_ids.op("@>")([event.id]),
                )
            )
            .scalars()
            .all()
        )

    confidences = [s.confidence for s in signals]
    base = EventListItem.model_validate(event)
    return EventOut(
        **base.model_dump(exclude={"signal_count", "max_confidence", "detectors"}),
        ocsf=event.ocsf,
        enrichment=event.enrichment,
        signal_count=len(signals),
        max_confidence=max(confidences) if confidences else None,
        detectors=sorted({s.detector_key for s in signals}),
        signals=[EventSignalOut.model_validate(s) for s in signals],
    )


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
    return _event_out(db, event)


@router.get("/analyses/{analysis_id}/events/by-line/{raw_line_no}", response_model=EventOut)
def get_event_by_line(
    analysis_id: uuid.UUID,
    raw_line_no: int,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> EventOut:
    """docs/v2_migration change 16: evidence cards show `contributing_line_numbers` — file line
    numbers (`Event.raw_line_no`), not `events.id` — and must "click-to-expand into the raw log
    rows". Nothing before this endpoint could resolve a raw line number back to an event without
    the caller already knowing its database id, which the evidence layer never hands out (change
    2's own module docstring: "the file's line numbers, not events.id"). Keyed on `(analysis_id,
    raw_line_no)` rather than `raw_line_no` alone — line numbers restart at 1 for every uploaded
    file, so they are only unique within one analysis."""
    with tenant_scope(db, current.tenant.id):
        event = db.execute(
            select(Event).where(Event.analysis_id == analysis_id, Event.raw_line_no == raw_line_no)
        ).scalar_one_or_none()
        if event is None:
            raise _event_not_found()
    return _event_out(db, event)
