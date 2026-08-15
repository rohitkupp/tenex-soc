"""GET /api/analyses/{id}/stream — docs/09's SSE relay.

Wire event shape, byte for byte what every `data:` line carries — docs/01-
ARCHITECTURE.md's "Progress streaming" section as amended with its "Terminal contract"
addendum (added, concurrently with this milestone's build, specifically to make stream
termination unambiguous — see `app.pipeline.progress`'s docstring for the full text):

```json
{ "stage": "triage", "progress": 1.0, "status": "complete", "message": "Done",
  "counters": {"events": 1412903, "signals": 812, "incidents": 14, "needs_attention": 3} }
```

Workers publish this exact payload to Redis channel `analysis:{id}`
(`app.pipeline.progress.publish_progress`); this module relays it to the browser
unchanged, wrapped as one SSE `data:` frame per message.

## Why this isn't "subscribe and forward" alone

Redis pub/sub has no replay/history — a client that connects *after* the (fast,
skeleton-stage) pipeline has already finished would otherwise hang forever waiting for
a message that already happened, which is a real risk here specifically because most
M4 stages are near-instant pass-throughs. So, on connect:

1. Immediately look up the current `analyses` row and emit one synthetic snapshot event
   in the same wire shape (`status` included) — a client that connects mid-pipeline or
   after it finished still sees where things stand right away, not just future events.
2. If the analysis is already terminal (`status in {complete, failed}`), close right
   after that snapshot; nothing further will ever be published for it.
3. Otherwise, subscribe to `analysis:{id}` and relay every message verbatim, reading
   `status` straight off each message to decide when to stop — the doc's own point
   ("this is specified because it cannot be inferred"). A short poll of the DB `status`
   (`_POLL_INTERVAL_SECONDS`) runs only on cycles where no Redis message arrived in
   time, purely as a fallback in case a publish was ever missed — not the primary
   termination signal.

## Terminating cleanly

"SSE must be tenant-scoped and must terminate cleanly; a hung stream is a leaked
connection" (this milestone's brief). Three independent things close the generator:
client disconnect (`request.is_disconnected()`, checked every poll cycle), the analysis
reaching a terminal state, and `_MAX_STREAM_SECONDS` as a hard backstop so a stuck
analysis can never pin a connection open indefinitely.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db, get_engine
from app.core.errors import ApiError
from app.core.logging import get_logger
from app.core.security import CurrentUser, require_user
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.pipeline import state
from app.pipeline.contracts import public_counters
from app.pipeline.progress import channel_name
from app.pipeline.redis_client import get_redis

router = APIRouter()
log = get_logger(__name__)

_TERMINAL_STATUSES = frozenset({"complete", "failed"})
_POLL_INTERVAL_SECONDS = 1.0
_MAX_STREAM_SECONDS = 600.0


def _not_found() -> ApiError:
    return ApiError(status_code=404, code="not_found", detail="Analysis not found.")


def _sse_frame(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload)}\n\n"


def _load_snapshot(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> dict[str, Any] | None:
    with get_engine().begin() as conn:
        try:
            row = state.fetch_analysis(conn, analysis_id=analysis_id, tenant_id=tenant_id)
        except state.AnalysisNotFoundError:
            return None
    return {
        "stage": row["stage"] or "ingest",
        "progress": row["progress"],
        "status": row["status"],
        "message": row.get("error") or f"status={row['status']}",
        "counters": public_counters(row["counters"]),
    }


def _current_status(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> str | None:
    with get_engine().begin() as conn:
        return state.fetch_status(conn, analysis_id=analysis_id, tenant_id=tenant_id)


def _status_of(raw_json: str) -> str | None:
    try:
        value = json.loads(raw_json).get("status")
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, str) else None


async def _event_stream(
    request: Request, analysis_id: uuid.UUID, tenant_id: uuid.UUID
) -> AsyncIterator[str]:
    snapshot = await asyncio.to_thread(_load_snapshot, analysis_id, tenant_id)
    if snapshot is None:
        return
    yield _sse_frame(snapshot)
    if snapshot["status"] in _TERMINAL_STATUSES:
        return

    redis_client = get_redis()
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(channel_name(analysis_id))
    started = time.monotonic()
    try:
        while True:
            if await request.is_disconnected():
                log.info("stream.client_disconnected", analysis_id=str(analysis_id))
                return
            if time.monotonic() - started > _MAX_STREAM_SECONDS:
                log.warning("stream.timeout", analysis_id=str(analysis_id))
                return

            message = await pubsub.get_message(
                ignore_subscribe_messages=True, timeout=_POLL_INTERVAL_SECONDS
            )
            if message is not None and message.get("type") == "message":
                raw = message["data"]
                yield f"data: {raw}\n\n"
                if _status_of(raw) in _TERMINAL_STATUSES:
                    return
                continue

            # No Redis message this cycle — fallback poll in case a publish was ever
            # missed. `status` is the authoritative signal (docs/01's "Terminal
            # contract"), not a guess based on stage/progress.
            status = await asyncio.to_thread(_current_status, analysis_id, tenant_id)
            if status in _TERMINAL_STATUSES:
                final_snapshot = await asyncio.to_thread(_load_snapshot, analysis_id, tenant_id)
                if final_snapshot is not None:
                    yield _sse_frame(final_snapshot)
                return
    finally:
        await pubsub.unsubscribe(channel_name(analysis_id))
        # redis-py's async PubSub.aclose has no stub, hence the untyped-call ignore.
        await pubsub.aclose()  # type: ignore[no-untyped-call]


@router.get("/analyses/{analysis_id}/stream")
async def stream_analysis(
    analysis_id: uuid.UUID,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> StreamingResponse:
    with tenant_scope(db, current.tenant.id):
        exists = db.execute(
            select(Analysis.id).where(Analysis.id == analysis_id)
        ).scalar_one_or_none()
    if exists is None:
        raise _not_found()

    return StreamingResponse(
        _event_stream(request, analysis_id, current.tenant.id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # disable nginx/Caddy response buffering, if fronted by one
        },
    )
