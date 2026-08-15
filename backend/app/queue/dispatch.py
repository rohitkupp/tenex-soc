"""Publish-only entrypoint for non-worker callers. Currently just `app.api.uploads`,
which needs to publish exactly one message per upload (the `ingest` `StageMessage`
that starts the pipeline, docs/09: POST /api/uploads "Kicks off the pipeline") without
paying a fresh AMQP connection handshake on every request the way a one-shot
`app.queue.topology.get_connection()` caller would.

**Why this tracks the running event loop, not just "is there a connection."** A real
API process (`uvicorn app.main:app`) runs one event loop for its entire lifetime, so a
plain "create once, reuse forever" cache would be enough on its own. But `asyncio`
primitives (this module's `asyncio.Lock`, and `aio-pika`'s own internal
`asyncio.Event`s) bind to whichever event loop is running the first time they're
awaited — reusing them from a *different* loop raises `RuntimeError: ... bound to a
different event loop`, not silently misbehaving. That happens for real, not just in
theory: `TestClient` gives each instance its own event loop, and `tests/test_csrf.py`'s
`test_full_flow_...` (and others) upload through several fresh `TestClient`s in the
same pytest process — the second one to call `kickoff_pipeline` would otherwise crash
reusing the first one's loop-bound connection and lock. Tracking `_loop` and rebuilding
both the connection *and* the lock when it changes fixes that for good, at zero cost to
the single-loop production case (the comparison is one pointer check).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from aio_pika.abc import AbstractChannel, AbstractRobustConnection

from app.core.logging import get_logger
from app.pipeline.messages import StageMessage
from app.queue.publish import publish_stage_message
from app.queue.topology import declare_topology, get_connection

log = get_logger(__name__)

_connection: AbstractRobustConnection | None = None
_channel: AbstractChannel | None = None
_loop: asyncio.AbstractEventLoop | None = None
_lock: asyncio.Lock | None = None


async def _get_channel() -> AbstractChannel:
    global _connection, _channel, _loop, _lock

    current_loop = asyncio.get_running_loop()
    if _lock is None or _loop is not current_loop:
        # No `await` between this check and its use below, so — single-threaded,
        # cooperative asyncio — there is no interleaving window for two callers on the
        # *same* loop to race here; only a genuine loop change reaches this branch.
        _lock = asyncio.Lock()

    async with _lock:
        if _connection is None or _connection.is_closed or _loop is not current_loop:
            _connection = await get_connection()
            _channel = await _connection.channel()
            await declare_topology(_channel)
            _loop = current_loop
        assert _channel is not None
        return _channel


async def kickoff_pipeline(*, analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
    """Publish the `ingest` `StageMessage` to `q.orchestrator`. Callers must have
    already committed the `analyses`/`uploads` rows — the orchestrator worker may pick
    this up and query them within milliseconds."""
    channel = await _get_channel()
    message = StageMessage(
        analysis_id=analysis_id,
        tenant_id=tenant_id,
        stage="ingest",
        attempt=0,
        emitted_at=datetime.now(UTC),
    )
    await publish_stage_message(channel, "orchestrator", message)
    log.info("pipeline.kickoff", analysis_id=str(analysis_id), tenant_id=str(tenant_id))


async def close() -> None:
    """Closes the cached connection — called from `app.main`'s lifespan shutdown so the
    API process doesn't leave an AMQP connection open on exit, and by tests that need a
    clean slate between `TestClient` instances/event loops."""
    global _connection, _channel, _loop, _lock
    if _connection is not None and not _connection.is_closed:
        await _connection.close()
    _connection = None
    _channel = None
    _loop = None
    _lock = None
