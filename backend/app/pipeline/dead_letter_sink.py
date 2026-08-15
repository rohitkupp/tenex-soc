"""The single place `dead_letters` (Postgres, docs/02) rows get written.

Two different paths put a message on a `dlq.<name>` queue:

1. `app.pipeline.base_worker`, once a stage exhausts its 3 app-level retries —
   publishes explicitly (`app.queue.publish.publish_dead_letter`). No `x-death` header.
2. RabbitMQ itself, natively, when a `q.<name>` quorum queue's `x-delivery-limit` is
   exceeded — the case where a worker process is killed (or crashes) while holding a
   message, repeatedly, so `app.pipeline.base_worker`'s exception handler never gets a
   chance to run at all (see `app.queue.topology`'s docstring — this is exactly the
   "kill a worker mid-run" scenario). RabbitMQ stamps an `x-death` header with `reason:
   "delivery_limit_exceeded"` and the broker's own redelivery count on that hop.

This module consumes every `dlq.<name>` queue and writes exactly one `dead_letters` row
per message, regardless of which path put it there — so `GET /api/ops/dead-letters` is
a complete picture of pipeline failures, not just the ones this codebase's own
exception handler happened to catch. `attempts` prefers the broker's own count
(`x-death[0].count`) when present, since that is ground truth for path 2; it falls back
to the message body's own `attempt + 1` (what path 1 already computed) otherwise.

It is also the only place that marks the analysis `failed` for path 2 — `app.pipeline.
base_worker`'s own exception handler does that for path 1, but by definition nothing in
that module ever runs for a broker-native `x-delivery-limit` dead-letter (that is the
entire point of the mechanism — see `app.queue.topology`). Without this, an analysis
whose message hit the delivery limit would sit at `status='running'` forever: nothing
would ever publish to its next queue, so it would never reach `complete`, and nothing
would ever call `mark_failed`, so it would never reach `failed` either — a permanently
stuck analysis and a permanently open SSE stream. Calling `mark_failed` here for *every*
dead letter (not just native ones) is intentional and safe, not redundant-by-accident:
`mark_failed`'s own `WHERE status NOT IN ('complete', 'failed')` guard (`app.pipeline.
state`) makes a second call for the same analysis (path 1 already called it once) a
no-op, so this module doesn't need to distinguish the two paths to stay correct.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from aio_pika.abc import AbstractIncomingMessage

from app.core.db import get_engine
from app.core.logging import get_logger
from app.pipeline.contracts import STAGE_PROGRESS, public_counters
from app.pipeline.dead_letters import insert_dead_letter
from app.pipeline.messages import decode_stage_message
from app.pipeline.progress import publish_progress
from app.pipeline.redis_client import get_redis
from app.pipeline.state import AnalysisNotFoundError, get_counters, mark_failed
from app.queue.topology import QUEUE_NAMES, dead_letter_queue, declare_topology, get_connection

log = get_logger(__name__)


def _attempts_from_headers(headers: dict[str, Any] | None, fallback: int) -> int:
    if headers:
        x_death = headers.get("x-death")
        if isinstance(x_death, list) and x_death:
            count = x_death[0].get("count")
            if isinstance(count, int):
                return count
    return fallback


def _reason_from_headers(headers: dict[str, Any] | None) -> str | None:
    if headers:
        x_death = headers.get("x-death")
        if isinstance(x_death, list) and x_death:
            reason = x_death[0].get("reason")
            if isinstance(reason, str):
                return reason
    return None


def _stage_error_from_headers(headers: dict[str, Any] | None) -> str | None:
    """The original exception text `app.pipeline.base_worker` attached via the
    `x-stage-error` header (`app.queue.publish.publish_dead_letter`) — present for the
    app-level exhausted-retry path, absent for the broker-native `x-delivery-limit`
    path (nothing in this codebase ran to set it)."""
    if headers:
        value = headers.get("x-stage-error")
        if isinstance(value, str):
            return value
    return None


async def _handle(queue_name: str, delivery: AbstractIncomingMessage) -> None:
    async with delivery.process():
        native_reason = _reason_from_headers(delivery.headers)
        try:
            message = decode_stage_message(delivery.body)
        except Exception as exc:
            log.warning("dead_letter_sink.undecodable", queue=queue_name, error=str(exc))
            payload: dict[str, Any] = {"undecodable_body_hex": delivery.body.hex()}
            analysis_id: uuid.UUID | None = None
            tenant_id: uuid.UUID | None = None
            stage_label = queue_name
            attempts = _attempts_from_headers(delivery.headers, 1)
            error = f"undecodable body on dlq.{queue_name}: {exc}"
        else:
            payload = message.model_dump(mode="json")
            analysis_id = message.analysis_id
            tenant_id = message.tenant_id
            stage_label = message.stage
            attempts = _attempts_from_headers(delivery.headers, message.attempt + 1)
            stage_error = _stage_error_from_headers(delivery.headers)
            if native_reason:
                error = f"broker dead-lettered from q.{queue_name} ({native_reason})"
            elif stage_error:
                error = stage_error
            else:
                error = f"{queue_name} stage failed permanently after {attempts} attempt(s)"

        def _write() -> dict[str, Any] | None:
            with get_engine().begin() as conn:
                insert_dead_letter(
                    conn,
                    analysis_id=analysis_id,
                    stage=queue_name,
                    payload=payload,
                    error=error,
                    attempts=attempts,
                )
                if analysis_id is None or tenant_id is None:
                    return None
                try:
                    mark_failed(conn, analysis_id=analysis_id, tenant_id=tenant_id, error=error)
                    return get_counters(conn, analysis_id=analysis_id, tenant_id=tenant_id)
                except AnalysisNotFoundError:
                    # The analysis is already gone (e.g. deleted while this dead
                    # letter was in flight) — the dead_letters row above is still the
                    # historical record docs/09's ops endpoint wants; there is just no
                    # live analysis left to mark failed or publish progress for. Not a
                    # bug in this consumer, so it must not crash the `asyncio.gather`
                    # group that every other dlq.* queue's consumption shares (`run`,
                    # below) — one already-deleted analysis must not take down dead
                    # letter recording for every other stage's queue.
                    log.info(
                        "dead_letter_sink.analysis_already_gone",
                        queue=queue_name,
                        analysis_id=str(analysis_id),
                    )
                    return None

        counters = await asyncio.to_thread(_write)
        log.error(
            "dead_letter_sink.recorded",
            queue=queue_name,
            analysis_id=str(analysis_id) if analysis_id else None,
            attempts=attempts,
            native=bool(native_reason),
        )

        # Push, not just the eventual DB-status poll fallback (app.api.stream) —
        # matters most for path 2, where nothing else ever publishes a terminal event
        # for this analysis (see the module docstring).
        if analysis_id is not None and counters is not None:
            try:
                await publish_progress(
                    get_redis(),
                    analysis_id=analysis_id,
                    stage=stage_label,
                    progress=STAGE_PROGRESS.get(stage_label, 0.0),
                    status="failed",
                    message=error,
                    counters=public_counters(counters),
                )
            except Exception:
                log.warning("dead_letter_sink.progress_publish_failed", exc_info=True)


async def run() -> None:
    """Consumes every `dlq.<name>` queue concurrently on one connection. Unlike the
    per-stage `StageWorker`, this is intentionally one process for all eleven dead-letter
    queues — it does no pipeline work, just persistence, so there's nothing to gain from
    running it as eleven separate containers the way the real stages are (docs/01's "one
    container, one queue" argument is about demonstrating independent stage scale-out;
    this is plumbing)."""
    connection = await get_connection()
    try:
        setup_channel = await connection.channel()
        await declare_topology(setup_channel)
        await setup_channel.close()

        async def _consume_one(name: str) -> None:
            channel = await connection.channel()
            await channel.set_qos(prefetch_count=4)
            queue = await channel.get_queue(dead_letter_queue(name))
            async with queue.iterator() as messages:
                async for delivery in messages:
                    try:
                        await _handle(name, delivery)
                    except Exception:
                        # Defense in depth beyond `_handle`'s own known-exception
                        # handling (`AnalysisNotFoundError`, undecodable bodies): an
                        # unanticipated failure on *one* dlq.<name> queue must not
                        # propagate through `asyncio.gather` below and take every
                        # other queue's consumer down with it — recording dead letters
                        # for the other ten stages is independent of this one.
                        log.critical(
                            "dead_letter_sink.unexpected_failure", queue=name, exc_info=True
                        )

        log.info("dead_letter_sink.started", queues=[dead_letter_queue(n) for n in QUEUE_NAMES])
        await asyncio.gather(*(_consume_one(name) for name in QUEUE_NAMES))
    finally:
        await connection.close()
