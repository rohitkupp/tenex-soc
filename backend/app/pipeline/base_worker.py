"""The base worker loop every `app/workers/*.py` entrypoint runs — transport, retry,
and dead-lettering, shared so no individual worker re-implements the retry/backoff/DLQ
policy (docs/01: "3 attempts with exponential backoff (1s, 4s, 16s), then dead-letter").

## What a stage plugs in

A stage supplies one async function:

```python
async def handle(message: StageMessage) -> list[tuple[str, StageMessage]]
```

It reads its input from the DB/object store, does its work, writes its output, updates
`analyses.stage`/`progress`/`counters`, publishes a progress event to Redis, and
**returns** the `StageMessage`(s) to publish next as `(queue_name, message)` pairs — it
never publishes them itself. Returning `[]` means "nothing to forward" (a fan-in stage
like `parse` on every worker except the one that observes `pending_parsers` hit zero, or
a genuinely terminal stage like `tier2`). Returning more than one pair is exactly how
the orchestrator's parallel parser fan-out works — no special case needed here for
fan-out *or* fan-in; both are just "how many pairs did the handler return."

Raising any exception means the stage failed. What happens next is this module's job,
not the stage's:

* **A caught exception** (this function runs to completion, badly): `attempt < 3` ->
  ack the original delivery, explicitly republish it to `delay.<name>` with the
  backoff-appropriate per-message TTL (`app.queue.publish.publish_retry`). `attempt >=
  3` -> write a `dead_letters` row, mark the analysis `failed`, publish to `dlq.<name>`,
  ack the original. Raising `app.pipeline.errors.PermanentStageError` instead of a bare
  exception skips straight to the dead-letter step regardless of `attempt` — for
  failures that are deterministic (the referenced analysis/upload row is gone), where
  spending ~21s retrying would only re-learn the same fact three more times.
* **The process dies mid-message** (no exception, no ack — killed, OOM, crashed): this
  code never runs. `app.queue.topology`'s quorum-queue `x-delivery-limit` is the safety
  net for that case, handled entirely by the broker. See that module's docstring.

Every worker holds exactly one AMQP channel with `prefetch_count=1` (docs/01: "One
durable queue per worker, prefetch 1") — one message in flight at a time, never a
second delivery while the first is still being decided.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from aio_pika.abc import AbstractChannel, AbstractIncomingMessage

from app.core.db import get_engine
from app.core.logging import get_logger
from app.pipeline.contracts import DEFAULT_COUNTERS, STAGE_PROGRESS, public_counters
from app.pipeline.dead_letters import insert_dead_letter
from app.pipeline.errors import PermanentStageError
from app.pipeline.messages import StageMessage, decode_stage_message
from app.pipeline.progress import publish_progress
from app.pipeline.redis_client import get_redis
from app.pipeline.state import AnalysisNotFoundError, get_counters, mark_failed
from app.queue.publish import publish_dead_letter, publish_retry, publish_stage_message
from app.queue.topology import (
    BACKOFF_SECONDS,
    MAX_ATTEMPTS,
    declare_topology,
    get_connection,
    work_queue,
)

log = get_logger(__name__)

StageHandler = Callable[[StageMessage], Awaitable[list[tuple[str, StageMessage]]]]


class StageWorker:
    """Runs one queue forever. `queue_name` is the logical name from `app.queue.
    topology.QUEUE_NAMES` (e.g. `"enrich"`, `"parse.zscaler"`, `"orchestrator"`)."""

    def __init__(self, queue_name: str, handler: StageHandler) -> None:
        self.queue_name = queue_name
        self.handler = handler

    async def run(self) -> None:
        connection = await get_connection()
        try:
            channel = await connection.channel()
            await channel.set_qos(prefetch_count=1)
            await declare_topology(channel)
            queue = await channel.get_queue(work_queue(self.queue_name))
            log.info("worker.started", queue=work_queue(self.queue_name))

            async with queue.iterator() as messages:
                async for delivery in messages:
                    await self._handle_delivery(channel, delivery)
        finally:
            await connection.close()

    async def _handle_delivery(
        self, channel: AbstractChannel, delivery: AbstractIncomingMessage
    ) -> None:
        try:
            message = decode_stage_message(delivery.body)
        except Exception as exc:  # malformed body — nothing to retry, no analysis to trace
            log.error("worker.decode_failed", queue=self.queue_name, error=str(exc))
            await self._dead_letter_undecodable(delivery, error=str(exc))
            await delivery.ack()
            return

        log_ctx = {
            "queue": self.queue_name,
            "analysis_id": str(message.analysis_id),
            "attempt": message.attempt,
        }

        try:
            next_messages = await self.handler(message)
        except Exception as exc:
            log.warning("worker.stage_failed", error=str(exc), **log_ctx)
            await self._handle_failure(channel, message, exc)
            await delivery.ack()
            return

        for queue_name, next_message in next_messages:
            await publish_stage_message(channel, queue_name, next_message)
        await delivery.ack()
        log.info("worker.stage_done", forwarded=[q for q, _ in next_messages], **log_ctx)

    async def _handle_failure(
        self, channel: AbstractChannel, message: StageMessage, exc: Exception
    ) -> None:
        error_text = f"{type(exc).__name__}: {exc}"
        if not isinstance(exc, PermanentStageError) and message.attempt < MAX_ATTEMPTS:
            delay = BACKOFF_SECONDS[message.attempt]
            retry_message = message.model_copy(
                update={"attempt": message.attempt + 1, "emitted_at": datetime.now(UTC)}
            )
            await publish_retry(channel, self.queue_name, retry_message, delay_seconds=delay)
            log.info(
                "worker.retry_scheduled",
                queue=self.queue_name,
                analysis_id=str(message.analysis_id),
                next_attempt=retry_message.attempt,
                delay_seconds=delay,
            )
            return

        await self._dead_letter(channel, message, error=error_text)

    async def _dead_letter(
        self, channel: AbstractChannel, message: StageMessage, *, error: str
    ) -> None:
        """Mark the analysis failed and put the message on `dlq.<name>`. Does **not**
        write the `dead_letters` Postgres row itself — `app.pipeline.dead_letter_sink`
        is the single place that happens, so an app-level exhausted-retry dead-letter
        and a broker-native `x-delivery-limit` dead-letter (the "kill a worker mid-run"
        case, where this code never runs at all — see `app.queue.topology`) both end up
        recorded the same way, through the same consumer, instead of this path writing
        a row here and racing/duplicating whatever the sink also does."""
        attempts = message.attempt + 1
        failure_reason = (
            f"{self.queue_name} stage failed permanently after {attempts} attempt(s): {error}"
        )

        def _write() -> dict[str, Any]:
            with get_engine().begin() as conn:
                try:
                    mark_failed(
                        conn,
                        analysis_id=message.analysis_id,
                        tenant_id=message.tenant_id,
                        error=failure_reason,
                        # This worker's own stage — the one that actually died. Without it the
                        # column keeps the last *successful* stage and the funnel points at the
                        # wrong box (change 27).
                        stage=self.queue_name,
                    )
                    return get_counters(
                        conn, analysis_id=message.analysis_id, tenant_id=message.tenant_id
                    )
                except AnalysisNotFoundError:
                    # The analysis row is already gone — e.g. `DELETE
                    # /api/analyses/{id}` (which cascades, docs/09) raced this message,
                    # or it was cleaned up by something else entirely unrelated to this
                    # failure. Expected and benign, not a bookkeeping bug: there is
                    # nothing left to mark failed or read counters from, so there is
                    # nothing more for this function to do.
                    log.info(
                        "worker.dead_letter_analysis_already_gone",
                        queue=self.queue_name,
                        analysis_id=str(message.analysis_id),
                    )
                    return dict(DEFAULT_COUNTERS)

        try:
            counters = await asyncio.to_thread(_write)
        except Exception:
            log.critical(
                "worker.dead_letter_bookkeeping_failed",
                queue=self.queue_name,
                analysis_id=str(message.analysis_id),
                exc_info=True,
            )
            counters = {}

        await publish_dead_letter(channel, self.queue_name, message, error=error)
        log.error(
            "worker.dead_lettered",
            queue=self.queue_name,
            analysis_id=str(message.analysis_id),
            attempts=attempts,
            error=error,
        )

        try:
            await publish_progress(
                get_redis(),
                analysis_id=message.analysis_id,
                stage=message.stage,
                progress=STAGE_PROGRESS.get(message.stage, 0.0),
                status="failed",
                message=failure_reason,
                counters=public_counters(counters),
            )
        except Exception:
            log.warning("worker.progress_publish_failed", exc_info=True)

    async def _dead_letter_undecodable(
        self, delivery: AbstractIncomingMessage, *, error: str
    ) -> None:
        def _write() -> None:
            with get_engine().begin() as conn:
                insert_dead_letter(
                    conn,
                    analysis_id=None,
                    stage=self.queue_name,
                    payload={"undecodable_body_b64": delivery.body.hex()},
                    error=f"could not decode StageMessage: {error}",
                    attempts=1,
                )

        try:
            await asyncio.to_thread(_write)
        except Exception:
            log.critical(
                "worker.dead_letter_bookkeeping_failed", queue=self.queue_name, exc_info=True
            )
