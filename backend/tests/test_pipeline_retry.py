"""`app.pipeline.base_worker`'s retry/backoff/dead-letter policy against the real
RabbitMQ and Postgres from docker-compose.yml — docs/13's M4 acceptance line:
"Killing a worker mid-run dead-letters cleanly and retries," and this milestone's own
brief: "prove the message dead-letters cleanly, retries per the backoff policy, and
lands in dead_letters after exhausting attempts. This is ... the hardest part — do not
skip or simulate it."

This file covers the deterministic half of that: a stage handler that fails every
time, run against the live broker with `app.pipeline.dead_letter_sink` also running,
measuring the actual wall-clock gaps between attempts (must land near 1s/4s/16s) and
asserting the `dead_letters` row and `analyses.status` end up correct. The
"kill -9 an actual worker process" half is exercised as a live, human-verified
end-to-end run (see the milestone report) since a hard process kill mid-delivery isn't
something a fast, deterministic pytest run should depend on timing precisely — what
*is* deterministic and belongs in the suite is the policy this test proves.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from app.core.db import get_engine
from app.pipeline import dead_letter_sink, state
from app.pipeline.base_worker import StageWorker
from app.pipeline.messages import StageMessage
from app.pipeline.redis_client import get_redis
from app.queue.publish import publish_stage_message
from app.queue.topology import dead_letter_queue, declare_topology, get_connection, work_queue
from tests.conftest import make_analysis, make_tenant, make_user


@pytest.fixture(autouse=True)
def _fresh_redis_client() -> Iterator[None]:
    """`app.pipeline.redis_client.get_redis` is a process-wide `@lru_cache`d client —
    exactly right for a worker process, which runs one event loop for its whole
    lifetime, but pytest-asyncio hands each async test function its own event loop by
    default. Without clearing the cache, a client created on test N's loop gets reused
    (and errors) on test N+1's different loop. Not a production concern; a test-harness
    one."""
    get_redis.cache_clear()
    yield
    get_redis.cache_clear()


# A real docs/01 queue (`enrich`) rather than inventing a test-only one —
# app.queue.topology only declares the eleven names in QUEUE_NAMES, and no worker
# container is running against it during the test suite (docker-compose.yml's worker
# services aren't part of `make test`), so this is safe and exercises the exact
# production topology.
TEST_QUEUE = "enrich"


@pytest.fixture(autouse=True)
async def _clean_queue() -> AsyncIterator[None]:
    connection = await get_connection()
    try:
        channel = await connection.channel()
        await declare_topology(channel)
        work = await channel.declare_queue(work_queue(TEST_QUEUE), passive=True)
        dlq = await channel.declare_queue(dead_letter_queue(TEST_QUEUE), passive=True)
        await work.purge()
        await dlq.purge()
        yield
        await work.purge()
        await dlq.purge()
    finally:
        await connection.close()


@pytest.fixture
def analysis(tenant_cleanup: list[uuid.UUID]) -> tuple[uuid.UUID, uuid.UUID]:
    tenant = make_tenant(name="Retry Policy Test Tenant")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"retry-test-{uuid.uuid4()}@test.local")
    row = make_analysis(tenant_id=tenant.id, user_id=user.id)
    return row.id, tenant.id


async def test_retries_with_exponential_backoff_then_dead_letters(
    analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    analysis_id, tenant_id = analysis
    attempts_seen: list[tuple[int, float]] = []

    async def always_fails(message: StageMessage) -> list[tuple[str, StageMessage]]:
        attempts_seen.append((message.attempt, time.monotonic()))
        raise RuntimeError(f"synthetic failure on attempt {message.attempt}")

    worker = StageWorker(TEST_QUEUE, always_fails)
    worker_task = asyncio.create_task(worker.run())
    sink_task = asyncio.create_task(dead_letter_sink.run())
    try:
        connection = await get_connection()
        try:
            channel = await connection.channel()
            await declare_topology(channel)
            message = StageMessage(
                analysis_id=analysis_id,
                tenant_id=tenant_id,
                stage="enrich",
                attempt=0,
                emitted_at=datetime.now(UTC),
            )
            await publish_stage_message(channel, TEST_QUEUE, message)
        finally:
            await connection.close()

        # 4 total tries expected: attempt 0 (original) + 3 retries (attempts 1,2,3),
        # spaced by the 1s/4s/16s backoff — worst case ~21s of waiting plus handler
        # overhead, so a generous deadline.
        deadline = time.monotonic() + 45
        while len(attempts_seen) < 4 and time.monotonic() < deadline:  # noqa: ASYNC110 - bounded poll against real background tasks/processes, not a signal to await
            await asyncio.sleep(0.1)

        assert [a for a, _ in attempts_seen] == [0, 1, 2, 3], attempts_seen

        gaps = [attempts_seen[i + 1][1] - attempts_seen[i][1] for i in range(3)]
        # Real scheduling/network jitter tolerated; the shape (1s, 4s, 16s) must hold.
        assert 0.5 <= gaps[0] <= 3.0, f"retry 1 gap was {gaps[0]:.2f}s, expected ~1s"
        assert 3.0 <= gaps[1] <= 7.0, f"retry 2 gap was {gaps[1]:.2f}s, expected ~4s"
        assert 13.0 <= gaps[2] <= 19.0, f"retry 3 gap was {gaps[2]:.2f}s, expected ~16s"

        # The dead_letter_sink persists the Postgres row asynchronously — poll briefly.
        row = None
        deadline = time.monotonic() + 10
        while row is None and time.monotonic() < deadline:
            with get_engine().begin() as conn:
                row = (
                    conn.execute(
                        text(
                            "SELECT stage, attempts, error, payload FROM dead_letters "
                            "WHERE analysis_id = :aid ORDER BY id DESC LIMIT 1"
                        ),
                        {"aid": analysis_id},
                    )
                    .mappings()
                    .one_or_none()
                )
            if row is None:
                await asyncio.sleep(0.2)

        assert row is not None, "no dead_letters row was recorded"
        assert row["stage"] == TEST_QUEUE
        assert row["attempts"] == 4
        # The real exception text (threaded through the AMQP `x-stage-error` header,
        # since StageMessage's body has no field for it — see app.queue.publish) shows
        # up verbatim in the ops-visible dead_letters row, not a generic placeholder.
        assert "synthetic failure on attempt 3" in row["error"]
        assert row["payload"]["analysis_id"] == str(analysis_id)

        with get_engine().begin() as conn:
            final = state.fetch_analysis(conn, analysis_id=analysis_id, tenant_id=tenant_id)
        assert final["status"] == "failed"
        assert "enrich stage failed permanently after 4 attempt(s)" in (final["error"] or "")
    finally:
        worker_task.cancel()
        sink_task.cancel()
        for task in (worker_task, sink_task):
            with contextlib.suppress(asyncio.CancelledError):
                await task
        with get_engine().begin() as conn:
            conn.execute(
                text("DELETE FROM dead_letters WHERE analysis_id = :aid"), {"aid": analysis_id}
            )


async def test_permanent_stage_error_skips_retries_and_dead_letters_immediately(
    analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """`app.pipeline.errors.PermanentStageError` — a deterministic failure (e.g. the
    orchestrator's "no source types detected") must not spend ~21s of backoff learning
    the same fact three more times."""
    from app.pipeline.errors import PermanentStageError

    analysis_id, tenant_id = analysis
    attempts_seen: list[int] = []

    async def always_permanently_fails(message: StageMessage) -> list[tuple[str, StageMessage]]:
        attempts_seen.append(message.attempt)
        raise PermanentStageError("deterministic, do not retry")

    worker = StageWorker(TEST_QUEUE, always_permanently_fails)
    worker_task = asyncio.create_task(worker.run())
    sink_task = asyncio.create_task(dead_letter_sink.run())
    try:
        connection = await get_connection()
        try:
            channel = await connection.channel()
            await declare_topology(channel)
            message = StageMessage(
                analysis_id=analysis_id,
                tenant_id=tenant_id,
                stage="enrich",
                attempt=0,
                emitted_at=datetime.now(UTC),
            )
            await publish_stage_message(channel, TEST_QUEUE, message)
        finally:
            await connection.close()

        row = None
        deadline = time.monotonic() + 5
        while row is None and time.monotonic() < deadline:
            with get_engine().begin() as conn:
                row = (
                    conn.execute(
                        text("SELECT attempts FROM dead_letters WHERE analysis_id = :aid"),
                        {"aid": analysis_id},
                    )
                    .mappings()
                    .one_or_none()
                )
            if row is None:
                await asyncio.sleep(0.1)

        # No 21s of waiting for this path — must show up almost immediately.
        assert row is not None
        assert attempts_seen == [0]
        assert row["attempts"] == 1
    finally:
        worker_task.cancel()
        sink_task.cancel()
        for task in (worker_task, sink_task):
            with contextlib.suppress(asyncio.CancelledError):
                await task
        with get_engine().begin() as conn:
            conn.execute(
                text("DELETE FROM dead_letters WHERE analysis_id = :aid"), {"aid": analysis_id}
            )
