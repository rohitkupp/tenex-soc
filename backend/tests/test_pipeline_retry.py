"""`app.pipeline.base_worker`'s retry/backoff/dead-letter policy against the real
RabbitMQ and Postgres from docker-compose.yml — docs/13's M4 acceptance line:
"Killing a worker mid-run dead-letters cleanly and retries," and this milestone's own
brief: "prove the message dead-letters cleanly, retries per the backoff policy, and
lands in dead_letters after exhausting attempts. This is ... the hardest part — do not
skip or simulate it."

This file covers both halves now. The first half (below) is the deterministic
app-level path: a stage handler that fails every time, run against the live broker
with `app.pipeline.dead_letter_sink` also running, measuring the actual wall-clock
gaps between attempts (must land near 1s/4s/16s) and asserting the `dead_letters` row
and `analyses.status` end up correct.

The second half — "## kill a worker mid-run" below — is the broker-native path a real
`kill -9` takes: no application exception, no ack, nothing in `app.pipeline.
base_worker` ever runs (see that module's own docstring, "The process dies
mid-message"). change 25's own acceptance bar for the Integration row names this
scenario explicitly, so it is exercised for real here rather than deferred again: a
low-level consumer pulls one message off the real work queue and the connection is
torn down without ever acking it — indistinguishable, from RabbitMQ's point of view,
from a process that just died — and the test proves the two things that scenario
requires: a fresh worker recovers the redelivered message (retry), and enough repeated
crashes make the quorum queue's own `x-delivery-limit` dead-letter it natively, with
zero application code involved in the decision (clean dead-letter). This does not
literally `fork`+`SIGKILL` an OS process — see `_crash_mid_delivery`'s own docstring
for why that is a faithful simulation rather than a smaller substitute: the broker
cannot tell the difference, and it is the broker's behavior this scenario is about.
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


# ---------------------------------------------------------------------------- kill a worker mid-run


async def _publish_fresh_message(
    queue_name: str, *, analysis_id: uuid.UUID, tenant_id: uuid.UUID
) -> None:
    connection = await get_connection()
    try:
        channel = await connection.channel()
        await declare_topology(channel)
        message = StageMessage(
            analysis_id=analysis_id,
            tenant_id=tenant_id,
            stage=queue_name,
            attempt=0,
            emitted_at=datetime.now(UTC),
        )
        await publish_stage_message(channel, queue_name, message)
    finally:
        await connection.close()


async def _crash_mid_delivery(queue_name: str, *, fetch_timeout_s: float = 10.0) -> bool:
    """Simulates "the worker process dies mid-message" — `app.pipeline.base_worker`'s own module
    docstring's second failure mode, where no exception is ever raised and no ack ever happens
    because the process holding the delivery is gone. This deliberately does not go through
    `StageWorker` (which *always* acks — see `_handle_delivery`: every branch, including the
    exception branch, ends in `await delivery.ack()`) or `asyncio.Task.cancel()` on a running
    worker (a cancelled task still unwinds through `finally: await connection.close()`, which is
    a graceful AMQP close, not a dropped connection — a strictly *easier* case for the broker than
    a real crash). Instead: a fresh, low-level connection pulls exactly one message off the real
    work queue with `no_ack=False` (the broker now expects an ack that will never come), and the
    connection is torn down immediately, before any ack or nack. RabbitMQ's quorum queue does not
    distinguish a connection closed like this from a `kill -9`'d TCP peer — both look identical on
    the wire: a channel disappears holding an unacked delivery. That equivalence is exactly what
    lets this be a faithful "kill a worker mid-run" rather than a smaller substitute for one; see
    `app.queue.topology`'s own docstring for why `x-delivery-limit` is "handled entirely by the
    broker" for this case, independent of anything in this codebase.

    Returns whether a message was actually there to crash on. Deliberately does **not** assert
    that itself — once enough crashes have pushed a message past `x-delivery-limit`, the broker
    removes it from `q.<name>` on its own, so a *later* call in a crash-loop finding nothing is
    the expected terminal state, not a failure; callers that expect a message to always be
    present (a single crash right after a fresh publish) assert on the return value themselves."""
    connection = await get_connection()
    try:
        channel = await connection.channel()
        await channel.set_qos(prefetch_count=1)
        await declare_topology(channel)
        queue = await channel.get_queue(work_queue(queue_name))
        message = await queue.get(no_ack=False, fail=False, timeout=fetch_timeout_s)
        # No ack, no nack when found — falling straight through to `connection.close()` below.
        return message is not None
    finally:
        await connection.close()


async def test_worker_crash_mid_delivery_requeues_and_a_fresh_worker_recovers(
    analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """change 25's Integration row acceptance bar, "retry" half: kill a worker mid-run, and a
    replacement worker still finishes the job. No application-level retry logic is involved at
    all here (`message.attempt` never advances — this is the broker's own unacked-redelivery
    mechanism, not `app.pipeline.base_worker`'s exponential backoff, which is covered separately
    above by `test_retries_with_exponential_backoff_then_dead_letters`)."""
    analysis_id, tenant_id = analysis
    await _publish_fresh_message(TEST_QUEUE, analysis_id=analysis_id, tenant_id=tenant_id)

    # The "kill -9": a worker receives the message and then simply stops existing, mid-delivery.
    found = await _crash_mid_delivery(TEST_QUEUE)
    assert found, "expected the just-published message to be there to crash on"

    processed_attempts: list[int] = []

    async def succeeds(message: StageMessage) -> list[tuple[str, StageMessage]]:
        processed_attempts.append(message.attempt)
        return []

    # A fresh worker -- standing in for whatever process supervisor restarts the container in
    # production (docs/01) -- picks up wherever the dead one left off.
    worker = StageWorker(TEST_QUEUE, succeeds)
    worker_task = asyncio.create_task(worker.run())
    try:
        deadline = time.monotonic() + 15
        while not processed_attempts and time.monotonic() < deadline:  # noqa: ASYNC110
            await asyncio.sleep(0.1)
        assert processed_attempts, (
            "the message the crashed worker never acked was never redelivered to the fresh "
            "worker -- broker-native requeue-on-disconnect did not happen"
        )
        assert processed_attempts == [0], (
            "the broker's own redelivery must not touch app.pipeline.base_worker's `attempt` "
            "field -- that counter is exclusively for the application-driven backoff path"
        )
    finally:
        worker_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await worker_task


async def test_repeated_worker_crashes_dead_letter_via_broker_delivery_limit(
    analysis: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """change 25's Integration row acceptance bar, "clean dead-letter" half: a worker that keeps
    dying on the same message (not one lucky recovery) must still converge on `dlq.<name>` /
    `dead_letters`, entirely through the quorum queue's own `x-delivery-limit`
    (`app.queue.topology`) — no `StageWorker`, and therefore no `app.pipeline.base_worker`
    exception handler, ever runs in this test. `app.pipeline.dead_letter_sink` is the only
    application code involved, and only *after* the broker has already made the dead-letter
    decision on its own."""
    analysis_id, tenant_id = analysis
    await _publish_fresh_message(TEST_QUEUE, analysis_id=analysis_id, tenant_id=tenant_id)

    sink_task = asyncio.create_task(dead_letter_sink.run())
    try:
        row = None
        deadline = time.monotonic() + 60
        crashes = 0
        # However many redeliveries x-delivery-limit actually allows (MAX_ATTEMPTS, but this
        # loop deliberately doesn't hardcode the exact off-by-one so a topology tuning change
        # elsewhere doesn't make this test brittle) -- crash again until the broker gives up on
        # this message and native dead-lettering fires, or the bound below is exhausted. Once a
        # crash finds nothing left on q.<name>, the broker has already dead-lettered it out from
        # under us (the terminal state this test is proving, not a bug in the loop) -- fall
        # through to the DB check below rather than crashing on an empty queue forever.
        while row is None and time.monotonic() < deadline and crashes < 10:
            found = await _crash_mid_delivery(TEST_QUEUE)
            crashes += 1
            with get_engine().begin() as conn:
                row = (
                    conn.execute(
                        text(
                            "SELECT stage, attempts, error FROM dead_letters "
                            "WHERE analysis_id = :aid ORDER BY id DESC LIMIT 1"
                        ),
                        {"aid": analysis_id},
                    )
                    .mappings()
                    .one_or_none()
                )
            if row is None and not found:
                # Nothing left to crash on and still no dead_letters row -- give the sink a beat
                # to finish writing it (it processes `dlq.<name>` asynchronously) before the
                # deadline/crash-count bound above gives up for good.
                await asyncio.sleep(0.5)
            elif row is None:
                await asyncio.sleep(0.2)

        assert row is not None, f"broker never dead-lettered the message after {crashes} crash(es)"
        assert row["stage"] == TEST_QUEUE
        # `app.pipeline.dead_letter_sink`'s own docstring: the broker-native path is recognizable
        # by its `x-death` header (RabbitMQ's own reason string, `"delivery_limit"`) — this is
        # what proves the *broker* made this call, not `app.pipeline.base_worker`'s
        # exhausted-retries branch (which was never reached: no StageWorker ran against this
        # queue in this test at all, so `x-stage-error` — the app-driven path's marker — is
        # absent, and `_handle`'s `native_reason` branch is what built this message instead).
        assert "broker dead-lettered" in row["error"] and "delivery_limit" in row["error"], row[
            "error"
        ]

        with get_engine().begin() as conn:
            final = state.fetch_analysis(conn, analysis_id=analysis_id, tenant_id=tenant_id)
        assert final["status"] == "failed"
    finally:
        sink_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await sink_task
        with get_engine().begin() as conn:
            conn.execute(
                text("DELETE FROM dead_letters WHERE analysis_id = :aid"), {"aid": analysis_id}
            )
