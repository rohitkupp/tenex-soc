"""`app.pipeline.stages.triage._permanent_stage_error_for` and its wiring into `_run_triage` --
the fix for a production incident where a triage stage that hit `anthropic.BadRequestError` (400
`invalid_request_error`, an exhausted credit balance) dead-lettered "after 4 attempt(s)" instead
of 1: `app.pipeline.base_worker`'s retry-with-backoff ladder re-ran the *entire*
Analyst/Judge/Presenter/Narrator chain on each of the three retries, climbing cost in even steps
before finally giving up on an error that could never have succeeded on any of those retries.

Every exception used here is a real `anthropic` SDK exception, constructed directly (`_anthropic_
error` below mirrors exactly what `anthropic.Anthropic._make_status_error` builds from a live
HTTP response -- verified against the installed SDK, anthropic==0.122.0, in the container). No
network call is made anywhere in this file, and no `app.agent.client.LiveCaller` is ever
constructed -- every handler here is built with an injected fake `LLMCaller`
(`triage.make_handler(caller=...)`), so this file needs no `ANTHROPIC_API_KEY` and can never
reach the real API, matching CLAUDE.md's "recorded fixtures ... CI must never need a key."

The `StageWorker`-level tests below publish real messages to the real `triage` queue against the
live RabbitMQ from docker-compose.yml (the same pattern `test_pipeline_retry.py` uses for
`enrich`). Unlike `enrich`/`parse.zscaler`, the `agent` service -- docs/01's name for the *only*
consumer of `q.triage` (`python -m app.workers.agent`, always a real `LiveCaller` -- see that
module's own docstring) -- is not part of the currently running docker-compose stack (confirmed
via `docker compose ps` before writing this file: no `agent` container). Publishing to the real
`triage` queue here therefore races against nothing, sidestepping the worker-fleet-vs-shared-
broker artifact `test_pipeline_retry.py`'s own `TEST_QUEUE` comment documents for the queues that
*do* have a live production consumer in this environment.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from typing import Any

import anthropic
import httpx
import pytest
from anthropic.types import Message
from sqlalchemy import text

from app.core.db import get_engine
from app.pipeline import dead_letter_sink
from app.pipeline.base_worker import StageWorker
from app.pipeline.errors import PermanentStageError
from app.pipeline.messages import StageMessage
from app.pipeline.redis_client import get_redis
from app.pipeline.stages import triage
from app.queue.publish import publish_stage_message
from app.queue.topology import dead_letter_queue, declare_topology, get_connection, work_queue
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.response import make_incident, make_signal


# Autouse for this module: every test here publishes to a real stage queue and consumes it back
# with its own worker, so a running `docker compose` stack silently steals half the messages.
# See the fixture's docstring in conftest.
@pytest.fixture(autouse=True)
def _require_exclusive_queues(no_competing_queue_consumers: None) -> None:
    """Bind the session-scoped check to every test in this module."""

TEST_QUEUE = "triage"


def _anthropic_error(
    cls: type[anthropic.APIStatusError], *, status_code: int, error_type: str, message: str
) -> anthropic.APIStatusError:
    """A real SDK exception instance, built the same way `anthropic.Anthropic._make_status_error`
    builds one from a live HTTP response -- no network call, no API key."""
    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    body = {"type": "error", "error": {"type": error_type, "message": message}}
    response = httpx.Response(status_code, request=request, json=body)
    return cls(f"Error code: {status_code} - {body}", response=response, body=body)


class _RaisingCaller:
    """An `LLMCaller` whose every `.create()` call raises `error` immediately -- standing in for
    a real `LiveCaller` that always hits this specific API failure. Never touches the network."""

    def __init__(self, error: Exception) -> None:
        self.error = error
        self.calls = 0

    def create(self, **_kwargs: Any) -> Message:
        self.calls += 1
        raise self.error


def _message(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> StageMessage:
    return StageMessage(
        analysis_id=analysis_id,
        tenant_id=tenant_id,
        stage="triage",
        storage_ref=None,
        source_type=None,
        attempt=0,
        emitted_at=datetime.now(UTC),
    )


@pytest.fixture
def analysis_with_one_incident(tenant_cleanup: list[uuid.UUID]) -> tuple[uuid.UUID, uuid.UUID]:
    tenant = make_tenant(name="triage retry classification test")
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"triage-retry-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    signal = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="user",
        entity_value="victim@corp.example",
    )
    make_incident(tenant_id=tenant.id, analysis_id=analysis.id, signal_ids=[signal.id])
    return analysis.id, tenant.id


# ---------------------------------------------------------------------------- classification: unit

_PERMANENT_CASES = [
    (anthropic.BadRequestError, 400, "invalid_request_error"),
    (anthropic.AuthenticationError, 401, "authentication_error"),
    (anthropic.PermissionDeniedError, 403, "permission_error"),
    (anthropic.NotFoundError, 404, "not_found_error"),
]


@pytest.mark.parametrize(("cls", "status", "error_type"), _PERMANENT_CASES)
def test_permanent_anthropic_errors_are_classified_as_permanent_stage_error(
    cls: type[anthropic.APIStatusError], status: int, error_type: str
) -> None:
    exc = _anthropic_error(cls, status_code=status, error_type=error_type, message="boom detail")
    result = triage._permanent_stage_error_for(exc)
    assert result is not None
    assert isinstance(result, PermanentStageError)
    assert cls.__name__ in str(result)
    assert "boom detail" in str(result)


def _transient_cases() -> list[Exception]:
    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    return [
        _anthropic_error(
            anthropic.RateLimitError, status_code=429, error_type="rate_limit_error", message="x"
        ),
        _anthropic_error(
            anthropic.InternalServerError, status_code=500, error_type="api_error", message="x"
        ),
        _anthropic_error(
            anthropic.InternalServerError, status_code=502, error_type="api_error", message="x"
        ),
        _anthropic_error(
            anthropic.InternalServerError, status_code=503, error_type="api_error", message="x"
        ),
        _anthropic_error(
            anthropic.OverloadedError, status_code=529, error_type="overloaded_error", message="x"
        ),
        anthropic.APITimeoutError(request=request),
        anthropic.APIConnectionError(request=request),
        ValueError("an unrelated bug, not an Anthropic error at all"),
    ]


@pytest.mark.parametrize("exc", _transient_cases())
def test_transient_and_unrelated_errors_are_not_classified_as_permanent(exc: Exception) -> None:
    assert triage._permanent_stage_error_for(exc) is None


# ---------------------------------------------------------------------------- handler-level


def test_handler_raises_permanent_stage_error_for_bad_request(
    analysis_with_one_incident: tuple[uuid.UUID, uuid.UUID],
) -> None:
    analysis_id, tenant_id = analysis_with_one_incident
    error = _anthropic_error(
        anthropic.BadRequestError,
        status_code=400,
        error_type="invalid_request_error",
        message="Your credit balance is too low to access the Claude API.",
    )
    caller = _RaisingCaller(error)
    handler = triage.make_handler(caller=caller)

    with pytest.raises(PermanentStageError, match="credit balance"):
        asyncio.run(handler(_message(analysis_id, tenant_id)))

    assert caller.calls == 1


def test_handler_lets_rate_limit_error_propagate_unchanged(
    analysis_with_one_incident: tuple[uuid.UUID, uuid.UUID],
) -> None:
    analysis_id, tenant_id = analysis_with_one_incident
    error = _anthropic_error(
        anthropic.RateLimitError, status_code=429, error_type="rate_limit_error", message="slow"
    )
    caller = _RaisingCaller(error)
    handler = triage.make_handler(caller=caller)

    # Not wrapped in PermanentStageError -- the exact same exception type/instance base_worker
    # sees, so its existing retry-with-backoff policy still applies unchanged.
    with pytest.raises(anthropic.RateLimitError):
        asyncio.run(handler(_message(analysis_id, tenant_id)))

    assert caller.calls == 1


# ---------------------------------------------------------------------------- StageWorker-level:
# proves the attempt-count/dead-letter behavior this bug is actually about, against the real
# broker (see module docstring for why `triage` is safe to publish to in this environment).


@pytest.fixture(autouse=True)
def _fresh_redis_client() -> Iterator[None]:
    get_redis.cache_clear()
    yield
    get_redis.cache_clear()


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


async def test_bad_request_error_is_attempted_once_and_dead_letters(
    analysis_with_one_incident: tuple[uuid.UUID, uuid.UUID],
) -> None:
    analysis_id, tenant_id = analysis_with_one_incident
    error = _anthropic_error(
        anthropic.BadRequestError,
        status_code=400,
        error_type="invalid_request_error",
        message="Your credit balance is too low to access the Claude API.",
    )
    caller = _RaisingCaller(error)
    handler = triage.make_handler(caller=caller)

    worker = StageWorker(TEST_QUEUE, handler)
    worker_task = asyncio.create_task(worker.run())
    sink_task = asyncio.create_task(dead_letter_sink.run())
    try:
        connection = await get_connection()
        try:
            channel = await connection.channel()
            await declare_topology(channel)
            await publish_stage_message(channel, TEST_QUEUE, _message(analysis_id, tenant_id))
        finally:
            await connection.close()

        row = None
        deadline = time.monotonic() + 10
        while row is None and time.monotonic() < deadline:
            with get_engine().begin() as conn:
                row = (
                    conn.execute(
                        text(
                            "SELECT attempts, error FROM dead_letters WHERE analysis_id = :aid "
                            "ORDER BY id DESC LIMIT 1"
                        ),
                        {"aid": analysis_id},
                    )
                    .mappings()
                    .one_or_none()
                )
            if row is None:
                await asyncio.sleep(0.2)

        assert row is not None, "expected a dead_letters row"
        assert row["attempts"] == 1, "a 400 invalid_request_error must not be retried"
        assert "credit balance" in row["error"]
        # Give any wrongly-scheduled retry a moment to have fired, then confirm it never did.
        await asyncio.sleep(1.5)
        assert caller.calls == 1, "the LLM chain must not have been re-run on a retry"
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


@pytest.mark.parametrize(
    ("cls", "status", "error_type"),
    [
        (anthropic.RateLimitError, 429, "rate_limit_error"),
        (anthropic.OverloadedError, 529, "overloaded_error"),
    ],
)
async def test_transient_errors_are_still_retried_with_backoff(
    analysis_with_one_incident: tuple[uuid.UUID, uuid.UUID],
    cls: type[anthropic.APIStatusError],
    status: int,
    error_type: str,
) -> None:
    analysis_id, tenant_id = analysis_with_one_incident
    error = _anthropic_error(cls, status_code=status, error_type=error_type, message="transient")
    caller = _RaisingCaller(error)
    handler = triage.make_handler(caller=caller)

    worker = StageWorker(TEST_QUEUE, handler)
    worker_task = asyncio.create_task(worker.run())
    sink_task = asyncio.create_task(dead_letter_sink.run())
    try:
        connection = await get_connection()
        try:
            channel = await connection.channel()
            await declare_topology(channel)
            await publish_stage_message(channel, TEST_QUEUE, _message(analysis_id, tenant_id))
        finally:
            await connection.close()

        # The first retry is scheduled ~1s out (BACKOFF_SECONDS[0]) -- wait for a second
        # attempt to prove this class is NOT dead-lettered on attempt 1.
        deadline = time.monotonic() + 8
        while caller.calls < 2 and time.monotonic() < deadline:  # noqa: ASYNC110
            await asyncio.sleep(0.1)

        assert caller.calls >= 2, (
            f"a {status} {error_type} must still be retried, not dead-lettered on attempt 1"
        )

        with get_engine().begin() as conn:
            row = (
                conn.execute(
                    text("SELECT attempts FROM dead_letters WHERE analysis_id = :aid"),
                    {"aid": analysis_id},
                )
                .mappings()
                .one_or_none()
            )
        assert row is None, "must not have dead-lettered yet after only one retry"
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
