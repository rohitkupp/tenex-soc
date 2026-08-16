"""`app.queue.topology` against the real RabbitMQ from docker-compose.yml.

Proves the topology docs/01 asks for actually exists on the broker: one durable queue
per worker (quorum type, `x-delivery-limit` set), each paired with `dlq.<name>` via
`x-dead-letter-exchange`, and that declaring it twice (every worker's startup, plus the
API's) is a true no-op rather than an error.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from aio_pika.abc import AbstractChannel

from app.queue.topology import (
    BACKOFF_SECONDS,
    MAX_ATTEMPTS,
    QUEUE_NAMES,
    STAGES_EXCHANGE,
    dead_letter_queue,
    declare_topology,
    delay_queue,
    get_connection,
    work_queue,
)


@pytest.fixture
async def channel() -> AsyncIterator[AbstractChannel]:
    connection = await get_connection()
    try:
        ch = await connection.channel()
        yield ch
    finally:
        await connection.close()


async def test_declare_topology_is_idempotent(channel: AbstractChannel) -> None:
    await declare_topology(channel)
    await declare_topology(channel)  # must not raise


async def test_every_stage_has_a_quorum_work_queue_paired_with_a_dlq(
    channel: AbstractChannel,
) -> None:
    await declare_topology(channel)

    for name in QUEUE_NAMES:
        work = await channel.declare_queue(work_queue(name), passive=True)
        assert work.name == work_queue(name)

        dlq = await channel.declare_queue(dead_letter_queue(name), passive=True)
        assert dlq.name == dead_letter_queue(name)

        delay = await channel.declare_queue(delay_queue(name), passive=True)
        assert delay.name == delay_queue(name)


async def test_backoff_policy_matches_docs_01() -> None:
    assert BACKOFF_SECONDS == (1.0, 4.0, 16.0)
    assert MAX_ATTEMPTS == 3


async def test_stages_exchange_exists(channel: AbstractChannel) -> None:
    await declare_topology(channel)
    exchange = await channel.get_exchange(STAGES_EXCHANGE)
    assert exchange.name == STAGES_EXCHANGE


async def test_queue_names_cover_docs_01_services_table() -> None:
    # One parse queue today (`parse.zscaler`) -- Okta and CloudTrail's sibling queues were
    # removed along with those sources; this project is narrowed to ZScaler web proxy logs only.
    # `respond` was removed in docs/v2_migration change 20 -- `triage` now publishes directly
    # to `tier2`.
    assert set(QUEUE_NAMES) == {
        "orchestrator",
        "parse.zscaler",
        "enrich",
        "anonymize",
        "detect",
        "correlate",
        "triage",
        "tier2",
    }
