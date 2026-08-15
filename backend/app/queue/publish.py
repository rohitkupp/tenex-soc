"""Publish helpers over `app.queue.topology`'s exchange/queue layout.

Every publish in the codebase — a fresh dispatch to the next stage, an application-level
retry, or a terminal dead-letter — goes through one of these three functions, so the
"queues carry references, never rows" size bound (`app.pipeline.messages`) and the
routing-key convention (`app.queue.topology`) are enforced in exactly one place each.
"""

from __future__ import annotations

from typing import Any

import aio_pika
from aio_pika.abc import AbstractChannel

from app.pipeline.messages import StageMessage, encode_stage_message
from app.queue.topology import STAGES_EXCHANGE, dead_letter_queue, delay_queue, work_queue


async def publish_stage_message(
    channel: AbstractChannel, queue_name: str, message: StageMessage
) -> None:
    """Fresh dispatch to `q.<queue_name>` — used by the orchestrator fanning out to
    parser queues and by every stage forwarding to the next one."""
    exchange = await channel.get_exchange(STAGES_EXCHANGE)
    routing_key = work_queue(queue_name)
    await exchange.publish(
        aio_pika.Message(
            body=encode_stage_message(message),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            content_type="application/json",
            type=message.stage,
        ),
        routing_key=routing_key,
    )


async def publish_retry(
    channel: AbstractChannel, queue_name: str, message: StageMessage, *, delay_seconds: float
) -> None:
    """Publish to `delay.<queue_name>` with a per-message TTL of `delay_seconds`. When
    that TTL elapses, RabbitMQ's native dead-lettering (declared on the delay queue,
    see `app.queue.topology.declare_topology`) drops it back onto `q.<queue_name>` —
    the actual backoff mechanism, driven entirely by the broker."""
    exchange = await channel.get_exchange(STAGES_EXCHANGE)
    routing_key = delay_queue(queue_name)
    await exchange.publish(
        aio_pika.Message(
            body=encode_stage_message(message),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            content_type="application/json",
            type=message.stage,
            expiration=delay_seconds,  # aio-pika accepts a float number of seconds
        ),
        routing_key=routing_key,
    )


_ERROR_HEADER = "x-stage-error"
_ERROR_HEADER_MAX_LEN = 1000


async def publish_dead_letter(
    channel: AbstractChannel, queue_name: str, message: StageMessage, *, error: str | None = None
) -> None:
    """Publish directly to `dlq.<queue_name>` — the explicit path `app.pipeline.
    base_worker` takes once retries are exhausted, run alongside (never instead of)
    writing the `dead_letters` Postgres row, so the queue and the table agree.

    `error`, if given, rides as the `x-stage-error` AMQP header — never in the message
    body. `StageMessage` is docs/01's envelope, exactly the fields specified there; the
    original exception text has no field to live in without violating that shape.
    Headers are transport metadata, not the envelope, so `app.pipeline.dead_letter_sink`
    can recover the real failure reason (for its `dead_letters.error` column) without
    this module smuggling an extra field into the documented message shape.
    """
    exchange = await channel.get_exchange(STAGES_EXCHANGE)
    routing_key = dead_letter_queue(queue_name)
    headers: dict[str, Any] = {_ERROR_HEADER: error[:_ERROR_HEADER_MAX_LEN]} if error else {}
    await exchange.publish(
        aio_pika.Message(
            body=encode_stage_message(message),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            content_type="application/json",
            type=message.stage,
            headers=headers,
        ),
        routing_key=routing_key,
    )
