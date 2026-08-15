"""`GET /api/ops/queues` support — depth per queue, read straight off the broker via a
passive `queue.declare` (the AMQP-native way to ask "how many messages/consumers does
this queue have" without an HTTP management-plugin dependency; the API already needs an
AMQP connection to publish, so this reuses that same access rather than requiring
RabbitMQ's management HTTP API to be reachable/credentialed separately).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.queue.topology import (
    QUEUE_NAMES,
    dead_letter_queue,
    declare_topology,
    delay_queue,
    get_connection,
    work_queue,
)


@dataclass(slots=True)
class QueueDepth:
    queue: str
    messages: int
    consumers: int


async def all_queue_depths() -> list[QueueDepth]:
    connection = await get_connection()
    try:
        channel = await connection.channel()
        await declare_topology(channel)  # idempotent — guarantees every queue below exists

        names = [
            name
            for stage in QUEUE_NAMES
            for name in (work_queue(stage), delay_queue(stage), dead_letter_queue(stage))
        ]
        depths: list[QueueDepth] = []
        for name in names:
            queue = await channel.declare_queue(name, passive=True)
            result = queue.declaration_result
            depths.append(
                QueueDepth(
                    queue=name,
                    messages=int(result.message_count or 0) if result else 0,
                    consumers=int(result.consumer_count or 0) if result else 0,
                )
            )
        return depths
    finally:
        await connection.close()
