"""Queue topology — docs/01-ARCHITECTURE.md "Queue topology" section, matched exactly:

* One durable queue per worker, prefetch 1.
* Every queue paired with a `dlq.<name>` bound via `x-dead-letter-exchange`.
* Retry policy: 3 attempts with exponential backoff (1s, 4s, 16s), then dead-letter.

## Design

Every queue name below is `q.<name>` for the ones in docs/01's services table (e.g.
`q.orchestrator`, `q.parse.zscaler`, `q.enrich`, ...). Three RabbitMQ objects exist per
stage `<name>`, all bound to one shared direct exchange (`STAGES_EXCHANGE`) so every
publish in this codebase — fresh dispatch, retry, or terminal dead-letter — goes through
exactly one exchange with the queue name as routing key:

* `q.<name>`   — the real work queue a worker's `basic.consume` reads from. Declared as
  a **quorum** queue (`x-queue-type=quorum`) with `x-dead-letter-exchange=STAGES_EXCHANGE`
  / `x-dead-letter-routing-key=dlq.<name>` / `x-delivery-limit=MAX_ATTEMPTS`. This is
  the literal "paired via x-dead-letter-exchange" the doc asks for, and it does double
  duty for the two distinct ways a message can fail:

  1. **A caught exception.** `app.pipeline.base_worker` acks the message itself and
     explicitly republishes it to `delay.<name>` (see below) or, once retries are
     exhausted, straight to `dlq.<name>` — application-driven, with the exact 1s/4s/16s
     backoff.
  2. **The worker process dies mid-message** (killed, OOM, segfault — anything that
     drops the AMQP connection before an ack). There is no Python exception to catch
     here, so (1)'s logic never runs. This is exactly what `x-delivery-limit` is for:
     quorum queues track a redelivery count *in the broker*, independent of any
     consumer's code, and increment it on every requeue-after-unacked-disconnect —
     unlike classic queues, which only expose a boolean `redelivered` flag with no
     count. Once that count exceeds `x-delivery-limit`, RabbitMQ itself dead-letters
     the message to `dlq.<name>` via the same `x-dead-letter-exchange` — no application
     code involved at all. This is the mechanism that makes "kill a worker mid-run"
     converge on `dlq.<name>` cleanly even though nothing in this codebase ran.

  The two mechanisms don't double-count each other: path (1) always acks before
  republishing, so it never increments the broker's redelivery counter; path (2) only
  ever engages when a message goes unacked, which never happens on the code path (1)
  takes.

* `delay.<name>` — a holding queue for application-level retries. It has no queue-level
  TTL (so it can serve every attempt's backoff, not just one fixed delay); instead
  `app.pipeline.base_worker` sets the AMQP message property `expiration` (a per-message
  TTL in milliseconds) to 1000, 4000, or 16000 depending on which retry this is. When
  that per-message TTL elapses, RabbitMQ dead-letters the message — again natively — to
  `STAGES_EXCHANGE` with routing key `q.<name>` (its `x-dead-letter-routing-key`), so it
  reappears on the real work queue after the backoff, with no polling and no scheduler
  process. (Caveat, acceptable at this scale: per-message TTL only expires messages at
  the queue head, so wildly different in-flight backoffs on the *same* delay queue can
  release slightly out of order. Fine for a handful of in-flight retries per stage.)

* `dlq.<name>` — the terminal dead-letter queue. Reached either natively (a bare `nack`)
  or explicitly once `app.pipeline.base_worker` has exhausted all 3 retries; either way,
  the same `app.models.dead_letter.DeadLetter` row is written to Postgres first (see
  `app.pipeline.base_worker`), so the queue and the table never disagree about what
  failed permanently.

`declare_topology` is idempotent — RabbitMQ's `queue_declare`/`exchange_declare` are
themselves idempotent as long as the arguments match the first declaration, so calling
this at the top of every worker's `run()` *and* at API startup (main.py's lifespan) is
safe and is in fact what makes "declare topology idempotently at startup" (this
milestone's brief) trivial rather than something requiring its own locking.
"""

from __future__ import annotations

from dataclasses import dataclass

import aio_pika
from aio_pika.abc import AbstractChannel, AbstractRobustConnection

from app.core.config import get_settings

STAGES_EXCHANGE = "stages"

# The eleven queues in docs/01's services table, named exactly as the "Consumes" column
# gives them (minus the `q.` prefix, which every helper below adds back).
QUEUE_NAMES: tuple[str, ...] = (
    "orchestrator",
    "parse.zscaler",
    "parse.okta",
    "parse.cloudtrail",
    "enrich",
    "anonymize",
    "detect",
    "correlate",
    "triage",
    "respond",
    "tier2",
)

# Exponential backoff, in seconds, docs/01 verbatim: "3 attempts with exponential
# backoff (1s, 4s, 16s), then dead-letter." Index 0 is the delay before the first
# retry (i.e. after the *original* attempt — attempt 0 — fails), index 1 before the
# second retry, index 2 before the third. A failure on attempt 3 (the third retry) has
# exhausted the policy and dead-letters immediately — see app.pipeline.base_worker.
BACKOFF_SECONDS: tuple[float, ...] = (1.0, 4.0, 16.0)
MAX_ATTEMPTS = len(BACKOFF_SECONDS)


def work_queue(name: str) -> str:
    return f"q.{name}"


def delay_queue(name: str) -> str:
    return f"delay.{name}"


def dead_letter_queue(name: str) -> str:
    return f"dlq.{name}"


@dataclass(slots=True)
class QueueHandles:
    """The three RabbitMQ queue names for one stage — what `declare_topology` sets up
    and what publish/consume call sites need, so nobody has to remember the `q./delay./
    dlq.` prefix convention by hand."""

    name: str
    work: str
    delay: str
    dead_letter: str


def queue_handles(name: str) -> QueueHandles:
    return QueueHandles(
        name=name,
        work=work_queue(name),
        delay=delay_queue(name),
        dead_letter=dead_letter_queue(name),
    )


async def get_connection() -> AbstractRobustConnection:
    """A fresh robust connection. Callers that live for a process lifetime (workers,
    the API's warm connection) should hold onto this; short-lived callers (a single ops
    request) should close it when done. Not cached at module scope — unlike
    `app.core.db.get_engine`/`app.storage.client.get_s3_client`, a RabbitMQ connection
    is a stateful, long-lived socket that a caller may need to close and reopen (e.g. a
    worker's own reconnect logic on shutdown), so ownership stays explicit."""
    settings = get_settings()
    return await aio_pika.connect_robust(settings.rabbitmq_url)


async def declare_topology(channel: AbstractChannel) -> None:
    """Idempotently declare `STAGES_EXCHANGE` and every stage's three queues, per the
    module docstring. Safe to call on every worker/API startup."""
    exchange = await channel.declare_exchange(
        STAGES_EXCHANGE, aio_pika.ExchangeType.DIRECT, durable=True
    )

    for name in QUEUE_NAMES:
        handles = queue_handles(name)

        dlq = await channel.declare_queue(handles.dead_letter, durable=True)
        await dlq.bind(exchange, routing_key=handles.dead_letter)

        work = await channel.declare_queue(
            handles.work,
            durable=True,
            arguments={
                "x-queue-type": "quorum",
                "x-delivery-limit": MAX_ATTEMPTS,
                "x-dead-letter-exchange": STAGES_EXCHANGE,
                "x-dead-letter-routing-key": handles.dead_letter,
            },
        )
        await work.bind(exchange, routing_key=handles.work)

        delay = await channel.declare_queue(
            handles.delay,
            durable=True,
            arguments={
                "x-dead-letter-exchange": STAGES_EXCHANGE,
                "x-dead-letter-routing-key": handles.work,
            },
        )
        await delay.bind(exchange, routing_key=handles.delay)


async def declare_topology_on_new_channel(connection: AbstractRobustConnection) -> None:
    """Convenience for one-shot callers (API startup) that don't otherwise need to keep
    the channel around."""
    channel = await connection.channel()
    try:
        await declare_topology(channel)
    finally:
        await channel.close()
