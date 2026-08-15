"""`python -m app.workers.dead_letter_sink` — consumes every `dlq.<name>` queue and
writes the corresponding `dead_letters` Postgres row. Not one of docs/01's eleven
named services (it does no pipeline work); see `app.pipeline.dead_letter_sink` for why
it exists as a single additional process rather than nothing at all — without it, a
message that dead-letters via a worker crash (`x-delivery-limit`, no application code
ever runs) would show up on the AMQP queue but never in `GET /api/ops/dead-letters`."""

from __future__ import annotations

import asyncio

from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.pipeline import dead_letter_sink

log = get_logger(__name__)


def main() -> None:
    configure_logging(get_settings().log_level)
    try:
        asyncio.run(dead_letter_sink.run())
    except KeyboardInterrupt:
        log.info("dead_letter_sink.stopped")


if __name__ == "__main__":
    main()
