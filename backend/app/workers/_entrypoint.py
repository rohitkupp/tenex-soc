"""Shared `main()` for every `app/workers/*.py` entrypoint — configure logging, build
one `StageWorker`, run it forever. Each worker module is a one-liner that calls this
with its queue name and handler; kept as separate importable modules (rather than one
parametrized script) because docs/01 wants "a separate container with its own queue"
per worker — a distinct module per worker is what gives each one its own Dockerfile
`command:` in `docker-compose.yml`/`deploy/gcp/compose.prod.yml`.
"""

from __future__ import annotations

import asyncio

from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.pipeline.base_worker import StageHandler, StageWorker

log = get_logger(__name__)


def run_worker(queue_name: str, handler: StageHandler) -> None:
    configure_logging(get_settings().log_level)
    worker = StageWorker(queue_name, handler)
    try:
        asyncio.run(worker.run())
    except KeyboardInterrupt:
        log.info("worker.stopped", queue=queue_name)
