"""Skeleton stages — `enrich`, `anonymize`, `detect`, `correlate`, `triage`, `respond`,
`tier2`. Their real implementations land at M5 through M14 (docs/13); this milestone's
brief is explicit about what they must do instead: "consume, update progress/counters
honestly, and forward. A skeleton stage must NOT claim work it did not do."

So each one, generically:

1. Updates `analyses.stage`/`progress` to its own stage (a real, honest transition —
   the analysis genuinely did reach this point in the pipeline).
2. Publishes a progress event to Redis whose `message` says in plain words that this is
   a pass-through skeleton and names the milestone that makes it real
   (`app.pipeline.contracts.SKELETON_MESSAGE`) — never a message implying detectors ran,
   entities were graphed, or an agent produced a verdict.
3. Does **not** touch `counters["signals"|"incidents"|"needs_attention"]` — those stay
   at whatever `parse` left them (0), because fabricating a signal/incident count here
   would be exactly the "claims work it did not do" the brief rules out.
4. Forwards the `StageMessage` to the next queue in `app.pipeline.contracts.NEXT_QUEUE`
   unchanged except for `stage`/`attempt`/`emitted_at` — or, for `tier2` (terminal),
   marks the analysis `complete` instead of forwarding anywhere.

One handler factory, `make_skeleton_handler`, rather than seven near-identical modules —
the seven stages differ only in name and successor, both looked up from
`app.pipeline.contracts`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from app.core.db import get_engine
from app.core.logging import get_logger
from app.pipeline import state
from app.pipeline.contracts import NEXT_QUEUE, SKELETON_MESSAGE, STAGE_PROGRESS, public_counters
from app.pipeline.messages import StageMessage
from app.pipeline.progress import publish_progress
from app.pipeline.redis_client import get_redis

log = get_logger(__name__)

SkeletonHandler = Callable[[StageMessage], Awaitable[list[tuple[str, StageMessage]]]]


def make_skeleton_handler(stage_name: str) -> SkeletonHandler:
    """`stage_name` must be a key in `app.pipeline.contracts.NEXT_QUEUE` (every skeleton
    stage, `tier2` included — its value there is `None`, meaning terminal)."""
    if stage_name not in NEXT_QUEUE:
        raise KeyError(f"{stage_name!r} is not a registered skeleton stage")
    next_queue = NEXT_QUEUE[stage_name]
    progress_message = SKELETON_MESSAGE[stage_name]
    progress_value = STAGE_PROGRESS[stage_name]

    async def handle(message: StageMessage) -> list[tuple[str, StageMessage]]:
        def _update() -> dict[str, Any]:
            with get_engine().begin() as conn:
                state.mark_stage(
                    conn,
                    analysis_id=message.analysis_id,
                    tenant_id=message.tenant_id,
                    stage=stage_name,
                    progress=progress_value,
                )
                if next_queue is None:
                    state.mark_complete(
                        conn, analysis_id=message.analysis_id, tenant_id=message.tenant_id
                    )
                return state.get_counters(
                    conn, analysis_id=message.analysis_id, tenant_id=message.tenant_id
                )

        counters = await asyncio.to_thread(_update)

        await publish_progress(
            get_redis(),
            analysis_id=message.analysis_id,
            stage=stage_name,
            progress=progress_value,
            status="complete" if next_queue is None else "running",
            message=progress_message,
            counters=public_counters(counters),
        )

        if next_queue is None:
            return []

        now = datetime.now(UTC)
        return [
            (
                next_queue,
                message.model_copy(update={"stage": next_queue, "attempt": 0, "emitted_at": now}),
            )
        ]

    return handle
