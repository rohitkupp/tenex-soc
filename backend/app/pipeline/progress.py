"""Progress -> Redis — docs/01-ARCHITECTURE.md "Progress streaming", event shape
matched exactly (as amended — see "Terminal contract" below the original example in
that doc, added while this milestone was being built to close a real gap: see this
module's `status` parameter):

```json
{ "stage": "triage", "progress": 1.0, "status": "complete", "message": "Done",
  "counters": { "events": 1412903, "signals": 812, "incidents": 14, "needs_attention": 3 } }
```

`counters` always carries all four keys (defaulting to 0 via
`app.pipeline.contracts.DEFAULT_COUNTERS`) — docs/09's copy of this event and docs/02's
`analyses.counters` column comment both list `needs_attention` alongside the other
three; docs/01's own abbreviated first example omits it, but its own *second* (amended)
example includes it, so all three docs agree on the four-key shape once you read
docs/01 in full.

`status` is docs/01's "Terminal contract" addition: every event carries `status`, one of
`queued | running | complete | failed`, mirroring `analyses.status` — specified there
precisely so a client (or, here, `app.api.stream`) never has to *infer* terminality by
guessing which `stage` name is last, which would silently break every time a new stage
lands. `app.api.stream` (the SSE relay) forwards this payload to the browser
byte-for-byte — this is the exact wire shape, "state your exact SSE event JSON" in the
milestone report.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Literal

from redis.asyncio import Redis

from app.core.logging import get_logger

log = get_logger(__name__)

AnalysisStatus = Literal["queued", "running", "complete", "failed"]


def channel_name(analysis_id: uuid.UUID) -> str:
    return f"analysis:{analysis_id}"


async def publish_progress(
    redis_client: Redis,
    *,
    analysis_id: uuid.UUID,
    stage: str,
    progress: float,
    status: AnalysisStatus,
    message: str,
    counters: dict[str, Any],
) -> None:
    payload = {
        "stage": stage,
        "progress": progress,
        "status": status,
        "message": message,
        "counters": counters,
    }
    await redis_client.publish(channel_name(analysis_id), json.dumps(payload))
    log.info(
        "pipeline.progress",
        analysis_id=str(analysis_id),
        stage=stage,
        progress=progress,
        status=status,
        counters=counters,
    )
