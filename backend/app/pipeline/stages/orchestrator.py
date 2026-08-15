"""Orchestrator — docs/01's `ingest` stage contract:

* Precondition: file in MinIO (already true by the time this runs — the upload
  endpoint, `app.api.uploads`, streamed it there synchronously before this
  `StageMessage` was ever published).
* Postcondition: `analyses` row, source types detected, `pending_parsers` set.

Consumes `q.orchestrator`, reads the upload's already-sniffed `detected_sources`
(`app.parsers.registry.detect_source_types`, run at upload time), sets
`analyses.pending_parsers` to the number of detected source types, and fans out one
`StageMessage` per source type to that source's parser queue — the "parser fan-out is
parallel" requirement (docs/01), which here is simply "the handler returns N pairs
instead of 1"; `app.pipeline.base_worker` doesn't need to know fan-out is happening.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from app.core.db import get_engine
from app.core.logging import get_logger
from app.pipeline import state
from app.pipeline.contracts import DEFAULT_COUNTERS, PARSER_QUEUES, STAGE_PROGRESS
from app.pipeline.errors import PermanentStageError
from app.pipeline.messages import StageMessage
from app.pipeline.progress import publish_progress
from app.pipeline.redis_client import get_redis

log = get_logger(__name__)


def _start_ingest(message: StageMessage) -> dict[str, Any]:
    with get_engine().begin() as conn:
        upload = state.fetch_upload_for_analysis(
            conn, analysis_id=message.analysis_id, tenant_id=message.tenant_id
        )
        detected_sources = list(upload["detected_sources"] or [])
        if not detected_sources:
            raise PermanentStageError(
                f"upload {upload['upload_id']} has no detected source types — nothing to parse"
            )
        unknown = [s for s in detected_sources if s not in PARSER_QUEUES]
        if unknown:
            raise PermanentStageError(f"no parser queue registered for source type(s): {unknown}")

        state.start_ingest(
            conn,
            analysis_id=message.analysis_id,
            tenant_id=message.tenant_id,
            pending_parsers=len(detected_sources),
            progress=STAGE_PROGRESS["ingest"],
        )
        return {"storage_ref": upload["storage_ref"], "detected_sources": detected_sources}


async def handle(message: StageMessage) -> list[tuple[str, StageMessage]]:
    result = await asyncio.to_thread(_start_ingest, message)
    detected_sources: list[str] = result["detected_sources"]
    storage_ref: str = result["storage_ref"]

    await publish_progress(
        get_redis(),
        analysis_id=message.analysis_id,
        stage="ingest",
        progress=STAGE_PROGRESS["ingest"],
        status="running",
        message=(
            f"Detected {len(detected_sources)} source type(s): "
            f"{', '.join(detected_sources)}. Fanning out to parsers."
        ),
        counters=DEFAULT_COUNTERS,
    )

    now = datetime.now(UTC)
    return [
        (
            PARSER_QUEUES[source_type],
            StageMessage(
                analysis_id=message.analysis_id,
                tenant_id=message.tenant_id,
                stage="parse",
                storage_ref=storage_ref,
                source_type=source_type,
                attempt=0,
                emitted_at=now,
            ),
        )
        for source_type in detected_sources
    ]
