"""`GET /api/ops/queues`, `GET /api/ops/dead-letters`, `POST /api/ops/dead-letters/{id}/
retry` — docs/09's Ops section. (`GET /api/health` is the fourth Ops route in that
table but is explicitly "Unauthenticated" there and already lives in
`app.api.health`.)

**Auth.** Every route here requires `require_user` like the rest of the authenticated
API (docs/09: "All routes except auth require a valid JWT cookie"). There is no
separate operator/admin role in this system (CLAUDE.md: "Do not add auth features
beyond credentials login") and `dead_letters` itself carries no `tenant_id` (docs/02 —
see `app.models.dead_letter`'s docstring for why), so these routes are deliberately
**not** tenant-filtered: any authenticated user can see queue depths and every tenant's
dead letters. That is a real limitation of reusing customer login for an ops surface,
not an oversight — a production system would put this behind a distinct operator
credential. Documented here rather than silently narrowed, since narrowing it would
require inventing a tenant_id this table's own schema doesn't have.
"""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from app.core.db import get_db, get_engine
from app.core.errors import ApiError
from app.core.logging import get_logger
from app.core.security import CurrentUser, require_user
from app.models.dead_letter import DeadLetter
from app.pipeline import state
from app.pipeline.messages import StageMessage
from app.queue.inspect import all_queue_depths
from app.queue.publish import publish_stage_message
from app.queue.topology import declare_topology, get_connection, work_queue
from app.schemas.ops import (
    DeadLetterListResponse,
    DeadLetterOut,
    DeadLetterRetryResponse,
    QueueDepthOut,
    QueueDepthsResponse,
)

router = APIRouter()
log = get_logger(__name__)


def _not_found() -> ApiError:
    return ApiError(status_code=404, code="not_found", detail="Dead letter not found.")


def _encode_cursor(created_at: datetime, dead_letter_id: int) -> str:
    raw = f"{created_at.isoformat()}|{dead_letter_id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, int]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        created_at_str, id_str = raw.split("|", 1)
        return datetime.fromisoformat(created_at_str), int(id_str)
    except (ValueError, binascii.Error) as exc:
        raise ApiError(status_code=400, code="invalid_cursor", detail="Invalid cursor.") from exc


@router.get("/ops/queues", response_model=QueueDepthsResponse)
async def get_queue_depths(
    current: Annotated[CurrentUser, Depends(require_user)],
) -> QueueDepthsResponse:
    depths = await all_queue_depths()
    return QueueDepthsResponse(
        items=[
            QueueDepthOut(queue=d.queue, messages=d.messages, consumers=d.consumers) for d in depths
        ]
    )


@router.get("/ops/dead-letters", response_model=DeadLetterListResponse)
def list_dead_letters(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    cursor: str | None = None,
) -> DeadLetterListResponse:
    stmt = (
        select(DeadLetter)
        .order_by(DeadLetter.created_at.desc(), DeadLetter.id.desc())
        .limit(limit + 1)
    )
    if cursor is not None:
        cursor_created_at, cursor_id = _decode_cursor(cursor)
        stmt = stmt.where(
            tuple_(DeadLetter.created_at, DeadLetter.id) < (cursor_created_at, cursor_id)
        )
    rows = db.execute(stmt).scalars().all()

    has_more = len(rows) > limit
    page = rows[:limit]
    items = [DeadLetterOut.model_validate(row) for row in page]
    next_cursor = _encode_cursor(page[-1].created_at, page[-1].id) if has_more and page else None
    return DeadLetterListResponse(items=items, next_cursor=next_cursor)


@router.post("/ops/dead-letters/{dead_letter_id}/retry", response_model=DeadLetterRetryResponse)
async def retry_dead_letter(
    dead_letter_id: int,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> DeadLetterRetryResponse:
    row = db.get(DeadLetter, dead_letter_id)
    if row is None:
        raise _not_found()

    try:
        message = StageMessage.model_validate(row.payload)
    except Exception as exc:
        raise ApiError(
            status_code=400,
            code="not_retryable",
            detail=f"dead letter {dead_letter_id} has no retryable StageMessage payload: {exc}",
        ) from exc

    fresh_message = message.model_copy(update={"attempt": 0, "emitted_at": datetime.now(UTC)})
    target_queue = row.stage  # the logical queue name at time of failure, e.g. "parse.zscaler"

    connection = await get_connection()
    try:
        channel = await connection.channel()
        await declare_topology(channel)
        await publish_stage_message(channel, target_queue, fresh_message)
    finally:
        await connection.close()

    retried_at = datetime.now(UTC)
    row.retried_at = retried_at
    db.add(row)

    with get_engine().begin() as conn:
        state.reopen_for_retry(conn, analysis_id=message.analysis_id, tenant_id=message.tenant_id)

    log.info(
        "ops.dead_letter_retried",
        dead_letter_id=dead_letter_id,
        analysis_id=str(message.analysis_id),
        queue=work_queue(target_queue),
    )

    return DeadLetterRetryResponse(
        id=dead_letter_id, republished_to=work_queue(target_queue), retried_at=retried_at
    )
