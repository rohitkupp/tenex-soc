"""GET /api/analyses, GET /api/analyses/{id}, DELETE /api/analyses/{id},
POST /api/analyses/{id}/retry — docs/09, as amended by docs/v2_migration change 27.

Every route requires an authenticated, tenant-scoped caller (docs/06); tenant scoping
itself is structural (`app.models.base`), not a filter a handler could forget.

`analyses` has no `created_at` column — docs/02-DATA-MODEL.md is matched exactly, see
`app.models.analysis`. "Newest first" is therefore ordered by the parent upload's
`created_at` (an upload and its analysis are created together, 1:1, in
`app.api.uploads`), with `analysis.id` as a tiebreaker for the keyset cursor.

`retry_analysis` is change 27's replacement for the deleted `POST /api/ops/dead-
letters/{id}/retry` (`app.api.ops`, removed along with the rest of `/ops` — "failures
surface on the analysis" instead of an ops console). Same republish mechanics as the
old route (find the dead-lettered `StageMessage` payload, republish it to its failing
queue with a fresh attempt budget, flip the analysis back to `running`), just addressed
by `analysis_id` — the id the analyst is already looking at — instead of a `dead_letter`
id from a console that no longer exists. `dead_letters` itself is unchanged and still
not tenant-scoped (see `app.models.dead_letter`'s docstring); this handler is safe
without a `tenant_id` filter on that table because it only ever looks up dead letters by
`analysis_id`, and the `analysis_id` itself was already resolved through a tenant-scoped
`Analysis` lookup above.
"""

from __future__ import annotations

import base64
import binascii
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session
from starlette import status

from app.core.db import get_db, get_engine
from app.core.errors import ApiError
from app.core.logging import get_logger
from app.core.security import CurrentUser, require_user
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.dead_letter import DeadLetter
from app.models.upload import Upload
from app.pipeline import state
from app.pipeline.messages import StageMessage
from app.queue.publish import publish_stage_message
from app.queue.topology import declare_topology, get_connection, work_queue
from app.schemas.uploads import AnalysisListResponse, AnalysisOut, AnalysisRetryResponse

router = APIRouter()
log = get_logger(__name__)


def _not_found() -> ApiError:
    return ApiError(status_code=404, code="not_found", detail="Analysis not found.")


def _not_retryable(detail: str, *, status_code: int = 404) -> ApiError:
    return ApiError(status_code=status_code, code="not_retryable", detail=detail)


def _encode_cursor(created_at: datetime, analysis_id: uuid.UUID) -> str:
    raw = f"{created_at.isoformat()}|{analysis_id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        created_at_str, id_str = raw.split("|", 1)
        return datetime.fromisoformat(created_at_str), uuid.UUID(id_str)
    except (ValueError, binascii.Error) as exc:
        raise ApiError(status_code=400, code="invalid_cursor", detail="Invalid cursor.") from exc


@router.get("/analyses", response_model=AnalysisListResponse)
def list_analyses(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    cursor: str | None = None,
) -> AnalysisListResponse:
    with tenant_scope(db, current.tenant.id):
        stmt = (
            select(Analysis, Upload.created_at)
            .join(Upload, Analysis.upload_id == Upload.id)
            .order_by(Upload.created_at.desc(), Analysis.id.desc())
            .limit(limit + 1)
        )
        if cursor is not None:
            cursor_created_at, cursor_id = _decode_cursor(cursor)
            stmt = stmt.where(
                tuple_(Upload.created_at, Analysis.id) < (cursor_created_at, cursor_id)
            )
        rows = db.execute(stmt).all()

    has_more = len(rows) > limit
    page = rows[:limit]
    items = [AnalysisOut.model_validate(analysis) for analysis, _ in page]
    next_cursor = _encode_cursor(page[-1][1], page[-1][0].id) if has_more and page else None
    return AnalysisListResponse(items=items, next_cursor=next_cursor)


@router.get("/analyses/{analysis_id}", response_model=AnalysisOut)
def get_analysis(
    analysis_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> AnalysisOut:
    with tenant_scope(db, current.tenant.id):
        analysis = db.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        ).scalar_one_or_none()
    if analysis is None:
        raise _not_found()
    return AnalysisOut.model_validate(analysis)


@router.delete("/analyses/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_analysis(
    analysis_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> None:
    with tenant_scope(db, current.tenant.id):
        analysis = db.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        ).scalar_one_or_none()
        if analysis is None:
            raise _not_found()
        db.delete(analysis)


@router.post("/analyses/{analysis_id}/retry", response_model=AnalysisRetryResponse)
async def retry_analysis(
    analysis_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> AnalysisRetryResponse:
    with tenant_scope(db, current.tenant.id):
        analysis = db.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        ).scalar_one_or_none()
    if analysis is None:
        raise _not_found()
    if analysis.status != "failed":
        raise _not_retryable(
            f"analysis {analysis_id} is not failed (status={analysis.status!r}).",
            status_code=409,
        )

    # `dead_letters` carries no tenant_id (see module docstring) — scoped by
    # `analysis_id` alone, which is safe here because `analysis_id` was already
    # resolved through the tenant-scoped lookup above. `retried_at IS NULL` picks the
    # dead letter this failure hasn't already been retried from, in case an earlier
    # retry itself failed and dead-lettered again.
    dead_letter = db.execute(
        select(DeadLetter)
        .where(DeadLetter.analysis_id == analysis_id, DeadLetter.retried_at.is_(None))
        .order_by(DeadLetter.created_at.desc(), DeadLetter.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    if dead_letter is None:
        raise _not_retryable(f"no retryable dead letter found for analysis {analysis_id}.")

    try:
        message = StageMessage.model_validate(dead_letter.payload)
    except Exception as exc:
        raise _not_retryable(
            f"dead letter {dead_letter.id} has no retryable StageMessage payload: {exc}",
            status_code=400,
        ) from exc

    fresh_message = message.model_copy(update={"attempt": 0, "emitted_at": datetime.now(UTC)})
    target_queue = dead_letter.stage  # the logical queue name at time of failure

    connection = await get_connection()
    try:
        channel = await connection.channel()
        await declare_topology(channel)
        await publish_stage_message(channel, target_queue, fresh_message)
    finally:
        await connection.close()

    retried_at = datetime.now(UTC)
    dead_letter.retried_at = retried_at
    db.add(dead_letter)

    with get_engine().begin() as conn:
        state.reopen_for_retry(conn, analysis_id=analysis_id, tenant_id=current.tenant.id)

    log.info(
        "analyses.retried",
        analysis_id=str(analysis_id),
        dead_letter_id=dead_letter.id,
        queue=work_queue(target_queue),
    )

    return AnalysisRetryResponse(
        analysis_id=analysis_id, republished_to=work_queue(target_queue), retried_at=retried_at
    )
