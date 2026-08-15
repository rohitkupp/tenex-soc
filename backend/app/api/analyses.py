"""GET /api/analyses, GET /api/analyses/{id}, DELETE /api/analyses/{id} — docs/09.

Every route requires an authenticated, tenant-scoped caller (docs/06); tenant scoping
itself is structural (`app.models.base`), not a filter a handler could forget.

`analyses` has no `created_at` column — docs/02-DATA-MODEL.md is matched exactly, see
`app.models.analysis`. "Newest first" is therefore ordered by the parent upload's
`created_at` (an upload and its analysis are created together, 1:1, in
`app.api.uploads`), with `analysis.id` as a tiebreaker for the keyset cursor.
"""

from __future__ import annotations

import base64
import binascii
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session
from starlette import status

from app.core.db import get_db
from app.core.errors import ApiError
from app.core.security import CurrentUser, require_user
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.upload import Upload
from app.schemas.uploads import AnalysisListResponse, AnalysisOut

router = APIRouter()


def _not_found() -> ApiError:
    return ApiError(status_code=404, code="not_found", detail="Analysis not found.")


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
