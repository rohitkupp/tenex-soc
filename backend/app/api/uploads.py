"""POST /api/uploads — docs/09 + docs/06.

Streams the file straight to MinIO (see `app.storage.streaming_upload` for how, and
why the usual `UploadFile` parameter cannot be used here), sniffs source types from
the first ~50 lines, and writes the `uploads` + `analyses` rows. Does **not** kick off
the pipeline or open the SSE stream — that is M4.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from starlette import status

from app.core.config import get_settings
from app.core.db import get_db
from app.core.logging import get_logger
from app.core.rate_limit import limiter
from app.core.security import CurrentUser, require_user
from app.models.analysis import Analysis
from app.models.upload import Upload
from app.schemas.uploads import UploadCreateResponse
from app.storage.client import ensure_bucket
from app.storage.source_sniffer import detect_source_types
from app.storage.streaming_upload import new_storage_key, stream_upload_to_storage

router = APIRouter()
log = get_logger(__name__)


@router.post(
    "/uploads",
    response_model=UploadCreateResponse,
    status_code=status.HTTP_201_CREATED,
    # Manual multipart streaming (below) means FastAPI can't infer a request body
    # schema from the signature the way it does for `UploadFile`/`Form(...)` params.
    # Documented here instead so the OpenAPI schema — the frontend's source of truth
    # for types (CLAUDE.md) — still describes the real contract.
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "properties": {"file": {"type": "string", "format": "binary"}},
                        "required": ["file"],
                    }
                }
            },
        }
    },
)
@limiter.limit("10/hour")
async def create_upload(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> UploadCreateResponse:
    settings = get_settings()
    ensure_bucket()

    upload_id = uuid.uuid4()
    analysis_id = uuid.uuid4()
    storage_key = new_storage_key(tenant_id=current.tenant.id, upload_id=upload_id)

    result, filename = await stream_upload_to_storage(
        request, bucket=settings.s3_bucket, storage_key=storage_key
    )
    detected_sources = detect_source_types(result.sample_text)

    upload = Upload(
        id=upload_id,
        tenant_id=current.tenant.id,
        user_id=current.user.id,
        filename=filename,
        size_bytes=result.size_bytes,
        sha256=result.sha256_hex,
        storage_ref=result.storage_key,
        detected_sources=detected_sources,
    )
    db.add(upload)
    # Upload and Analysis have no ORM relationship() between them (deliberate — the
    # schema is plain FK columns per docs/02, not an object graph), so SQLAlchemy's
    # unit-of-work has no basis to order their inserts. Flushing the upload row first
    # guarantees it exists before analyses.upload_id references it.
    db.flush()

    analysis = Analysis(
        id=analysis_id,
        tenant_id=current.tenant.id,
        upload_id=upload_id,
        status="queued",
    )
    db.add(analysis)

    log.info(
        "uploads.created",
        upload_id=str(upload_id),
        analysis_id=str(analysis_id),
        tenant_id=str(current.tenant.id),
        size_bytes=result.size_bytes,
        detected_sources=detected_sources,
    )

    return UploadCreateResponse(
        upload_id=upload_id, detected_sources=detected_sources, analysis_id=analysis_id
    )
