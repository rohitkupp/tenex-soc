"""`POST /api/incidents/{id}/feedback` — free-text analyst feedback, stored as a text file in
object storage next to the incident's own raw upload. That is the whole feature.

This replaces the learning loop that used to live behind this path (`app.api.learning` plus the
23 modules under `app/learning/`: calibration refits, suppression rules, benign-corpus
accumulation, exemplar banks, retrieval priors, entity threshold overrides, cohort assignment,
LightGBM retraining, verifier-rule proposals, few-shot memory). All of it is deleted. Feedback is
now written down and kept, and nothing reads it back — no model is refit, no threshold moves, no
prompt changes.

**Why that is a defensible scope and not a gap.** A learning loop is only honest if you can show
it improved something, and CLAUDE.md rule 2 is explicit that no model ships without beating a
baseline on the labeled eval set. Every consumer of this feedback was a mechanism whose effect
was never measured that way — and could not be, because the eval gate could never fail (three
independent reasons: an invalid CI workflow that meant CI never ran at all, missing detector
artifacts, and `baselines.json` never being written). Deleting the unmeasured half and keeping
the durable record is the smaller, truer claim.

## Storage layout

`app.storage.streaming_upload.new_storage_key` puts a raw upload at `{tenant_id}/{upload_id}`.
Feedback for an incident from that upload goes to:

    {tenant_id}/{upload_id}/feedback/{incident_id}/{utc_iso8601}.txt

Timestamped rather than one file per incident, so a second submission is a second record instead
of silently overwriting the first — an analyst correcting themselves is information, not a typo
to be erased. Keyed under the upload the incident came from so an incident's evidence and the
human judgement about it sit in one prefix.

The body is written verbatim as UTF-8. It is analyst-authored text, never shown to an LLM and
never parsed, so there is nothing to sanitize it *for*; the one thing that would matter — log
content flowing into a prompt (CLAUDE.md rule 3) — does not apply to a path nothing reads back.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette import status

from app.core.config import get_settings
from app.core.db import get_db
from app.core.errors import ApiError
from app.core.logging import get_logger
from app.core.security import CurrentUser, require_user
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.upload import Upload
from app.storage.client import ensure_bucket, get_s3_client

router = APIRouter()
log = get_logger(__name__)

# Long enough for a real paragraph of reasoning, bounded so a single request cannot stream an
# arbitrary object into the bucket.
MAX_FEEDBACK_CHARS = 8_000


class FeedbackRequest(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_FEEDBACK_CHARS)


class FeedbackResponse(BaseModel):
    """`storage_key` is returned so the analyst (and a reviewer) can see exactly where the
    feedback landed, rather than trusting that "saved" meant something."""

    incident_id: uuid.UUID
    storage_key: str
    submitted_at: datetime


@router.post(
    "/incidents/{incident_id}/feedback",
    response_model=FeedbackResponse,
    status_code=status.HTTP_201_CREATED,
)
def submit_incident_feedback(
    incident_id: uuid.UUID,
    body: FeedbackRequest,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> FeedbackResponse:
    """Store the analyst's own words about this incident. Nothing downstream consumes them."""
    tenant_id = current.tenant.id

    # Resolve incident -> analysis -> upload through tenant-scoped queries, so the storage prefix
    # is derived from rows this caller is actually allowed to see rather than from the path.
    with tenant_scope(db, tenant_id):
        row = db.execute(
            select(Upload.id)
            .join(Analysis, Analysis.upload_id == Upload.id)
            .join(Incident, Incident.analysis_id == Analysis.id)
            .where(Incident.id == incident_id)
        ).scalar_one_or_none()
    if row is None:
        raise ApiError(status_code=404, code="not_found", detail="Incident not found.")

    submitted_at = datetime.now(UTC)
    key = (
        f"{tenant_id}/{row}/feedback/{incident_id}/{submitted_at.strftime('%Y%m%dT%H%M%S%fZ')}.txt"
    )

    settings = get_settings()
    ensure_bucket()
    get_s3_client().put_object(
        Bucket=settings.s3_bucket,
        Key=key,
        Body=body.text.encode("utf-8"),
        ContentType="text/plain; charset=utf-8",
    )

    log.info(
        "feedback.stored",
        incident_id=str(incident_id),
        storage_key=key,
        chars=len(body.text),
    )
    return FeedbackResponse(incident_id=incident_id, storage_key=key, submitted_at=submitted_at)
