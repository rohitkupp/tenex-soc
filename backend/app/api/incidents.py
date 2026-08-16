"""Verdict endpoints — docs/09-API-CONTRACT.md.

docs/09 folds the verdict into `GET /api/incidents/{id}`'s full incident detail ("signals with
explanations, entities, timeline, verdict") — that composite endpoint spans several milestones'
data (`app/graph` signals/entities/timeline, `app/agent` verdict) and is not this module's to
build whole. What CLAUDE.md scopes to this file is the verdict slice specifically:

    POST /api/incidents/{incident_id}/triage    trigger (or re-trigger, ?force=true) triage
    GET  /api/incidents/{incident_id}/verdict    fetch the latest verdict
    POST /api/analyses/{analysis_id}/triage      triage the top MAX_TRIAGE_INCIDENTS by fused_score

Every route requires an authenticated, tenant-scoped caller (docs/06), same as
`app.api.analyses` — tenant scoping is structural (`app.models.base`), never a filter a handler
could forget.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agent.context import AgentContextError
from app.agent.orchestrator import (
    MissingAPIKeyError,
    triage_incident,
    triage_top_incidents_for_analysis,
)
from app.core.db import get_db
from app.core.errors import ApiError
from app.core.security import CurrentUser, require_user
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.triage_verdict import TriageVerdict
from app.schemas.agent import TriageVerdictListResponse, TriageVerdictResponse

router = APIRouter()


def _not_found(detail: str) -> ApiError:
    return ApiError(status_code=404, code="not_found", detail=detail)


def _require_incident(db: Session, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> Incident:
    """Confirms `incident_id` exists *and belongs to this tenant* before any triage/verdict
    lookup runs — `tenant_scope` makes a cross-tenant id 404 rather than leak, same guarantee
    `app.api.analyses._not_found` relies on for `analyses`."""
    with tenant_scope(db, tenant_id):
        incident = db.execute(
            select(Incident).where(Incident.id == incident_id)
        ).scalar_one_or_none()
    if incident is None:
        raise _not_found("Incident not found.")
    return incident


def _require_analysis(db: Session, tenant_id: uuid.UUID, analysis_id: uuid.UUID) -> Analysis:
    with tenant_scope(db, tenant_id):
        analysis = db.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        ).scalar_one_or_none()
    if analysis is None:
        raise _not_found("Analysis not found.")
    return analysis


def _no_api_key() -> ApiError:
    return ApiError(
        status_code=503,
        code="anthropic_api_key_not_configured",
        detail=(
            "Agent triage requires ANTHROPIC_API_KEY to be configured. DEMO_MODE and the "
            "no-key fallback have been removed — set the key and retry."
        ),
    )


@router.post("/incidents/{incident_id}/triage", response_model=TriageVerdictResponse)
def trigger_incident_triage(
    incident_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
    force: Annotated[
        bool, Query(description="Re-triage even if a verdict already exists.")
    ] = False,
) -> TriageVerdictResponse:
    """Idempotent by default (`app.agent.orchestrator.triage_incident`'s own docstring): a
    second call with `force=false` (the default) returns the existing verdict rather than
    spending on a second LLM run. `force=true` re-triages regardless."""
    _require_incident(db, current.tenant.id, incident_id)
    try:
        verdict = triage_incident(db, current.tenant.id, incident_id, force=force)
    except AgentContextError as exc:
        raise _not_found(str(exc)) from exc
    except MissingAPIKeyError as exc:
        raise _no_api_key() from exc
    return TriageVerdictResponse.model_validate(verdict)


@router.get("/incidents/{incident_id}/verdict", response_model=TriageVerdictResponse)
def get_incident_verdict(
    incident_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> TriageVerdictResponse:
    _require_incident(db, current.tenant.id, incident_id)
    # TriageVerdict is not tenant-scoped (docs/02: isolation is transitive through incident_id,
    # app.models.triage_verdict's own docstring) — the incident lookup above already proved
    # incident_id belongs to this tenant, so no further scoping is needed or possible here.
    verdict = db.execute(
        select(TriageVerdict)
        .where(TriageVerdict.incident_id == incident_id)
        .order_by(TriageVerdict.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if verdict is None:
        raise _not_found("This incident has not been triaged yet.")
    return TriageVerdictResponse.model_validate(verdict)


@router.post("/analyses/{analysis_id}/triage", response_model=TriageVerdictListResponse)
def trigger_analysis_triage(
    analysis_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
    force: Annotated[
        bool, Query(description="Re-triage every incident even if already triaged.")
    ] = False,
) -> TriageVerdictListResponse:
    """docs/07 "Scope discipline": only the top `MAX_TRIAGE_INCIDENTS` by `fused_score` for this
    analysis. Recurrences among them inherit their parent's verdict rather than re-running the
    LLM (`app.agent.orchestrator.triage_incident`)."""
    _require_analysis(db, current.tenant.id, analysis_id)
    try:
        verdicts = triage_top_incidents_for_analysis(
            db, current.tenant.id, analysis_id, force=force
        )
    except MissingAPIKeyError as exc:
        raise _no_api_key() from exc
    return TriageVerdictListResponse(
        items=[TriageVerdictResponse.model_validate(v) for v in verdicts]
    )
