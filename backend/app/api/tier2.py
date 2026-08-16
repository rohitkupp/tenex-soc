"""`GET /api/tier2/overview`, `GET /api/tier2/indicator-overlap`, `POST /api/tier2/query`
— docs/09's Tier 2 section, docs/06's "Text-to-SQL safety" for the third.

**Auth, and why these are not tenant-filtered.** Every route requires `require_user`
(docs/09: "All routes except auth require a valid JWT cookie") but, like
`app.api.ops`, is deliberately **not** scoped to the caller's tenant: `tier2_signatures`
(docs/02) structurally carries no `tenant_id` at all, only `tenant_hash` — an anonymous,
non-reversible token that is the entire point of this feature (see
`app.tier2.__init__`'s docstring). There is no tenant to filter by, and that is not an
oversight; it is what makes "this indicator appeared in 3 other tenants" answerable in the
first place. Any authenticated analyst from any tenant sees the same cross-tenant
aggregates — never another tenant's raw data, because none of it is stored here.

**`POST /api/tier2/query` is the one route in this file with a real attack surface.** The
question flows to `app.tier2.nl_to_sql.answer_question`, which generates SQL (via Claude,
gated on `settings.llm_enabled`, or a canned example) and validates it
(`app.tier2.sql_validator`) before ever executing it, as the separately-privileged
`tier2_readonly` role (`app.tier2.readonly_db`). The generated SQL is always in the
response — rejected or not (docs/09: "especially then") — so this route never silently
swallows an attack attempt; it shows exactly what was tried and why it didn't run.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.security import CurrentUser, require_user
from app.schemas.tier2 import (
    IncidentTypeBreakdownOut,
    IndicatorOverlapEntryOut,
    IndicatorOverlapResponse,
    Tier2OverviewResponse,
    Tier2QueryRequest,
    Tier2QueryResponse,
)
from app.tier2.indicator_overlap import get_overview, list_indicator_overlap
from app.tier2.nl_to_sql import answer_question

router = APIRouter()


@router.get("/tier2/overview", response_model=Tier2OverviewResponse)
def get_tier2_overview(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> Tier2OverviewResponse:
    overview = get_overview(db)
    return Tier2OverviewResponse(
        total_signatures=overview.total_signatures,
        total_tenants=overview.total_tenants,
        total_overlapping_indicators=overview.total_overlapping_indicators,
        by_incident_type=[
            IncidentTypeBreakdownOut(
                incident_type=row.incident_type,
                signature_count=row.signature_count,
                tenant_count=row.tenant_count,
                avg_confidence=row.avg_confidence,
            )
            for row in overview.by_incident_type
        ],
    )


@router.get("/tier2/indicator-overlap", response_model=IndicatorOverlapResponse)
def get_indicator_overlap(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
    min_tenants: Annotated[int, Query(ge=2, le=1000)] = 2,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> IndicatorOverlapResponse:
    rows = list_indicator_overlap(db, min_tenants=min_tenants, limit=limit)
    return IndicatorOverlapResponse(
        items=[
            IndicatorOverlapEntryOut(
                indicator_hash=row.indicator_hash,
                signature_count=row.signature_count,
                tenant_count=row.tenant_count,
                incident_types=row.incident_types,
                first_observed_at=row.first_observed_at,
                last_observed_at=row.last_observed_at,
            )
            for row in rows
        ]
    )


@router.post("/tier2/query", response_model=Tier2QueryResponse)
def query_tier2(
    body: Tier2QueryRequest,
    current: Annotated[CurrentUser, Depends(require_user)],
) -> Tier2QueryResponse:
    # Deliberately synchronous (FastAPI runs a `def` route in a worker thread) -- both the
    # optional Anthropic call and the readonly-role DB call are blocking, same reasoning as
    # app.api.ops.list_dead_letters. `settings=get_settings()` resolved *here*, module-
    # level import, rather than left to answer_question's own default -- so tests can
    # monkeypatch this module's own `get_settings` name to force the skip path without a
    # live API key.
    result = answer_question(body.question, settings=get_settings())
    return Tier2QueryResponse(
        sql=result.sql,
        explanation=result.explanation,
        columns=result.columns,
        rows=result.rows,
        chart_hint=result.chart_hint,
        rejected=result.rejected,
        rejection_reason=result.rejection_reason,
    )
