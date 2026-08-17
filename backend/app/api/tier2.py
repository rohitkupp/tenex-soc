"""`GET /api/tier2/overview`, `GET /api/tier2/indicator-overlap`, and the four cross-tenant
learning charts below — docs/09's Tier 2 section.

**The NL-to-SQL chatbot (`POST /api/tier2/query`) has been removed.** It was the one route
in this file with a real attack surface (`app.tier2.nl_to_sql.answer_question`, generating
SQL via Claude and executing it as the separately-privileged `tier2_readonly` role) and it
is also the one route in this file that could make a live, billable Anthropic call. Removed
under a hard cost constraint that this surface must shrink, never grow. `app.tier2.nl_to_sql`
and `app.tier2.sql_validator` are deleted along with it. `app.tier2.readonly_db` and
`app.tier2.views` are **kept** — they are still exercised directly by
`tests/test_tier2_readonly_role.py`/`tests/test_tier2_migration.py` as a DB-enforced,
defense-in-depth proof that the `tier2_readonly` Postgres role genuinely cannot reach
`events`/`users`/tenant-identifying tables, independent of any application-level caller.
Dropping the role/migration itself would be a schema change, out of scope for this cleanup.

**Auth, and why none of these routes are tenant-filtered.** Every route requires
`require_user` (docs/09: "All routes except auth require a valid JWT cookie") but, like
`app.api.ops`, is deliberately **not** scoped to the caller's tenant: `tier2_signatures`
(docs/02) structurally carries no `tenant_id` at all, only `tenant_hash` — an anonymous,
non-reversible token that is the entire point of this feature (see
`app.tier2.__init__`'s docstring). There is no tenant to filter by, and that is not an
oversight; it is what makes "this indicator appeared in 3 other tenants" answerable in the
first place. Any authenticated analyst from any tenant sees the same cross-tenant
aggregates — never another tenant's raw data, because none of it is stored here.

`get_detector_reliability` is the one exception worth calling out by name: it reads real,
tenant-scoped operational tables (`analyst_feedback`/`triage_verdicts`/`incidents`/`signals`),
not the anonymized `tier2_signatures` table, and deliberately pools every tenant's feedback
with no `tenant_id` filter at all. See `app.tier2.detector_reliability`'s module docstring
for why that is a reviewed exception to `app.models.base`'s tenant-isolation guard, not a bug.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import CurrentUser, require_user
from app.schemas.tier2 import (
    DetectorReliabilityEntryOut,
    DetectorReliabilityResponse,
    FirstSeenIndicatorOut,
    FirstSeenResponse,
    FirstSeenTenantObservationOut,
    IncidentTypeBreakdownOut,
    IndicatorOverlapEntryOut,
    IndicatorOverlapResponse,
    OverlapBucketOut,
    OverlapDistributionResponse,
    TechniquePrevalenceEntryOut,
    TechniquePrevalenceResponse,
    Tier2OverviewResponse,
)
from app.tier2.detector_reliability import list_detector_reliability
from app.tier2.first_seen import list_first_seen_propagation
from app.tier2.indicator_overlap import (
    get_overview,
    list_indicator_overlap,
    list_overlap_distribution,
)
from app.tier2.technique_prevalence import list_technique_prevalence

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


# ---------------------------------------------------------------------------- cross-tenant learning charts


@router.get("/tier2/overlap-distribution", response_model=OverlapDistributionResponse)
def get_overlap_distribution(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> OverlapDistributionResponse:
    """Chart 1: for every indicator signature, how many distinct tenants have seen it,
    bucketed into 1 / 2 / 3+. The 2+ buckets are the cross-tenant signal itself."""
    dist = list_overlap_distribution(db)
    return OverlapDistributionResponse(
        total_indicators=dist.total_indicators,
        buckets=[
            OverlapBucketOut(bucket=row.bucket, indicator_count=row.indicator_count)
            for row in dist.buckets
        ],
    )


@router.get("/tier2/technique-prevalence", response_model=TechniquePrevalenceResponse)
def get_technique_prevalence(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> TechniquePrevalenceResponse:
    """Chart 2: which of the 13 proxy-observable ATT&CK techniques (docs/13 M14,
    `data/kb/mitre/allowlist.yml`) appear in how many tenants — every allowlisted technique
    is returned, including ones observed in zero tenants so far, never a fabricated id."""
    result = list_technique_prevalence(db)
    return TechniquePrevalenceResponse(
        total_tenants_with_signatures=result.total_tenants_with_signatures,
        items=[
            TechniquePrevalenceEntryOut(
                technique_id=row.technique_id,
                technique_name=row.technique_name,
                tenant_count=row.tenant_count,
                signature_count=row.signature_count,
            )
            for row in result.items
        ],
    )


@router.get("/tier2/detector-reliability", response_model=DetectorReliabilityResponse)
def get_detector_reliability(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
) -> DetectorReliabilityResponse:
    """Chart 3: per-detector confirm/dismiss counts pooled across every tenant's analyst
    feedback — see `app.tier2.detector_reliability`'s module docstring for why this route is
    a deliberate, reviewed exception to tenant scoping rather than an accidental leak."""
    result = list_detector_reliability(db)
    return DetectorReliabilityResponse(
        total_tenants=result.total_tenants,
        items=[
            DetectorReliabilityEntryOut(
                detector_key=row.detector_key,
                detector_layer=row.detector_layer,
                confirmed=row.confirmed,
                dismissed=row.dismissed,
            )
            for row in result.items
        ],
    )


@router.get("/tier2/first-seen", response_model=FirstSeenResponse)
def get_first_seen_propagation(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(require_user)],
    min_tenants: Annotated[int, Query(ge=2, le=1000)] = 2,
) -> FirstSeenResponse:
    """Chart 4: for indicators seen by `min_tenants` or more tenants, when each tenant first
    observed it — the early-warning story ("tenant A on day 1, tenant B on day 4")."""
    items = list_first_seen_propagation(db, min_tenants=min_tenants)
    return FirstSeenResponse(
        items=[
            FirstSeenIndicatorOut(
                indicator_hash=row.indicator_hash,
                tenant_count=row.tenant_count,
                observations=[
                    FirstSeenTenantObservationOut(
                        tenant_hash=obs.tenant_hash, first_observed_at=obs.first_observed_at
                    )
                    for obs in row.observations
                ],
            )
            for row in items
        ]
    )
