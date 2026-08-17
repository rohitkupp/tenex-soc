"""Query helpers behind `GET /api/tier2/overview`, `GET /api/tier2/indicator-overlap`, and
`GET /api/tier2/overlap-distribution` (docs/09). These run on the app's own DB session (the
caller is an authenticated analyst hitting a fixed, developer-written query — not free-form
LLM-generated SQL, and there is no such query left in this codebase, since the NL-to-SQL
chatbot that used to make that distinction meaningful is gone), so there is no
`tier2_readonly`-role involvement here; the safety property these functions rely on is
structural instead: `tier2_signatures` (docs/02) was never allowed to carry a raw indicator
value or a tenant identity in the first place (see `app.models.tier2_signature`'s docstring),
so there is nothing for a query against it to leak regardless of which role runs it.

All three functions read the same two views (`app.tier2.views`), not the base table directly
— one definition of "cross-tenant overlap," reused rather than re-derived, so this module's
own functions can never silently disagree with each other about what "overlap" means.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, NamedTuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.tier2.views import TIER2_INDICATOR_OVERLAP_VIEW, TIER2_SIGNATURES_VIEW


class IndicatorOverlapRow(NamedTuple):
    indicator_hash: str
    signature_count: int
    tenant_count: int
    incident_types: list[str]
    first_observed_at: datetime
    last_observed_at: datetime


class OverlapBucket(NamedTuple):
    bucket: str  # "1" | "2" | "3+"
    indicator_count: int


class OverlapDistribution(NamedTuple):
    total_indicators: int
    buckets: list[OverlapBucket]


_BUCKET_ORDER = ("1", "2", "3+")


def list_indicator_overlap(
    session: Session, *, min_tenants: int = 2, limit: int = 50
) -> list[IndicatorOverlapRow]:
    """Indicators seen by `min_tenants` or more distinct tenants, most-overlapping first.
    `min_tenants=2` is the literal feature: "this domain appeared in 3 other tenants" only
    means something once at least two tenants are in the picture at all."""
    # The only interpolated value is TIER2_INDICATOR_OVERLAP_VIEW, a module-level constant
    # from app.tier2.views, never request data — the actual request-supplied values
    # (min_tenants, limit) are bound parameters below, not interpolated.
    query = (
        f"SELECT indicator_hash, signature_count, tenant_count, incident_types, "  # noqa: S608
        f"first_observed_at, last_observed_at FROM {TIER2_INDICATOR_OVERLAP_VIEW} "
        f"WHERE tenant_count >= :min_tenants "
        f"ORDER BY tenant_count DESC, signature_count DESC, indicator_hash "
        f"LIMIT :limit"
    )
    rows = session.execute(text(query), {"min_tenants": min_tenants, "limit": limit}).all()
    return [IndicatorOverlapRow(*row) for row in rows]


def list_overlap_distribution(session: Session) -> OverlapDistribution:
    """Tier 2 chart 1 ("Indicator overlap distribution"): every distinct indicator signature,
    bucketed by how many tenants have seen it — `1`, `2`, or `3+`. Unlike
    `list_indicator_overlap` (which only ever returns `tenant_count >= 2` rows, since that is
    literally what "overlap" means), this includes the `1`-tenant bucket too: the point of a
    *distribution* is showing that bucket as the expected majority, not hiding it.

    Reads `TIER2_INDICATOR_OVERLAP_VIEW`, same as `list_indicator_overlap` — one definition of
    "how many tenants saw this indicator," reused rather than re-derived. A `tier2_signatures`
    row with an empty `indicator_hashes` array (e.g. a signature synced from an incident with
    no domain/dst-IP entity) contributes no rows to this view at all (nothing to `unnest`), so
    it is structurally excluded here exactly as it is from `list_indicator_overlap` — not a
    special case, the same `unnest` semantics both queries already depend on.
    """
    # The only interpolated value is TIER2_INDICATOR_OVERLAP_VIEW, a module-level constant
    # from app.tier2.views, never request data.
    query = (
        f"SELECT CASE WHEN tenant_count = 1 THEN '1' "  # noqa: S608
        f"WHEN tenant_count = 2 THEN '2' ELSE '3+' END AS bucket, "
        f"COUNT(*) AS indicator_count "
        f"FROM {TIER2_INDICATOR_OVERLAP_VIEW} GROUP BY 1"
    )
    rows = session.execute(text(query)).all()
    counts = {row.bucket: row.indicator_count for row in rows}
    buckets = [OverlapBucket(bucket=b, indicator_count=counts.get(b, 0)) for b in _BUCKET_ORDER]
    return OverlapDistribution(
        total_indicators=sum(b.indicator_count for b in buckets), buckets=buckets
    )


class IncidentTypeBreakdown(NamedTuple):
    incident_type: str
    signature_count: int
    tenant_count: int
    avg_confidence: float


class Tier2Overview(NamedTuple):
    total_signatures: int
    total_tenants: int
    total_overlapping_indicators: int
    by_incident_type: list[IncidentTypeBreakdown]


def get_overview(session: Session) -> Tier2Overview:
    """Cross-tenant aggregates for `GET /api/tier2/overview` — totals plus a per-
    incident-type breakdown, every number computed over `tenant_hash`/`indicator_hash`,
    never a raw tenant or indicator value."""
    # Every interpolated value below is a module-level view-name constant from
    # app.tier2.views, never request data — there is no user input in this function at all.
    totals_query = (
        f"SELECT COUNT(*) AS total_signatures, "  # noqa: S608
        f"COUNT(DISTINCT tenant_hash) AS total_tenants "
        f"FROM {TIER2_SIGNATURES_VIEW}"
    )
    totals = session.execute(text(totals_query)).one()

    overlap_count_query = (
        f"SELECT COUNT(*) FROM {TIER2_INDICATOR_OVERLAP_VIEW} WHERE tenant_count >= 2"  # noqa: S608
    )
    overlapping = session.execute(text(overlap_count_query)).scalar_one()

    breakdown_query = (
        f"SELECT incident_type, COUNT(*) AS signature_count, "  # noqa: S608
        f"COUNT(DISTINCT tenant_hash) AS tenant_count, AVG(confidence) AS avg_confidence "
        f"FROM {TIER2_SIGNATURES_VIEW} GROUP BY incident_type "
        f"ORDER BY signature_count DESC"
    )
    breakdown_rows: list[Any] = session.execute(text(breakdown_query)).all()

    return Tier2Overview(
        total_signatures=totals.total_signatures,
        total_tenants=totals.total_tenants,
        total_overlapping_indicators=overlapping,
        by_incident_type=[
            IncidentTypeBreakdown(
                incident_type=row.incident_type,
                signature_count=row.signature_count,
                tenant_count=row.tenant_count,
                avg_confidence=float(row.avg_confidence),
            )
            for row in breakdown_rows
        ],
    )
