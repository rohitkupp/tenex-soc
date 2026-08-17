"""Query helper behind `GET /api/tier2/first-seen` (Tier 2 chart 4) — for indicators seen by
`min_tenants` or more tenants, when each tenant first observed it. The early-warning story:
"tenant A saw this on day 1, tenant B on day 4" is only worth telling once an indicator has
already cleared `list_indicator_overlap`'s own `min_tenants` bar, so this reuses that exact
qualification (`TIER2_INDICATOR_OVERLAP_VIEW`) rather than re-deriving a second notion of
"qualifies."

Same non-tenant-filtered reasoning as `app.tier2.indicator_overlap` — reads
`TIER2_SIGNATURES_VIEW`/`TIER2_INDICATOR_OVERLAP_VIEW` on the app's own session, no
`tier2_readonly`-role involvement (fixed, developer-written query, not LLM-generated SQL).
`tenant_hash` is the only tenant identity ever returned here, same as every other Tier 2
route — never a real tenant name, which the caller genuinely cannot recover from it.
"""

from __future__ import annotations

from datetime import datetime
from typing import NamedTuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.tier2.views import TIER2_INDICATOR_OVERLAP_VIEW, TIER2_SIGNATURES_VIEW


class TenantObservation(NamedTuple):
    tenant_hash: str
    first_observed_at: datetime


class FirstSeenIndicator(NamedTuple):
    indicator_hash: str
    tenant_count: int
    observations: list[TenantObservation]  # sorted first-seen ascending


def list_first_seen_propagation(
    session: Session, *, min_tenants: int = 2
) -> list[FirstSeenIndicator]:
    # The only interpolated values are the two view-name constants from app.tier2.views, never
    # request data — min_tenants is a bound parameter below.
    query = (
        "WITH qualifying AS ("  # noqa: S608
        f"  SELECT indicator_hash, tenant_count FROM {TIER2_INDICATOR_OVERLAP_VIEW} "
        "  WHERE tenant_count >= :min_tenants"
        "), per_tenant AS ("
        f"  SELECT ih AS indicator_hash, s.tenant_hash, MIN(s.observed_at) AS first_observed_at "
        f"  FROM {TIER2_SIGNATURES_VIEW} s, unnest(s.indicator_hashes) AS ih "
        "  GROUP BY ih, s.tenant_hash"
        ") "
        "SELECT q.indicator_hash, q.tenant_count, p.tenant_hash, p.first_observed_at "
        "FROM qualifying q JOIN per_tenant p ON p.indicator_hash = q.indicator_hash "
        "ORDER BY q.tenant_count DESC, q.indicator_hash, p.first_observed_at ASC"
    )
    rows = session.execute(text(query), {"min_tenants": min_tenants}).all()

    grouped: dict[str, FirstSeenIndicator] = {}
    for row in rows:
        entry = grouped.get(row.indicator_hash)
        if entry is None:
            entry = FirstSeenIndicator(
                indicator_hash=row.indicator_hash, tenant_count=row.tenant_count, observations=[]
            )
            grouped[row.indicator_hash] = entry
        entry.observations.append(
            TenantObservation(tenant_hash=row.tenant_hash, first_observed_at=row.first_observed_at)
        )
    # Rows already arrive tenant_count DESC, indicator_hash order -- dict preserves insertion order.
    return list(grouped.values())
