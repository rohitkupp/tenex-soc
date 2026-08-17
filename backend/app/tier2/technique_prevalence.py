"""Query helper behind `GET /api/tier2/technique-prevalence` (Tier 2 chart 2) — which of the
13 proxy-observable ATT&CK techniques (`app.tier2.mitre_allowlist`) appear in how many
tenants, distinguishing systemic techniques (seen everywhere) from tenant-specific ones.

Like `app.tier2.indicator_overlap`, this reads `TIER2_SIGNATURES_VIEW` (the app's own DB
session, a fixed developer-written query -- no `tier2_readonly`-role involvement, docs/06's
concern is specifically LLM-generated SQL).

**Restricted to indicator-bearing signatures** -- `WHERE cardinality(indicator_hashes) > 0`.
Two independent reasons, both real:

1. **Consistency with chart 1.** `list_overlap_distribution`/`list_indicator_overlap` only
   ever consider indicators, which only ever come from signatures that carry at least one
   `indicator_hashes` entry. A technique-prevalence chart drawn from a *different* population
   (all signatures, indicator-bearing or not) could show a technique as "prevalent" here while
   chart 1 shows zero indicator evidence backing it at all -- two Tier 2 charts silently
   disagreeing about what counts as a cross-tenant observation. Restricting both to the same
   population keeps them honest against each other.
2. **This measurement, concretely.** At the time this chart was built, 36 of the 42 rows in
   `tier2_signatures` had `indicator_hashes = '{}'` and all shared one technique
   (`T1071.001`) and one `tenant_hash` per row -- leaked `tier2_signatures` rows from repeated
   `pytest` runs against this environment's shared dev database (`tests/fixtures/tier2.py`'s
   signature factory does not set `indicator_hashes` by default, and several tier2 test
   modules do not tear their rows down). Counting those would have reported `T1071.001` as
   "seen in 36+ tenants" -- a real number, but not a real cross-tenant signal; it is one test
   fixture's default, replayed by a test suite that keeps growing that count on every run this
   filter does not depend on. Reason 1 above is what actually justifies keeping the filter
   permanently (it would be the right query even in a spotless database); this is why it also
   happens to be the fix for today's specific mess.
"""

from __future__ import annotations

from typing import NamedTuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.tier2.mitre_allowlist import load_allowlisted_techniques
from app.tier2.views import TIER2_SIGNATURES_VIEW


class TechniquePrevalenceRow(NamedTuple):
    technique_id: str
    technique_name: str
    tenant_count: int
    signature_count: int


class TechniquePrevalenceResult(NamedTuple):
    total_tenants_with_signatures: int
    items: list[TechniquePrevalenceRow]


def list_technique_prevalence(session: Session) -> TechniquePrevalenceResult:
    allowlist = load_allowlisted_techniques()  # {id: name}, exactly 13 entries

    # The only interpolated value is TIER2_SIGNATURES_VIEW, a module-level constant from
    # app.tier2.views, never request data -- see module docstring for the cardinality filter.
    query = (
        f"SELECT technique, COUNT(DISTINCT tenant_hash) AS tenant_count, COUNT(*) AS signature_count "  # noqa: S608
        f"FROM {TIER2_SIGNATURES_VIEW}, unnest(mitre_techniques) AS technique "
        f"WHERE cardinality(indicator_hashes) > 0 "
        f"GROUP BY technique"
    )
    rows = session.execute(text(query)).all()
    observed = {row.technique: (row.tenant_count, row.signature_count) for row in rows}

    total_query = (
        f"SELECT COUNT(DISTINCT tenant_hash) FROM {TIER2_SIGNATURES_VIEW} "  # noqa: S608
        f"WHERE cardinality(indicator_hashes) > 0"
    )
    total_tenants = session.execute(text(total_query)).scalar_one()

    items = [
        TechniquePrevalenceRow(
            technique_id=tid,
            technique_name=name,
            tenant_count=observed.get(tid, (0, 0))[0],
            signature_count=observed.get(tid, (0, 0))[1],
        )
        for tid, name in allowlist.items()
    ]
    items.sort(key=lambda r: (-r.tenant_count, -r.signature_count, r.technique_id))
    return TechniquePrevalenceResult(total_tenants_with_signatures=total_tenants, items=items)
