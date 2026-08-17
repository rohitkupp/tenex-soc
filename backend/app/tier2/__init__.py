"""Tier 2 — cross-tenant threat intelligence (M14, docs/13).

What lives in this package:

1. **Signature sync** (`signature_sync.py`) — after an incident is triaged, a
   `tier2_signatures` row is emitted: `tenant_hash`, `incident_type`, `mitre_techniques`,
   `source_types`, `confidence`, `indicator_hashes`, `observed_at`, `embedding`. Never
   `tenant_id`, never a raw domain/IP, never anything else identifiable — see
   docs/02-DATA-MODEL.md's own table comment and `app.models.tier2_signature`'s docstring
   for why that table structurally cannot carry tenant identity.
2. **Cross-tenant indicator overlap** (`indicator_overlap.py`) — "this C2 domain appeared
   in 3 other tenants" without any tenant ever seeing another's raw indicator value.
3. **Cross-tenant learning charts** (`technique_prevalence.py`, `detector_reliability.py`,
   `first_seen.py`) — the dashboard behind `/tier2`, all deterministic queries over
   `tier2_signatures` or, for `detector_reliability.py` specifically, real operational
   tables pooled across every tenant on purpose — see that module's own docstring.
4. **`readonly_db.py` / `views.py`** — the dedicated, SELECT-only `tier2_readonly` Postgres
   role and the two views it may read. These used to back a natural-language-to-SQL chatbot
   (`POST /api/tier2/query`, `sql_validator.py`, `nl_to_sql.py`) that has since been removed
   under a hard cost constraint on this task (no code path may make a live Anthropic call).
   The role/views are kept: `tests/test_tier2_readonly_role.py` and
   `tests/test_tier2_migration.py` still prove, against the real database, that this role
   genuinely cannot reach `events`/`users`/tenant-identifying tables — a DB-enforced
   guarantee worth keeping even with no application caller today, and dropping the role or
   its migration would be a schema change out of scope for this cleanup.

## The salt tradeoff (docs/06, stated here explicitly, not buried)

Every pseudonym in this system (`app.privacy.pseudonymize`) is HMAC'd with a **per-tenant**
salt (`tenants.pseudonym_salt`) — deliberately unique per tenant, so no two tenants' hashes
of the same underlying value can ever collide, and no external party could correlate
identity across tenants even with a compromised salt from one of them. That is the right
default for everything that identifies a *principal* (a user, an IP, a hostname).

Tier 2 indicator hashes (`indicator_hashes` — domains and destination IPs, and *only*
those two kinds, computed by `app.privacy.pseudonymize.indicator_hash`) are the one
deliberate exception: they use a single **shared** salt across every tenant
(`settings.tier2_indicator_salt`), so the same domain hashes to the same value no matter
which tenant observed it. That is what makes "this domain appeared in 3 other tenants" a
question this system can answer at all — with a per-tenant salt on indicators, the same C2
domain would hash to N different, uncorrelatable values across N tenants and the whole
feature would silently do nothing (every "overlap" query would find none, forever, with no
error to notice). This is the real privacy/utility tradeoff CLAUDE.md calls out: a
sufficiently resourced adversary who already knows a candidate domain/IP can confirm
whether *some* tenant saw it (that's the feature working as designed); they learn nothing
about which tenant, and nothing about anything else in that tenant's data. Getting this
backwards — a per-tenant salt on indicators, or the shared salt anywhere near a principal
— is exactly the two failure modes CLAUDE.md warns about, in either direction.

`tenant_hash` (identifying *which* row belongs to *a* tenant, without revealing *which*
tenant) is not an indicator and is **not** part of this exception: `app.tier2.hashing`
computes it with each tenant's own per-tenant `pseudonym_salt`, exactly like every other
principal-shaped value in the system. It only needs to be *stable and distinct per tenant*
(so `COUNT(DISTINCT tenant_hash)` means "N tenants") — it never needs to match across
tenants the way an indicator hash does, so there is no reason to weaken it.
"""

from __future__ import annotations
