"""Tier 2 — cross-tenant threat intelligence (M14, docs/13).

Three things live in this package:

1. **Signature sync** (`signature_sync.py`) — after an incident is triaged, a
   `tier2_signatures` row is emitted: `tenant_hash`, `incident_type`, `mitre_techniques`,
   `source_types`, `confidence`, `indicator_hashes`, `observed_at`, `embedding`. Never
   `tenant_id`, never a raw domain/IP, never anything else identifiable — see
   docs/02-DATA-MODEL.md's own table comment and `app.models.tier2_signature`'s docstring
   for why that table structurally cannot carry tenant identity.
2. **Cross-tenant indicator overlap** (`indicator_overlap.py`) — "this C2 domain appeared
   in 3 other tenants" without any tenant ever seeing another's raw indicator value.
3. **NL-to-SQL** (`sql_validator.py`, `nl_to_sql.py`, `readonly_db.py`) — a chatbot over
   exactly two read-only views, treated as an attack surface (docs/06 "Text-to-SQL
   safety"), not a feature with security bolted on after.

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
