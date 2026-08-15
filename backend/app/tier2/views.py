"""The Tier 2 view allowlist — the single source of truth shared by three consumers that
must never drift apart:

1. `alembic/versions/*_tier2_readonly_role_and_views.py` creates exactly these two views
   and grants the `tier2_readonly` role `SELECT` on exactly these two views (and nothing
   else) -- `tests/test_tier2_readonly_role.py` asserts the live database matches this
   module, not the other way around.
2. `app.tier2.sql_validator` rejects any generated query whose table references are not a
   subset of `ALLOWED_VIEWS` -- the second, DB-independent layer of the same allowlist.
3. `app.tier2.nl_to_sql` renders `VIEW_SCHEMAS` into the system prompt so the model knows
   what it is allowed to query, instead of guessing at (or hallucinating) column names.

Both views select only from `tier2_signatures` (docs/02), which itself carries no
`tenant_id`, no raw indicator value, and no principal -- see `app.models.tier2_signature`'s
docstring. There is no privileged information these views could leak that the base table
doesn't already refuse to store.
"""

from __future__ import annotations

TIER2_SIGNATURES_VIEW = "tier2_signatures_v"
TIER2_INDICATOR_OVERLAP_VIEW = "tier2_indicator_overlap_v"

ALLOWED_VIEWS: frozenset[str] = frozenset({TIER2_SIGNATURES_VIEW, TIER2_INDICATOR_OVERLAP_VIEW})

# (column, type) pairs, in the exact order the migration's `CREATE VIEW` projects them --
# used only to describe the schema to the NL->SQL model and in tests that assert the live
# `information_schema.columns` output matches. Not used to build the SQL itself (the
# migration's raw `CREATE VIEW` text is the actual source of truth for that).
VIEW_SCHEMAS: dict[str, tuple[tuple[str, str], ...]] = {
    TIER2_SIGNATURES_VIEW: (
        ("id", "uuid"),
        ("tenant_hash", "text"),
        ("incident_type", "text"),
        ("mitre_techniques", "text[]"),
        ("source_types", "text[]"),
        ("confidence", "real"),
        ("indicator_hashes", "text[]"),
        ("observed_at", "timestamptz"),
    ),
    TIER2_INDICATOR_OVERLAP_VIEW: (
        ("indicator_hash", "text"),
        ("signature_count", "bigint"),
        ("tenant_count", "bigint"),
        ("incident_types", "text[]"),
        ("first_observed_at", "timestamptz"),
        ("last_observed_at", "timestamptz"),
    ),
}
