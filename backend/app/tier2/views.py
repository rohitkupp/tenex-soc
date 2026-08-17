"""The Tier 2 view allowlist — the single source of truth shared by two consumers that must
never drift apart:

1. `alembic/versions/*_tier2_readonly_role_and_views.py` creates exactly these two views
   and grants the `tier2_readonly` role `SELECT` on exactly these two views (and nothing
   else) -- `tests/test_tier2_readonly_role.py` asserts the live database matches this
   module, not the other way around.
2. `app.tier2.indicator_overlap`, `app.tier2.technique_prevalence`, and `app.tier2.
   first_seen` all read these views (not the base `tier2_signatures` table directly) for the
   dashboard's own deterministic queries -- one definition of "how many tenants saw this,"
   reused rather than re-derived across every chart.

A third consumer used to exist here: `app.tier2.sql_validator` rejected any NL-to-SQL-
generated query whose table references were not a subset of `ALLOWED_VIEWS`, and
`app.tier2.nl_to_sql` rendered `VIEW_SCHEMAS` into the model's system prompt. Both are
deleted (the chatbot they served is gone, under this task's cost constraint) -- `VIEW_SCHEMAS`
itself is kept, since `tests/test_tier2_migration.py::test_view_columns_match_the_declared_
schema` still asserts it against the live database as a drift guard independent of the
chatbot.

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
