"""tier2 readonly role and views

M14 (docs/13), docs/06-PRIVACY-SECURITY.md "Text-to-SQL safety": the database-level half of
the NL->SQL chatbot's defense in depth. `app.tier2.sql_validator` is the application-level
gate; this migration is what makes a bypass of that gate harmless anyway.

Two views, both `SELECT ... FROM tier2_signatures` only (docs/02) -- see
`app.tier2.views.VIEW_SCHEMAS` for the single source of truth these are matched to, and
that module's docstring for why the two must never drift apart:

* `tier2_signatures_v` -- every non-embedding column of `tier2_signatures`.
* `tier2_indicator_overlap_v` -- one row per indicator hash, `unnest`ed and aggregated
  across every tenant, so "how many tenants saw this" is a pre-computed column rather than
  something the NL->SQL model has to construct a correct `GROUP BY`/`unnest` for itself.

One new role, `tier2_readonly`:

* `LOGIN`, a password sourced from `settings.tier2_readonly_db_password` (never hardcoded
  here -- see below), `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION`.
* `statement_timeout = 5s`, set on the role itself (docs/06's literal wording), so it
  applies regardless of which session/tool connects as it.
* `GRANT SELECT` on exactly the two views above. No grant on `tier2_signatures` itself, and
  none on any other table -- `events`, `users`, and `pseudonym_map`/anything
  tenant-identifying are unreachable not because of an explicit `REVOKE` (Postgres already
  starts every new role at zero privileges on existing objects; nothing here needed a
  `REVOKE` to be safe) but because this role was simply never granted anything else. See
  `tests/test_tier2_readonly_role.py` for a real connection as this role proving that.

**Password provisioning.** `CREATE ROLE ... PASSWORD` / `ALTER ROLE ... PASSWORD` are DDL
and Postgres does not accept a bind parameter there (verified empirically -- `psycopg`
raises a syntax error on `$1` in that position), so the value from
`get_settings().tier2_readonly_db_password` is inlined as a single-quote-escaped SQL string
literal (`_quote_literal` below) rather than bound. This is not string-interpolating
*untrusted* input (CLAUDE.md's SQL rule is about request-time user input, not a
migration-time operator-controlled config value -- the same category as
`docs/06`'s own JWT_SECRET), but it is still escaped correctly rather than assumed safe.
`upgrade()` always re-runs `ALTER ROLE ... PASSWORD` even if the role already exists, so
`alembic upgrade head` is also how a password rotation gets pushed to the database in
whatever environment it runs in -- one source of truth, not two that can drift.

Revision ID: ccb431c4c689
Revises: c59cf17b44e7
Create Date: 2026-08-15 04:04:00.846969
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "ccb431c4c689"
down_revision: str | None = "c59cf17b44e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

READONLY_ROLE = "tier2_readonly"
SIGNATURES_VIEW = "tier2_signatures_v"
OVERLAP_VIEW = "tier2_indicator_overlap_v"


def _quote_literal(value: str) -> str:
    """Postgres single-quoted string literal, doubling embedded `'` -- the standard SQL
    escape, used because `PASSWORD` cannot be a bind parameter (see module docstring)."""
    return "'" + value.replace("'", "''") + "'"


def _quote_ident(value: str) -> str:
    """Postgres double-quoted identifier, doubling embedded `"`."""
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    # Imported here, not at module scope, so `alembic downgrade`/tooling that only needs
    # `down_revision` (no DB, no fully-configured Settings) never pays for it. Every other
    # migration in this repo already runs inside the app's own configured environment
    # (alembic/env.py sources the DSN from `get_settings()`), so this is consistent, not a
    # new pattern.
    from app.core.config import get_settings

    settings = get_settings()
    password_literal = _quote_literal(settings.tier2_readonly_db_password.get_secret_value())

    bind = op.get_bind()
    dbname = bind.execute(sa.text("SELECT current_database()")).scalar_one()

    role_exists = bind.execute(
        sa.text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": READONLY_ROLE}
    ).scalar_one_or_none()
    if role_exists is None:
        op.execute(
            f"CREATE ROLE {READONLY_ROLE} WITH LOGIN PASSWORD {password_literal} "
            "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION"
        )
    else:
        # Idempotent re-run (and the password-rotation path — see module docstring):
        # bring an existing role's password in line with current settings rather than
        # skipping it.
        op.execute(f"ALTER ROLE {READONLY_ROLE} WITH PASSWORD {password_literal}")

    # docs/06: "statement_timeout = 5s on the role." Set on the role so it applies no
    # matter what connects as it (app.tier2.readonly_db additionally sets this per
    # connection as defense in depth — see that module's docstring).
    op.execute(f"ALTER ROLE {READONLY_ROLE} SET statement_timeout = '5s'")

    op.execute(f"GRANT CONNECT ON DATABASE {_quote_ident(dbname)} TO {READONLY_ROLE}")
    op.execute(f"GRANT USAGE ON SCHEMA public TO {READONLY_ROLE}")

    # `CREATE OR REPLACE VIEW` so re-running this migration (or a future migration that
    # needs to adjust the view body without a data-shape change) never needs a DROP first.
    # Neither view selects `embedding` — a 1024-dim vector has no use in a text-to-SQL
    # answer and only bloats every result row.
    # (S608 suppressed below: SIGNATURES_VIEW/OVERLAP_VIEW are fixed module-level
    # constants, not user input — this is DDL text, not a query built from a request.)
    signatures_view_sql = (
        f"CREATE OR REPLACE VIEW {SIGNATURES_VIEW} AS "  # noqa: S608
        "SELECT id, tenant_hash, incident_type, mitre_techniques, source_types, "
        "confidence, indicator_hashes, observed_at "
        "FROM tier2_signatures"
    )
    op.execute(signatures_view_sql)

    overlap_view_sql = (
        f"CREATE OR REPLACE VIEW {OVERLAP_VIEW} AS "  # noqa: S608
        "SELECT indicator_hash, COUNT(*) AS signature_count, "
        "COUNT(DISTINCT tenant_hash) AS tenant_count, "
        "array_agg(DISTINCT incident_type) AS incident_types, "
        "MIN(observed_at) AS first_observed_at, MAX(observed_at) AS last_observed_at "
        "FROM tier2_signatures, LATERAL unnest(indicator_hashes) AS indicator_hash "
        "GROUP BY indicator_hash"
    )
    op.execute(overlap_view_sql)

    op.execute(f"GRANT SELECT ON {SIGNATURES_VIEW}, {OVERLAP_VIEW} TO {READONLY_ROLE}")


def downgrade() -> None:
    bind = op.get_bind()
    dbname = bind.execute(sa.text("SELECT current_database()")).scalar_one()

    # Grants must be revoked before DROP ROLE (Postgres refuses to drop a role that still
    # owns privileges anywhere — "DependentObjectsStillExist", verified empirically).
    op.execute(f"REVOKE SELECT ON {SIGNATURES_VIEW}, {OVERLAP_VIEW} FROM {READONLY_ROLE}")  # noqa: S608
    op.execute(f"REVOKE USAGE ON SCHEMA public FROM {READONLY_ROLE}")
    op.execute(f"REVOKE CONNECT ON DATABASE {_quote_ident(dbname)} FROM {READONLY_ROLE}")

    op.execute(f"DROP VIEW IF EXISTS {OVERLAP_VIEW}")
    op.execute(f"DROP VIEW IF EXISTS {SIGNATURES_VIEW}")

    op.execute(f"DROP ROLE IF EXISTS {READONLY_ROLE}")
