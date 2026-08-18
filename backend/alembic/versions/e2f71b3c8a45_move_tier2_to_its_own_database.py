"""move tier2_signatures out of the primary database

Tier 2 is the cross-tenant surface — the only place one tenant's data is compared against
another's — so it is the boundary CLAUDE.md rule 4 actually names. It now lives in a physically
separate Postgres (`settings.tier2_database_url`, the `tier2-postgres` compose service), holding
`tier2_signatures` plus the pseudonymised `tier2_events` the `anonymize` stage writes.

This drops the table, its two read-only views and the `tier2_readonly` role from the *primary*
database, because leaving them there would leave a second, diverging copy of the schema and a
grant on a table that is no longer the real one.

Nothing is lost that cannot be rebuilt: `tier2_signatures` is derived from `incidents` and
`triage_verdicts`, both of which stay here, and re-running an analysis regenerates it on the
Tier 2 side.

The Tier 2 schema itself is created by `app.core.db.init_tier2_schema` rather than a second
Alembic tree — see that function's docstring for why, and for the condition under which that
stops being defensible.

Revision ID: e2f71b3c8a45
Revises: d1a94f6b3e82
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector

revision = "e2f71b3c8a45"
down_revision = "d1a94f6b3e82"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop every view over the table by discovery rather than by name. Enumerating them by hand
    # already missed one (`tier2_indicator_overlap_v`), and a hardcoded list here would be a
    # second place the set of Tier 2 views has to be kept in sync — the same duplicated-list
    # failure this codebase has hit repeatedly.
    op.execute(
        """
        DO $$
        DECLARE v record;
        BEGIN
            FOR v IN
                SELECT DISTINCT dependent.relname AS view_name
                FROM pg_depend d
                JOIN pg_rewrite r ON r.oid = d.objid
                JOIN pg_class dependent ON dependent.oid = r.ev_class
                JOIN pg_class source ON source.oid = d.refobjid
                WHERE source.relname = 'tier2_signatures'
                  AND dependent.relkind = 'v'
            LOOP
                EXECUTE format('DROP VIEW IF EXISTS %I CASCADE', v.view_name);
            END LOOP;
        END $$;
        """
    )
    # The role is cluster-wide, not per-database, so its grants must go before it can be dropped.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tier2_readonly') THEN
                EXECUTE format(
                    'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', 'tier2_readonly'
                );
                EXECUTE format('REVOKE ALL ON SCHEMA public FROM %I', 'tier2_readonly');
                -- Database-level grants are the ones Postgres reports as "privileges for
                -- database <name>"; without revoking these the DROP ROLE fails with
                -- DependentObjectsStillExist even after every table grant is gone.
                EXECUTE format(
                    'REVOKE ALL ON DATABASE %I FROM %I', current_database(), 'tier2_readonly'
                );
                EXECUTE format('DROP ROLE %I', 'tier2_readonly');
            END IF;
        END $$;
        """
    )
    op.drop_table("tier2_signatures")


def downgrade() -> None:
    op.create_table(
        "tier2_signatures",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("tenant_hash", sa.Text(), nullable=False),
        sa.Column("incident_type", sa.Text(), nullable=False),
        sa.Column("mitre_techniques", sa.ARRAY(sa.Text()), nullable=False),
        sa.Column("source_types", sa.ARRAY(sa.Text()), nullable=False),
        sa.Column("confidence", sa.REAL(), nullable=False),
        sa.Column("indicator_hashes", sa.ARRAY(sa.Text()), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("embedding", Vector(1024), nullable=True),
    )
