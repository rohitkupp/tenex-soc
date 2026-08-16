"""baseline store tables

docs/v2_migration/MIGRATION-01-evidence-first.md, change 1 ("Historical baseline store") --
"the single biggest change": percentiles, rarity, and deviations move from being computed
against the uploaded file to a persistent 6-month per-tenant history. Three tables, matched
verbatim to the migration's own SQL:

* `baseline_windows`   -- one row per (entity, hour-bucket), `app.models.baseline_window`
* `baseline_profiles`  -- one row per (entity, metric), `app.models.baseline_profile`
* `baseline_contacts`  -- one row per (scope, scope_value, domain), `app.models.baseline_contact`

None of the three gets a `tenants` FK or a bare `tenant_id` index -- the migration's SQL block
declares `tenant_id UUID NOT NULL` with no `REFERENCES tenants(id)` on any of them, the same
high-volume-table pattern already used for `events`/`signals` (`bcc348df665e`'s predecessors).
Loaded by `app.baseline.loader` (`python -m app.baseline.loader`, wired into `make seed`).

Revision ID: 744b82efc029
Revises: bcc348df665e
Create Date: 2026-08-16 01:54:41.094736
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "744b82efc029"
down_revision: str | None = "bcc348df665e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "baseline_windows",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("entity_type", sa.Text(), nullable=False),
        sa.Column("entity_value", sa.Text(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("features", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "entity_type",
            "entity_value",
            "window_start",
            name="uq_baseline_windows_tenant_entity_window",
        ),
    )
    op.create_index(
        "ix_baseline_windows_tenant_entity",
        "baseline_windows",
        ["tenant_id", "entity_type", "entity_value"],
    )

    op.create_table(
        "baseline_profiles",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("entity_type", sa.Text(), nullable=False),
        sa.Column("entity_value", sa.Text(), nullable=False),
        sa.Column("metric", sa.Text(), nullable=False),
        sa.Column("p50", sa.Double(), nullable=True),
        sa.Column("p95", sa.Double(), nullable=True),
        sa.Column("p99", sa.Double(), nullable=True),
        sa.Column("mean", sa.Double(), nullable=True),
        sa.Column("mad", sa.Double(), nullable=True),
        sa.Column("n_windows", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "entity_type",
            "entity_value",
            "metric",
            name="pk_baseline_profiles",
        ),
    )

    op.create_table(
        "baseline_contacts",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("scope_value", sa.Text(), nullable=False),
        sa.Column("domain", sa.Text(), nullable=False),
        sa.Column("contact_count", sa.BigInteger(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "scope",
            "scope_value",
            "domain",
            name="pk_baseline_contacts",
        ),
    )
    op.create_index(
        "ix_baseline_contacts_tenant_domain",
        "baseline_contacts",
        ["tenant_id", "domain"],
    )


def downgrade() -> None:
    op.drop_index("ix_baseline_contacts_tenant_domain", table_name="baseline_contacts")
    op.drop_table("baseline_contacts")

    op.drop_table("baseline_profiles")

    op.drop_index("ix_baseline_windows_tenant_entity", table_name="baseline_windows")
    op.drop_table("baseline_windows")
