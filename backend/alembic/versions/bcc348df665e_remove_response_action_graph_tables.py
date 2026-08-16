"""remove response action graph tables

docs/v2_migration change 20: the response action graph and simulated enforcement plane are
removed entirely. Drops the three tables `62f176de175c_remaining_data_model_tables.py`
introduced for them, in FK-safe order (`enforcement_journal` references `response_plans`
references `incidents`/`users`; `enforcement_state` has no FK to anything):

  * `response_plans`
  * `enforcement_state`
  * `enforcement_journal`

`triage_verdicts.recommended_actions` survives unchanged at the column level (still JSONB) —
only its meaning changes, from action-catalog IDs to free-text investigation guidance
(`app.agent.schemas`), which needs no migration.

`downgrade()` recreates all three exactly as `62f176de175c` originally defined them, so a
rollback restores the identical schema (columns, defaults, constraints, FKs) rather than an
approximation.

Revision ID: bcc348df665e
Revises: 6ba739579d4b
Create Date: 2026-08-15 13:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "bcc348df665e"
down_revision: str | None = "6ba739579d4b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Children before parents: enforcement_journal.plan_id -> response_plans.id.
    op.drop_table("enforcement_journal")
    op.drop_table("response_plans")
    op.drop_table("enforcement_state")


def downgrade() -> None:
    op.create_table(
        "enforcement_state",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("resource_type", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.Text(), nullable=False),
        sa.Column("state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "resource_type",
            "resource_id",
            name="uq_enforcement_state_tenant_id_resource_type_resource_id",
        ),
    )
    op.create_table(
        "response_plans",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("actions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("verification", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.Text(), server_default="pending_approval", nullable=False),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "execution_log",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
        sa.Column("outcome", sa.Text(), nullable=True),
        sa.Column("outcome_detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(
            ["approved_by"],
            ["users.id"],
        ),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "enforcement_journal",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("plan_id", sa.Uuid(), nullable=False),
        sa.Column("action_id", sa.Text(), nullable=False),
        sa.Column("before_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("after_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("succeeded", sa.Boolean(), nullable=False),
        sa.Column("precondition_failure", sa.Text(), nullable=True),
        sa.Column(
            "executed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["plan_id"],
            ["response_plans.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
