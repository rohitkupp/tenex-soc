"""M13 learning loop tables

`suppression_candidates`, `benign_baseline_entries`, `learning_synthetic_seed` — three tables
docs/02-DATA-MODEL.md does not define, added by `app/learning` (M13) to back the six feedback
consumers in docs/08 Part 2. See `app/models/suppression_candidate.py`,
`app/models/benign_baseline_entry.py`, and `app/models/synthetic_seed_marker.py` for why each one
exists rather than a column added to an existing docs/02 table. No existing table is altered by
this migration.

Revision ID: c59cf17b44e7
Revises: 62f176de175c
Create Date: 2026-08-15 04:10:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c59cf17b44e7"
down_revision: str | None = "62f176de175c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "suppression_candidates",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("feedback_id", sa.Uuid(), nullable=False),
        sa.Column("detector_key", sa.Text(), nullable=False),
        sa.Column("entity_type", sa.Text(), nullable=False),
        sa.Column("entity_value", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("rule_yaml", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("synthetic", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by", sa.Uuid(), nullable=True),
        sa.Column("written_path", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["feedback_id"], ["analyst_feedback.id"]),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_suppression_candidates_tenant_id", "suppression_candidates", ["tenant_id"])
    op.create_index(
        "ix_suppression_candidates_status", "suppression_candidates", ["tenant_id", "status"]
    )

    op.create_table(
        "benign_baseline_entries",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("feedback_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("entity_type", sa.Text(), nullable=False),
        sa.Column("entity_value", sa.Text(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("synthetic", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("included_in_training_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["feedback_id"], ["analyst_feedback.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_benign_baseline_entries_tenant_id", "benign_baseline_entries", ["tenant_id"]
    )

    op.create_table(
        "learning_synthetic_seed",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("table_name", sa.Text(), nullable=False),
        sa.Column("row_id", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "table_name", "row_id", name="uq_learning_synthetic_seed_table_name_row_id"
        ),
    )
    op.create_index(
        "ix_learning_synthetic_seed_tenant_id", "learning_synthetic_seed", ["tenant_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_learning_synthetic_seed_tenant_id", table_name="learning_synthetic_seed")
    op.drop_table("learning_synthetic_seed")
    op.drop_index("ix_benign_baseline_entries_tenant_id", table_name="benign_baseline_entries")
    op.drop_table("benign_baseline_entries")
    op.drop_index("ix_suppression_candidates_status", table_name="suppression_candidates")
    op.drop_index("ix_suppression_candidates_tenant_id", table_name="suppression_candidates")
    op.drop_table("suppression_candidates")
