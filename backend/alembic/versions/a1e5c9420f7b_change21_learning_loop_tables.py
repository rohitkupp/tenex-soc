"""docs/v2_migration change 21 — continuous learning: `learning_events` ledger + supporting tables

`learning_events` matches the task brief's schema verbatim (no `tenant_id` — change 23's shared
single-tenant workspace already removed per-tenant partitioning as a live concern for this
ledger). The eight supporting tables back the 15 mechanisms' own state where docs/02 defines
nothing: `entity_threshold_overrides` (3), `reference_set_exclusions` (5), `entity_cohorts` (7),
`dga_label_feedback` (8), `exemplar_bank_entries` (10), `retrieval_priors` (13),
`evidence_profile_state` (15), and `learning_proposals` (the shared propose/approve/reject staging
table for every gated mechanism: 6, 7, 8, 10, 11, 12, 14, 15). See each model's own docstring
under `app/models/` for why it exists and what it backs.

No existing table is altered by this migration.

Revision ID: a1e5c9420f7b
Revises: 81f36664938b
Create Date: 2026-08-16 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "a1e5c9420f7b"
down_revision: str | None = "81f36664938b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "learning_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("mechanism", sa.Integer(), nullable=False),
        sa.Column("trigger_feedback_id", sa.Uuid(), nullable=True),
        sa.Column("applied", sa.Boolean(), nullable=False),
        sa.Column("before_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("after_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("metric_delta", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_learning_events_mechanism", "learning_events", ["mechanism"])
    op.create_index("ix_learning_events_applied", "learning_events", ["applied"])

    op.create_table(
        "entity_threshold_overrides",
        sa.Column("id", sa.Integer(), sa.Identity(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("entity_type", sa.Text(), nullable=False),
        sa.Column("entity_value", sa.Text(), nullable=False),
        sa.Column("detector_key", sa.Text(), server_default=sa.text("''"), nullable=False),
        sa.Column("threshold_percentile", sa.REAL(), nullable=False),
        sa.Column("confirm_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("dismiss_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "entity_type",
            "entity_value",
            "detector_key",
            name="uq_entity_threshold_overrides_entity_detector",
        ),
    )
    op.create_index(
        "ix_entity_threshold_overrides_tenant_id", "entity_threshold_overrides", ["tenant_id"]
    )

    op.create_table(
        "reference_set_exclusions",
        sa.Column("id", sa.Integer(), sa.Identity(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("entity_type", sa.Text(), nullable=False),
        sa.Column("entity_value", sa.Text(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("feedback_id", sa.Uuid(), nullable=False),
        sa.Column("models", sa.ARRAY(sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["feedback_id"], ["analyst_feedback.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_reference_set_exclusions_tenant_id", "reference_set_exclusions", ["tenant_id"]
    )
    op.create_index(
        "ix_reference_set_exclusions_entity",
        "reference_set_exclusions",
        ["tenant_id", "entity_type", "entity_value"],
    )

    op.create_table(
        "entity_cohorts",
        sa.Column("id", sa.Integer(), sa.Identity(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("entity_type", sa.Text(), nullable=False),
        sa.Column("entity_value", sa.Text(), nullable=False),
        sa.Column("cohort_label", sa.Text(), nullable=False),
        sa.Column("method", sa.Text(), nullable=False),
        sa.Column(
            "computed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "entity_type", "entity_value", name="uq_entity_cohorts_entity"
        ),
    )
    op.create_index("ix_entity_cohorts_tenant_id", "entity_cohorts", ["tenant_id"])

    op.create_table(
        "dga_label_feedback",
        sa.Column("id", sa.Integer(), sa.Identity(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("domain", sa.Text(), nullable=False),
        sa.Column("is_dga", sa.Boolean(), nullable=False),
        sa.Column("feedback_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["feedback_id"], ["analyst_feedback.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dga_label_feedback_tenant_id", "dga_label_feedback", ["tenant_id"])

    op.create_table(
        "exemplar_bank_entries",
        sa.Column("id", sa.Integer(), sa.Identity(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("feedback_id", sa.Uuid(), nullable=False),
        sa.Column("error_mode", sa.Text(), nullable=False),
        sa.Column("finding_summary", sa.Text(), nullable=False),
        sa.Column("corrected_summary", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["feedback_id"], ["analyst_feedback.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_exemplar_bank_entries_tenant_id", "exemplar_bank_entries", ["tenant_id"])

    op.create_table(
        "retrieval_priors",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("technique_id", sa.Text(), nullable=False),
        sa.Column("retrieved_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("supported_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("weight", sa.REAL(), server_default="1.0", nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("tenant_id", "technique_id"),
    )

    op.create_table(
        "evidence_profile_state",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("extractor", sa.Text(), nullable=False),
        sa.Column("total_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("expand_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("widened", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("tenant_id", "extractor"),
    )

    op.create_table(
        "learning_proposals",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("mechanism", sa.Integer(), nullable=False),
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "supporting_feedback_ids",
            sa.ARRAY(sa.Uuid()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by", sa.Uuid(), nullable=True),
        sa.Column("learning_event_id", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["learning_event_id"], ["learning_events.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_learning_proposals_tenant_id", "learning_proposals", ["tenant_id"])
    op.create_index(
        "ix_learning_proposals_status", "learning_proposals", ["tenant_id", "status"]
    )


def downgrade() -> None:
    op.drop_index("ix_learning_proposals_status", table_name="learning_proposals")
    op.drop_index("ix_learning_proposals_tenant_id", table_name="learning_proposals")
    op.drop_table("learning_proposals")

    op.drop_table("evidence_profile_state")
    op.drop_table("retrieval_priors")

    op.drop_index("ix_exemplar_bank_entries_tenant_id", table_name="exemplar_bank_entries")
    op.drop_table("exemplar_bank_entries")

    op.drop_index("ix_dga_label_feedback_tenant_id", table_name="dga_label_feedback")
    op.drop_table("dga_label_feedback")

    op.drop_index("ix_entity_cohorts_tenant_id", table_name="entity_cohorts")
    op.drop_table("entity_cohorts")

    op.drop_index("ix_reference_set_exclusions_entity", table_name="reference_set_exclusions")
    op.drop_index("ix_reference_set_exclusions_tenant_id", table_name="reference_set_exclusions")
    op.drop_table("reference_set_exclusions")

    op.drop_index(
        "ix_entity_threshold_overrides_tenant_id", table_name="entity_threshold_overrides"
    )
    op.drop_table("entity_threshold_overrides")

    op.drop_index("ix_learning_events_applied", table_name="learning_events")
    op.drop_index("ix_learning_events_mechanism", table_name="learning_events")
    op.drop_table("learning_events")
