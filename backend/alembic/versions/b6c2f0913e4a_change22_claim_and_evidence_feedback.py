"""docs/v2_migration change 22 — feedback UI: per-claim thumbs + evidence relevance toggle

`claim_feedback` backs "per-claim thumbs on narrative claims, hover-revealed" and feeds mechanism
14 (verifier rule induction). `evidence_relevance_feedback` backs the evidence-section relevance
toggle and feeds mechanism 15 (evidence profile widening) -- see each model's own docstring,
`app/models/claim_feedback.py` and `app/models/evidence_relevance_feedback.py`, for the full
reasoning including a documented cross-reference discrepancy in the migration doc itself.

No existing table is altered by this migration.

Revision ID: b6c2f0913e4a
Revises: a1e5c9420f7b
Create Date: 2026-08-16 00:30:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b6c2f0913e4a"
down_revision: str | None = "a1e5c9420f7b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "claim_feedback",
        sa.Column("id", sa.Integer(), sa.Identity(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("verdict_id", sa.Uuid(), nullable=False),
        sa.Column("step", sa.Integer(), nullable=False),
        sa.Column("helpful", sa.Boolean(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["verdict_id"], ["triage_verdicts.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_claim_feedback_tenant_id", "claim_feedback", ["tenant_id"])
    op.create_index("ix_claim_feedback_incident_id", "claim_feedback", ["incident_id"])

    op.create_table(
        "evidence_relevance_feedback",
        sa.Column("id", sa.Integer(), sa.Identity(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Text(), nullable=False),
        sa.Column("extractor", sa.Text(), nullable=False),
        sa.Column("relevant", sa.Boolean(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_evidence_relevance_feedback_tenant_id", "evidence_relevance_feedback", ["tenant_id"]
    )
    op.create_index(
        "ix_evidence_relevance_feedback_incident_id",
        "evidence_relevance_feedback",
        ["incident_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_evidence_relevance_feedback_incident_id", table_name="evidence_relevance_feedback"
    )
    op.drop_index(
        "ix_evidence_relevance_feedback_tenant_id", table_name="evidence_relevance_feedback"
    )
    op.drop_table("evidence_relevance_feedback")

    op.drop_index("ix_claim_feedback_incident_id", table_name="claim_feedback")
    op.drop_index("ix_claim_feedback_tenant_id", table_name="claim_feedback")
    op.drop_table("claim_feedback")
