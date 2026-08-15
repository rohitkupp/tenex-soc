"""dead letters table

The `dead_letters` table from docs/02-DATA-MODEL.md, matched exactly — see
`app/models/dead_letter.py` for why it carries neither `tenant_id` nor a FK on
`analysis_id` (both deliberate, per docs/02's own literal SQL). Written by
`app.pipeline.base_worker` once a `StageMessage` exhausts the retry policy
(docs/01: 3 attempts, exponential backoff 1s/4s/16s, then dead-letter), and read/
retried via `GET /api/ops/dead-letters` / `POST /api/ops/dead-letters/{id}/retry`
(docs/09).

Revision ID: 3ecd8a2dc9bd
Revises: 93944a5223d9
Create Date: 2026-08-14 21:44:11.322927
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "3ecd8a2dc9bd"
down_revision: str | None = "93944a5223d9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dead_letters",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=True),
        sa.Column("stage", sa.Text(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("retried_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("dead_letters")
