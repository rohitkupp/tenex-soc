"""persist the Timeline tab's windowed event summary

One LLM call over deterministic SQL buckets (`app.api.events`). Stored so the tab renders the
summary already paid for rather than re-spending per visit — the same lesson as
`analyses.narrative` and `analyses.domain_semantic_findings`. NULL until an analyst requests one;
unlike the narrative this is not produced by the pipeline.

Revision ID: d1a94f6b3e82
Revises: c9d5e83f2a17
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "d1a94f6b3e82"
down_revision = "c9d5e83f2a17"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analyses",
        sa.Column("event_timeline_summary", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("analyses", "event_timeline_summary")
