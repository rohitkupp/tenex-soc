"""persist the Path A analysis narrative

The Narrator (`app.agent.orchestrator.narrate_analysis`, migration change 14 Path A) has always
run inside the `triage` stage, once per analysis, and its result was thrown away — the stage kept
only `cost_usd` and `citation_valid` and dropped the prose. The UI then offered a
"Generate executive summary" button that re-ran the same call and re-spent for a narrative the
pipeline had already paid for and discarded.

These columns are that narrative's home, so the pipeline's own run is what the analyst reads.
`POST /api/analyses/{id}/narrate` keeps working and now writes here too, so a deliberate
regeneration replaces the stored copy rather than living only in one browser tab.

`narrative_invalid_citations` is stored alongside the prose rather than derived: an unverified
claim must stay visible next to the sentence that made it (CLAUDE.md rule 6), and recomputing
verification later against re-fetched evidence would not reproduce what the model was actually
told at generation time.

Revision ID: a7e31b9c4d20
Revises: c2a71f5e9d34
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "a7e31b9c4d20"
down_revision = "c2a71f5e9d34"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("analyses", sa.Column("narrative", sa.Text(), nullable=True))
    op.add_column(
        "analyses",
        sa.Column(
            "narrative_phases",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
    )
    op.add_column(
        "analyses", sa.Column("narrative_citation_valid", sa.Boolean(), nullable=True)
    )
    op.add_column(
        "analyses",
        sa.Column(
            "narrative_invalid_citations",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
    )
    op.add_column("analyses", sa.Column("narrative_model", sa.Text(), nullable=True))
    op.add_column(
        "analyses", sa.Column("narrative_cost_usd", sa.Numeric(10, 4), nullable=True)
    )
    op.add_column(
        "analyses",
        sa.Column("narrative_generated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("analyses", "narrative_generated_at")
    op.drop_column("analyses", "narrative_cost_usd")
    op.drop_column("analyses", "narrative_model")
    op.drop_column("analyses", "narrative_invalid_citations")
    op.drop_column("analyses", "narrative_citation_valid")
    op.drop_column("analyses", "narrative_phases")
    op.drop_column("analyses", "narrative")
