"""triage_verdicts: evidence confidence computed from the Judge's rubric

Adds the three columns behind `app.agent.confidence`: the score, its band, and the
decomposition that produced it.

All three are nullable, and that is load-bearing rather than convenience. A verdict written
before this migration, or one produced by a `needs_review` fallback that never reached the
Judge, has *no* evidence assessment — which is a different statement from an assessment that
came out at zero. Backfilling a default would erase that distinction permanently, and every
consumer (API, queue column, Tier 2 sync) is written to treat `NULL` as "not assessed" and
render it as an em dash rather than as a bad score.

No index. `evidence_confidence` is read per-incident on a case file and aggregated over the
handful of incidents in one analysis; nothing sorts or filters the whole table by it, so an
index would cost writes on every triage to serve a query that does not exist.

Revision ID: a7d3e91c5b04
Revises: e2f71b3c8a45
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a7d3e91c5b04"
down_revision: str | None = "e2f71b3c8a45"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.add_column(
        "triage_verdicts",
        sa.Column("evidence_confidence", sa.REAL(), nullable=True),
    )
    op.add_column(
        "triage_verdicts",
        sa.Column("evidence_confidence_band", sa.Text(), nullable=True),
    )
    op.add_column(
        "triage_verdicts",
        sa.Column("evidence_confidence_basis", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("triage_verdicts", "evidence_confidence_basis")
    op.drop_column("triage_verdicts", "evidence_confidence_band")
    op.drop_column("triage_verdicts", "evidence_confidence")
