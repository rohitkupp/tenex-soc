"""persist change 8's semantic domain findings

`GET /api/analyses/{id}/overview` computed these by calling `assess_domain_semantics` — a live
Anthropic request — *inside the request handler*. A route whose own docstring called it "safe to
call on every page load" therefore blocked on an LLM round trip and spent real tokens on every
load, every reload, and every tab switch. Measured against production it was the dominant cost in
that endpoint: 14-17s of a ~17s response, far past the frontend's server-render budget, which is
what surfaced to the analyst as "a server-side exception has occurred".

The reason previously given for recomputing rather than storing was that there was nowhere to put
the result without a schema migration. This is that migration.

Revision ID: b8f42c7a1e93
Revises: a7e31b9c4d20
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b8f42c7a1e93"
down_revision = "a7e31b9c4d20"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analyses",
        sa.Column(
            "domain_semantic_findings",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
    )
    op.add_column(
        "analyses",
        sa.Column("domain_semantics_generated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("analyses", "domain_semantics_generated_at")
    op.drop_column("analyses", "domain_semantic_findings")
