"""drop incident recurrence — the duplicate-checking service is gone

`app.graph.recurrence` embedded each incident's structural signature (sorted technique ids,
detector keys, entity types, enrichment tags) with a HashingVectorizer, stored it in
`incidents.embedding`, cosine-searched prior incidents over an HNSW index, and linked anything
at or above 0.92 similarity as a recurrence. A linked recurrence then skipped agent triage and
inherited its parent's verdict.

All of it is removed at the caller's request. Two consequences worth stating plainly rather than
discovering later:

* Every incident is now triaged on its own evidence or not at all — there is no inheritance path.
  That *raises* LLM cost, because duplicate-suppression was the mechanism that made a repeat
  incident free.
* The `recurring` tag no longer exists, and `TriageVerdict` lookups no longer fall back to a
  parent's verdict.

Dropping the HNSW index with the column also removes this schema's only pgvector index. The
extension stays installed (the health check asserts it, and `tier2_signatures` is unaffected).

Revision ID: c9d5e83f2a17
Revises: b8f42c7a1e93
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector

revision = "c9d5e83f2a17"
down_revision = "b8f42c7a1e93"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_incidents_embedding_hnsw", table_name="incidents")
    op.drop_column("incidents", "embedding")
    op.drop_column("incidents", "recurrence_similarity")
    op.drop_column("incidents", "recurrence_of")


def downgrade() -> None:
    op.add_column(
        "incidents",
        sa.Column("recurrence_of", sa.Uuid(as_uuid=True), sa.ForeignKey("incidents.id")),
    )
    op.add_column("incidents", sa.Column("recurrence_similarity", sa.REAL(), nullable=True))
    op.add_column("incidents", sa.Column("embedding", Vector(1024), nullable=True))
    op.create_index(
        "ix_incidents_embedding_hnsw",
        "incidents",
        ["embedding"],
        postgresql_using="hnsw",
        postgresql_ops={"embedding": "vector_cosine_ops"},
    )
