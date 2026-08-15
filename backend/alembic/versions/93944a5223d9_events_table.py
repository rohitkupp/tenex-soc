"""events table

The `events` table from docs/02-DATA-MODEL.md, matched exactly: hot columns, `ocsf`
JSONB, `enrichment` JSONB, and all five listed indexes (including the GIN index on
`ocsf` with the `jsonb_path_ops` operator class). Rows are bulk-loaded via `COPY`
(`app.storage.event_writer`), never row-by-row INSERT.

Unlike the M1 core tables (`users`, `uploads`, `analyses`), `tenant_id` here has no
`REFERENCES tenants(id)` foreign key and no standalone index — docs/02's own SQL omits
both for `events` (and every other high-volume/detection table it defines), and
`app.models.event`'s module docstring explains why: FK-check overhead on a
million-row `COPY`, and a bare `tenant_id` index that duplicates what the composite
`(analysis_id, ...)` indexes below already cover. Structural tenant scoping
(`app.models.base.TenantScopedMixin`) still fully applies at the ORM layer regardless —
see `app/models/event.py`.

Revision ID: 93944a5223d9
Revises: b67faee96cf5
Create Date: 2026-08-14 21:00:24.644101
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "93944a5223d9"
down_revision: str | None = "b67faee96cf5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_type", sa.Text(), nullable=False),
        sa.Column("raw_line_no", sa.Integer(), nullable=False),
        sa.Column("ocsf_class_uid", sa.Integer(), nullable=False),
        # --- hot columns ---
        sa.Column("principal", sa.Text(), nullable=True),
        sa.Column("src_ip", postgresql.INET(), nullable=True),
        sa.Column("dst_ip", postgresql.INET(), nullable=True),
        sa.Column("domain", sa.Text(), nullable=True),
        sa.Column("url_path", sa.Text(), nullable=True),
        sa.Column("action", sa.Text(), nullable=True),
        sa.Column("http_method", sa.Text(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("bytes_in", sa.BigInteger(), nullable=True),
        sa.Column("bytes_out", sa.BigInteger(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("event_key", sa.Text(), nullable=True),
        sa.Column("ocsf", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "enrichment",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_events_analysis_id_domain", "events", ["analysis_id", "domain"])
    op.create_index(
        "ix_events_analysis_id_principal_ts", "events", ["analysis_id", "principal", "ts"]
    )
    op.create_index("ix_events_analysis_id_src_ip", "events", ["analysis_id", "src_ip"])
    op.create_index("ix_events_analysis_id_ts", "events", ["analysis_id", "ts"])
    op.create_index(
        "ix_events_ocsf_gin",
        "events",
        ["ocsf"],
        postgresql_using="gin",
        postgresql_ops={"ocsf": "jsonb_path_ops"},
    )


def downgrade() -> None:
    op.drop_index(
        "ix_events_ocsf_gin",
        table_name="events",
        postgresql_using="gin",
        postgresql_ops={"ocsf": "jsonb_path_ops"},
    )
    op.drop_index("ix_events_analysis_id_ts", table_name="events")
    op.drop_index("ix_events_analysis_id_src_ip", table_name="events")
    op.drop_index("ix_events_analysis_id_principal_ts", table_name="events")
    op.drop_index("ix_events_analysis_id_domain", table_name="events")
    op.drop_table("events")
