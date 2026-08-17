"""ja4 hash hot column

Adds `events.ja4_hash` — the one Phase 2 detection field this task promotes to a hot, indexed
column. `%s{ja4_str}` (docs/v1/zscaler-nss-web-fields.md "SSL/TLS") is the JA4 client TLS
fingerprint; the task's own framing is that it is "a better cross-tenant Tier 2 indicator than a
domain" because malware rotates domains and IPs far more readily than its TLS stack, so an
indexed `(analysis_id, ja4_hash)` lookup — "same fingerprint, different domain, across this
analysis's events" — is the query this column exists to make fast. Every other Phase 2 field
(certificate posture, file hashes, domain fronting, geo risk, upload metadata, threat severity)
rides in `ocsf` JSONB only, same treatment `urlcategory`/`appname`/`threatname`/... already get —
see `app.models.event.Event`'s own comment for why only this one field earns the column.

No backfill: `events` rows written before this revision were parsed by a version of
`app.parsers.zscaler` that did not read `%s{ja4_str}` at all, so there is nothing to backfill
from — every existing row gets `NULL`, the honest state for a historical row.

Revision ID: c2a71f5e9d34
Revises: f4c8a1d9e2b6
Create Date: 2026-08-17 17:05:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c2a71f5e9d34"
down_revision: str | None = "f4c8a1d9e2b6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("events", sa.Column("ja4_hash", sa.Text(), nullable=True))
    op.create_index(
        "ix_events_analysis_id_ja4_hash", "events", ["analysis_id", "ja4_hash"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_events_analysis_id_ja4_hash", table_name="events")
    op.drop_column("events", "ja4_hash")
