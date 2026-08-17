"""device asset hot columns

Adds the seven device/asset hot columns `app.models.event.Event` now declares — the "critical
gap" this task closes: Zscaler Client Connector device fields (docs/v1/zscaler-nss-web-fields.md)
never had anywhere to land in `events`, so the parser could not map them and the asset tag bank
(`app.graph.asset_tags`) had nothing to aggregate at correlate time.

`hostname` (not `device_hostname`): `app.privacy.event_privacy._PSEUDONYMIZE_FIELDS` already
reserved that exact key for "a client machine's own hostname, distinct from `domain`" before any
parser emitted one (see that module's docstring) — this column is that field, finally arriving.

No index on any of the seven: none is on docs/02's five-index list for `events`, and asset-tag
computation reads them through a targeted `id IN (...)` query over one incident's own evidence
events (`app.pipeline.stages.correlate`), never a full-table scan — the same access pattern
`user_agent`/`http_method`/`action` (also unindexed hot columns) already use.

No backfill: `events` rows written before this revision have no device data to backfill from (the
parser did not populate it) — every column defaults to `NULL`, which is the honest state for a
historical row, not a fabricated `"unknown"`.

Revision ID: f4c8a1d9e2b6
Revises: 356bd7cbdfe9
Create Date: 2026-08-17 15:40:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f4c8a1d9e2b6"
down_revision: str | None = "356bd7cbdfe9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("events", sa.Column("hostname", sa.Text(), nullable=True))
    op.add_column("events", sa.Column("device_name", sa.Text(), nullable=True))
    op.add_column("events", sa.Column("device_owner", sa.Text(), nullable=True))
    op.add_column("events", sa.Column("os_type", sa.Text(), nullable=True))
    op.add_column("events", sa.Column("os_version", sa.Text(), nullable=True))
    op.add_column("events", sa.Column("bypassed_traffic", sa.Boolean(), nullable=True))
    op.add_column("events", sa.Column("flow_type", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("events", "flow_type")
    op.drop_column("events", "bypassed_traffic")
    op.drop_column("events", "os_version")
    op.drop_column("events", "os_type")
    op.drop_column("events", "device_owner")
    op.drop_column("events", "device_name")
    op.drop_column("events", "hostname")
