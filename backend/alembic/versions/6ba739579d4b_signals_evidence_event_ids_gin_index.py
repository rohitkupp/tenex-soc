"""signals evidence_event_ids GIN index

`app.api.events`'s `has_signal` filter (docs/09) now runs a real predicate against
`signals.evidence_event_ids` -- a correlated `EXISTS`/`NOT EXISTS` using the array
containment operator (`@>`) for the single-event-id list endpoint filter, and a page-wide
overlap (`&&`) for folding signal stats onto a page of events. Postgres's default `array_ops`
GIN opclass indexes both `@>` and `&&` (also `<@`/`=`), so one index covers both call sites.

Without this index each of those predicates falls back to a sequential scan of `signals`
per outer row (`has_signal=true`) or one full-table array scan (the page-overlap join) --
docs/13's M3 acceptance bar is "paginates 1M+ rows without timing out", and an analysis at
that scale can carry thousands of signals, each with up to `EVIDENCE_CAP` (200,
`app.detection.signal.constants`) evidence ids. `analysis_id` isn't included in the index
key: this is a GIN index on the array column itself (not a composite btree), and every real
query already carries a separate `signals.analysis_id` equality predicate that the planner
combines with the GIN bitmap scan via a bitmap AND -- a second column here would only bloat
the index for no selectivity gain, since the array elements are already unique enough to be
highly selective on their own.

Revision ID: 6ba739579d4b
Revises: 88fcc9caf4ea
Create Date: 2026-08-15 09:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "6ba739579d4b"
down_revision: str | None = "88fcc9caf4ea"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_signals_evidence_event_ids_gin",
        "signals",
        ["evidence_event_ids"],
        unique=False,
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index("ix_signals_evidence_event_ids_gin", table_name="signals")
