"""signals calibrated provenance

Adds `signals.calibrated` — see `app.models.signal.Signal`'s module docstring ("calibrated"
section) for the full defect this fixes: `CalibratorStore.calibrate()` falls back to
`clamp01(raw_score)` for a detector with no fitted calibrator, and for a detector whose raw
score is unbounded (`signal.stl_residual`'s robust-z), that fallback saturates at exactly
`1.0` — indistinguishable, by number alone, from a genuinely calibrated model's most confident
output. This column makes the distinction a fact about the row instead of something a reader
has to infer.

**Backfill: every existing row set to `FALSE`.** Not because every existing row is actually a
fallback -- many aren't -- but because there is no way to reconstruct, after the fact, whether
`CalibratorStore.has(detector_key)` was true *at the moment each row was written* (the
calibrator roster on disk has changed since, and this migration cannot re-run history). `FALSE`
("unmeasured until proven otherwise") is the direction it's safe to be wrong in: it can at
worst under-rank an already-persisted signal that was genuinely calibrated, never let an
old fallback-inflated one keep masquerading as trustworthy. Every row written after this
migration gets a real value from the write path itself (`app/pipeline/stages/detect.py::
_recalibrate_signals`, `app/graph/pipeline_demo.py::run_scenario`), not the backfill.

Revision ID: b7bc5ec88aa5
Revises: b6c2f0913e4a
Create Date: 2026-08-17 06:30:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b7bc5ec88aa5"
down_revision: str | None = "b6c2f0913e4a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # server_default satisfies NOT NULL for every pre-existing row in one statement (Postgres
    # backfills the default for the whole table as part of ADD COLUMN); left in place afterward
    # (not dropped once backfilled) as a second line of defense for any insert path that ever
    # bypasses the ORM-level default -- the same "default to the safe/unmeasured direction"
    # policy `app.models.signal.Signal.calibrated`'s Python-side default already states.
    op.add_column(
        "signals",
        sa.Column("calibrated", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("signals", "calibrated")
