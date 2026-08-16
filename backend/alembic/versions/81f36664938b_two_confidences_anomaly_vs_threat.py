"""two confidences: anomaly vs threat

docs/v2_migration/MIGRATION-01-evidence-first.md change 3 ("Two confidences, never mixed"). A
behaviour can be extremely anomalous and not remotely malicious -- collapsing "how unusual is
this vs. history" and "how well does the evidence support this specific security interpretation"
into one number was the mistake this migration exists to undo.

* `incidents.anomaly_confidence REAL NOT NULL` -- added. ML + evidence layer, isotonic-calibrated,
  0-100. `app.detection.fusion.anomaly_confidence_from_fused_score` is the single place it is
  derived from `fused_score`; every caller that persists an `Incident` row computes both from the
  same `fused_score` in the same call, so the two can never silently drift apart.

* `triage_verdicts.confidence REAL NOT NULL` -- replaced with `threat_confidence TEXT NOT NULL` +
  `threat_confidence_reason TEXT NOT NULL`. Hypothesis-evaluation output (low/moderate/high, plus
  a mandatory reason), never a raw float the LLM invents.

## Backfill -- existing rows are not dropped

**`incidents.anomaly_confidence`**: every existing incident already carries the exact number this
column exists to expose -- its own `fused_score` -- so the backfill is exact, not approximate:
`anomaly_confidence = round(fused_score * 100, 1)`, clamped to `[0, 100]`. This is the same
formula `app.detection.fusion.anomaly_confidence_from_fused_score` uses for every future row, run
here in SQL so the column can be `NOT NULL` from the moment it exists.

**`triage_verdicts.threat_confidence`**: the old `confidence REAL` blended anomaly and threat
judgement into one number that this migration's whole point is to stop trusting as a threat
signal -- there is no way to recover the LLM's real hypothesis-evaluation confidence for a verdict
it was never asked to produce. Rather than drop the column's information silently, it is bucketed
into the new three-level scale using the same thresholds `docs/04`'s severity table already
establishes as meaningful cut points for this system (>=0.75 high, >=0.4 moderate, else low), and
`threat_confidence_reason` says plainly that the value is a migration artifact, not a real
hypothesis-evaluation judgement, so no dashboard or analyst mistakes it for one:

    threat_confidence = 'high'     if confidence >= 0.75
                       = 'moderate' if confidence >= 0.4
                       = 'low'      otherwise
    threat_confidence_reason = "Backfilled during migration 81f36664938b from the legacy single
        confidence value (<old value>), which predates the anomaly/threat confidence split and
        blended both meanings into one number -- this is not a genuine hypothesis-evaluation
        judgement."

`downgrade()` reverses both: drops `incidents.anomaly_confidence` outright (it never existed
before this revision, nothing to restore), and rebuilds `triage_verdicts.confidence` from
`threat_confidence`'s bucket midpoint (high -> 0.85, moderate -> 0.55, low -> 0.2 -- the
thresholds' own midpoints, not the original value, which the forward migration already discarded
by design). Lossy in both directions by construction (a three-level bucket cannot round-trip a
float exactly) but always leaves a valid, fully populated schema -- never a NULL.

Revision ID: 81f36664938b
Revises: 744b82efc029
Create Date: 2026-08-16 10:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "81f36664938b"
down_revision: str | None = "744b82efc029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- incidents.anomaly_confidence -------------------------------------------------------
    op.add_column("incidents", sa.Column("anomaly_confidence", sa.REAL(), nullable=True))
    op.execute(
        "UPDATE incidents "
        "SET anomaly_confidence = LEAST(GREATEST(round((fused_score * 100)::numeric, 1), 0), 100)"
    )
    op.alter_column("incidents", "anomaly_confidence", nullable=False)

    # --- triage_verdicts.confidence -> threat_confidence + threat_confidence_reason ----------
    op.add_column("triage_verdicts", sa.Column("threat_confidence", sa.Text(), nullable=True))
    op.add_column(
        "triage_verdicts", sa.Column("threat_confidence_reason", sa.Text(), nullable=True)
    )
    op.execute(
        """
        UPDATE triage_verdicts
        SET threat_confidence = CASE
                WHEN confidence >= 0.75 THEN 'high'
                WHEN confidence >= 0.4 THEN 'moderate'
                ELSE 'low'
            END,
            threat_confidence_reason = (
                'Backfilled during migration 81f36664938b from the legacy single confidence '
                'value (' || round(confidence::numeric, 3)::text || '), which predates the '
                'anomaly/threat confidence split and blended both meanings into one number -- '
                'this is not a genuine hypothesis-evaluation judgement.'
            )
        """
    )
    op.alter_column("triage_verdicts", "threat_confidence", nullable=False)
    op.alter_column("triage_verdicts", "threat_confidence_reason", nullable=False)
    op.drop_column("triage_verdicts", "confidence")


def downgrade() -> None:
    op.add_column("triage_verdicts", sa.Column("confidence", sa.REAL(), nullable=True))
    op.execute(
        """
        UPDATE triage_verdicts
        SET confidence = CASE threat_confidence
                WHEN 'high' THEN 0.85
                WHEN 'moderate' THEN 0.55
                WHEN 'low' THEN 0.2
                ELSE 0.5
            END
        """
    )
    op.alter_column("triage_verdicts", "confidence", nullable=False)
    op.drop_column("triage_verdicts", "threat_confidence_reason")
    op.drop_column("triage_verdicts", "threat_confidence")

    op.drop_column("incidents", "anomaly_confidence")
