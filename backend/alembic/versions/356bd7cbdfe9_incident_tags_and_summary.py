"""incident tags and summary

Two new columns on `incidents`, both deterministic pipeline outputs (zero LLM cost) rather than
side effects of LLM triage -- see `app.graph.tags` / `app.graph.summary` module docstrings for
the full rationale. `app.pipeline.stages.correlate` computes both, once, for *every* incident it
forms, not just the top `MAX_TRIAGE_INCIDENTS` an LLM later triages.

* `tags TEXT[] NOT NULL DEFAULT '{}'` -- a flat, namespaced tag list aggregated from the
  incident's member signals: `technique:<id>` (allowlisted MITRE technique ids only --
  `data/kb/mitre/allowlist.yml`'s 13 proxy-observable techniques, MIGRATION-01 change 4),
  `layer:<detector_layer>`, `detector:<detector_key>`, plus derived `multi-layer`/`recurring`.
  Indexed GIN `array_ops` -- that operator class supports `@>`/`<@`/`&&`/`=`, **not**
  `x = ANY(tags)`; a future filter must be written `tags @> ARRAY['technique:T1090']` to use
  this index, never the reversed `ANY(...)` form.

* `summary TEXT NOT NULL DEFAULT ''` -- three factual sentences (what fired, how much evidence,
  fused severity), never overwritten by the LLM's own, richer `triage_verdicts.summary` -- the
  two are separate columns, separate provenance, exactly like `anomaly_confidence`/
  `threat_confidence` (migration `81f36664938b`).

## Backfill -- existing incidents are not left blank

This environment already has real, previously-correlated incidents (existing analyses run before
this migration). Both columns are backfilled for them, computed from data already on the row --
`signal_ids` and `entity_ids` are already persisted, so no re-run of detection or correlation is
needed, only aggregation over `signals`/`entities` rows the incident already references.

**Why this backfill is pure SQL, self-contained, and deliberately not a byte-for-byte match of
`app.graph.tags`/`app.graph.summary`'s live Python output**: importing evolving application code
into a migration is the anti-pattern migration `81f36664938b` already avoids (that migration's own
backfill is pure SQL, not a call into `app.detection.fusion`) -- a migration is a frozen, one-time
snapshot; if `app.graph.summary`'s template changes next month, this file must not silently change
behavior along with it on a fresh `alembic upgrade head` run against old history. The tag
computation (`technique:`/`layer:`/`detector:`/`multi-layer`/`recurring`) is exactly reproduced,
because it is pure set aggregation with no prose to drift. The summary sentence is a **simplified,
explicitly self-labelled** rendering of the same facts (signal count, layers, entities, event
count, top technique, severity) -- comma-joined rather than "a, b, and c"-joined, and prefixed
"Backfilled during migration 356bd7cbdfe9" so no analyst mistakes it for a live-pipeline summary
or an LLM narrative. Every future incident gets the real, live-Python summary from
`app.pipeline.stages.correlate` -- this prefix only ever appears on rows that predate this
revision.

`downgrade()` drops both columns outright -- neither existed before this revision, nothing to
restore.

Revision ID: 356bd7cbdfe9
Revises: b7bc5ec88aa5
Create Date: 2026-08-17 14:15:06.353742
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "356bd7cbdfe9"
down_revision: str | None = "b7bc5ec88aa5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# MIGRATION-01 change 4's 13-technique allowlist (`data/kb/mitre/allowlist.yml`), inlined for the
# same "no app.* imports in a migration" reason the module docstring gives.
_ALLOWLISTED_TECHNIQUES = (
    "T1071.001",
    "T1102",
    "T1567",
    "T1567.002",
    "T1567.004",
    "T1041",
    "T1029",
    "T1568.002",
    "T1105",
    "T1090",
    "T1505.003",
    "T1595",
    "T1204",
)

# `app.graph.titling._TECHNIQUE_NAMES`, inlined -- same reason. Only used to render a friendlier
# backfilled summary sentence; unrecognized ids fall back to the bare id (`COALESCE`), never a
# fabricated name, matching that module's own documented fallback.
_TECHNIQUE_NAMES = (
    ("T1071", "Application Layer Protocol"),
    ("T1071.001", "Application Layer Protocol: Web Protocols"),
    ("T1552.001", "Unsecured Credentials: Credentials In Files"),
    ("T1090", "Proxy"),
    ("T1090.003", "Proxy: Multi-hop Proxy"),
    ("T1105", "Ingress Tool Transfer"),
    ("T1567", "Exfiltration Over Web Service"),
    ("T1048", "Exfiltration Over Alternative Protocol"),
    ("T1048.003", "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol"),
    ("T1030", "Data Transfer Size Limits"),
    ("T1567.002", "Exfiltration to Cloud Storage"),
    ("T1020", "Automated Exfiltration"),
)


def upgrade() -> None:
    op.add_column(
        "incidents",
        sa.Column("tags", sa.ARRAY(sa.Text()), nullable=False, server_default="{}"),
    )
    op.add_column(
        "incidents",
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_incidents_tags_gin",
        "incidents",
        ["tags"],
        unique=False,
        postgresql_using="gin",
        postgresql_ops={"tags": "array_ops"},
    )

    allowlist_values = ", ".join(f"('{tid}')" for tid in _ALLOWLISTED_TECHNIQUES)
    technique_name_values = ", ".join(
        "('{}', '{}')".format(tid, name.replace("'", "''")) for tid, name in _TECHNIQUE_NAMES
    )

    # --- tags backfill --------------------------------------------------------------------
    op.execute(
        f"""
        WITH allowlist(tid) AS (VALUES {allowlist_values}),
        sig AS (
            SELECT i.id AS incident_id, s.mitre_technique, s.detector_layer, s.detector_key
            FROM incidents i
            JOIN signals s ON s.id = ANY(i.signal_ids)
        ),
        tag_rows AS (
            SELECT incident_id, 'technique:' || mitre_technique AS tag
            FROM sig
            WHERE mitre_technique IS NOT NULL AND mitre_technique IN (SELECT tid FROM allowlist)
            UNION
            SELECT incident_id, 'layer:' || detector_layer FROM sig
            UNION
            SELECT incident_id, 'detector:' || detector_key FROM sig
            UNION
            SELECT incident_id, 'multi-layer'
            FROM sig
            GROUP BY incident_id
            HAVING count(DISTINCT detector_layer) > 1
            UNION
            SELECT id AS incident_id, 'recurring'
            FROM incidents
            WHERE recurrence_of IS NOT NULL
        ),
        agg AS (
            SELECT incident_id, array_agg(DISTINCT tag ORDER BY tag) AS tags
            FROM tag_rows
            GROUP BY incident_id
        )
        UPDATE incidents i
        SET tags = agg.tags
        FROM agg
        WHERE i.id = agg.incident_id
        """
    )

    # --- summary backfill -------------------------------------------------------------------
    op.execute(
        f"""
        WITH technique_names(tid, tname) AS (VALUES {technique_name_values}),
        sub AS (
            SELECT
                i2.id AS incident_id,
                COALESCE(array_length(i2.signal_ids, 1), 0) AS n_signals,
                COALESCE(
                    (SELECT string_agg(DISTINCT s.detector_layer, ', ' ORDER BY s.detector_layer)
                     FROM signals s WHERE s.id = ANY(i2.signal_ids)),
                    'unknown'
                ) AS layers,
                (SELECT min(s.window_start) FROM signals s WHERE s.id = ANY(i2.signal_ids))
                    AS window_start,
                (SELECT max(s.window_end) FROM signals s WHERE s.id = ANY(i2.signal_ids))
                    AS window_end,
                COALESCE(
                    (SELECT count(DISTINCT eid) FROM signals s, unnest(s.evidence_event_ids) eid
                     WHERE s.id = ANY(i2.signal_ids)),
                    0
                ) AS n_events,
                COALESCE(
                    (SELECT string_agg(et.cnt || ' ' || et.etype, ', ' ORDER BY et.etype)
                     FROM (
                         SELECT e.type AS etype, count(*) AS cnt
                         FROM entities e WHERE e.id = ANY(i2.entity_ids)
                         GROUP BY e.type
                     ) et),
                    'an unspecified set of entities'
                ) AS entities,
                (SELECT s.mitre_technique
                 FROM signals s
                 WHERE s.id = ANY(i2.signal_ids) AND s.mitre_technique IS NOT NULL
                 GROUP BY s.mitre_technique
                 ORDER BY count(*) DESC, s.mitre_technique ASC
                 LIMIT 1) AS top_tid
            FROM incidents i2
        )
        UPDATE incidents i
        SET summary = (
            'Backfilled during migration 356bd7cbdfe9 from this incident''s already-persisted '
            'signals (a historical row -- see this migration''s own docstring for why it is not '
            'byte-identical to a live-pipeline summary). '
            || sub.n_signals || ' signal(s) from the ' || sub.layers || ' layer(s) fired on '
            || sub.entities
            || COALESCE(
                   ' between ' || to_char(sub.window_start, 'YYYY-MM-DD HH24:MI')
                   || ' and ' || to_char(sub.window_end, 'YYYY-MM-DD HH24:MI') || ' UTC',
                   ''
               )
            || '. ' || sub.n_events || ' event(s) support this finding'
            || CASE
                   WHEN sub.top_tid IS NULL THEN '; no MITRE technique was identified among these signals'
                   ELSE '; top technique ' || COALESCE(tn.tname, sub.top_tid) || ' (' || sub.top_tid || ')'
               END
            || '. Fused severity: ' || i.severity || '.'
        )
        FROM sub
        LEFT JOIN technique_names tn ON tn.tid = sub.top_tid
        WHERE i.id = sub.incident_id
        """
    )


def downgrade() -> None:
    op.drop_index("ix_incidents_tags_gin", table_name="incidents")
    op.drop_column("incidents", "summary")
    op.drop_column("incidents", "tags")
