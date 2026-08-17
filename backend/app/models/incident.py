"""`incidents` — docs/02-DATA-MODEL.md "Graph & incidents", matched exactly:

```sql
CREATE TABLE incidents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_id UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  fused_score REAL NOT NULL,
  anomaly_confidence REAL NOT NULL,
  entity_ids BIGINT[] NOT NULL,
  signal_ids BIGINT[] NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  recurrence_of UUID REFERENCES incidents(id),
  recurrence_similarity REAL,
  embedding VECTOR(1024),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON incidents USING hnsw (embedding vector_cosine_ops);
```

`anomaly_confidence` — docs/v2_migration change 3 ("two confidences, never mixed") — is the
same `fused_score` on a 0-100 scale (`app.detection.fusion.anomaly_confidence_from_fused_score`),
added by migration `<see backend/alembic/versions for the "two confidences" revision>` alongside
that migration's `triage_verdicts.confidence` -> `threat_confidence`/`threat_confidence_reason`
split. Existing rows were backfilled from their own `fused_score` at migration time (a defensible,
lossless-for-this-direction choice: it *is* the same number, just rescaled — see that migration's
own docstring for the reasoning). **The LLM may never write this column** — `app.agent.verifier.
verify_anomaly_confidence` is a hard, deterministic rejection if a triage verdict's echoed
`anomaly_confidence` differs from the value already persisted here; nothing in `app.agent` ever
issues an `UPDATE` against this column.

`tenant_id` overrides `TenantScopedMixin`'s column exactly like `app.models.event.Event` and
`app.models.signal.Signal` — no FK, no bare index, matching docs/02's literal SQL for this
table. Structural tenant scoping still fully applies (the guard is keyed off the class).

`recurrence_of` is a self-referential FK (`REFERENCES incidents(id)`, no `ON DELETE` action
per docs/02) — an incident can point at an earlier one it's a recurrence of.

`embedding` is `VECTOR(1024)` (`pgvector.sqlalchemy.Vector`), backing the HNSW index
(`vector_cosine_ops`) created in the migration for nearest-neighbor recurrence search.

## `tags` / `summary` -- deterministic pipeline outputs, this task

Added by migration `<see backend/alembic/versions for the "incident tags and summary"
revision>`. Both are computed exactly once, at correlate time
(`app.pipeline.stages.correlate`), from the incident's own member signals -- zero LLM cost, so
every incident gets them, not just the top `MAX_TRIAGE_INCIDENTS` an LLM triages. See
`app.graph.tags`/`app.graph.summary` module docstrings for the full derivation.

`tags TEXT[] NOT NULL DEFAULT '{}'` -- a flat, namespaced tag list (`technique:T1090`,
`layer:rule`, `detector:sigma.blocked_then_allowed`, plus unprefixed derived tags like
`multi-layer`/`recurring`). Indexed with a GIN `array_ops` index: that operator class supports
`@>`/`<@`/`&&`/`=` (containment/overlap/equality), never `x = ANY(tags)` -- a future filter must
be written `tags @> ARRAY['technique:T1090']`, not `'technique:T1090' = ANY(tags)`, or it will
silently fall back to a sequential scan.

`summary TEXT NOT NULL DEFAULT ''` -- three factual sentences (what fired, how much evidence,
fused severity). Never overwritten by `TriageVerdict.summary` (the LLM's own, richer narrative,
present only for triaged incidents) -- the two are separate columns on separate tables with
separate provenance, exactly like `anomaly_confidence`/`threat_confidence` above. The UI prefers
the LLM's when present but always renders this one too (docs/10's Summary section is never empty).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import ARRAY, REAL, BigInteger, ForeignKey, Index, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class Incident(Base, TenantScopedMixin):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    # Overrides TenantScopedMixin's `tenant_id` column (no FK, no bare index) — see the
    # module docstring; same pattern as app.models.event.Event / app.models.signal.Signal.
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    fused_score: Mapped[float] = mapped_column(REAL, nullable=False)
    # docs/v2_migration change 3: the same fused_score, rescaled to 0-100 -- see this module's own
    # docstring and app.detection.fusion.anomaly_confidence_from_fused_score.
    anomaly_confidence: Mapped[float] = mapped_column(REAL, nullable=False)
    entity_ids: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), nullable=False)
    signal_ids: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), nullable=False)
    # Deterministic pipeline outputs -- see module docstring "tags / summary" section.
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, default=list, server_default=text("'{}'")
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="open")
    recurrence_of: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id"), nullable=True
    )
    recurrence_similarity: Mapped[float | None] = mapped_column(REAL, nullable=True)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index(
            "ix_incidents_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
        # GIN `array_ops` -- supports `@>`/`<@`/`&&`/`=` on `tags`, not `x = ANY(tags)` (see
        # module docstring). No caller uses this yet (docs/09 lists no `?tag=` query param today),
        # but the column exists specifically so the dashboard can filter on it later without a
        # second migration, and a GIN index on a small `TEXT[]` at this row count is effectively
        # free to maintain -- added now so "get the operator right" is enforced by the index
        # itself (a `= ANY` query simply can't use it) rather than left to a future author to
        # remember.
        Index(
            "ix_incidents_tags_gin",
            "tags",
            postgresql_using="gin",
            postgresql_ops={"tags": "array_ops"},
        ),
    )
