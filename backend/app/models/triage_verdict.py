"""`triage_verdicts` — docs/02-DATA-MODEL.md "Triage & response", as amended by
docs/v2_migration/MIGRATION-01-evidence-first.md change 3 ("two confidences, never mixed"):

```sql
CREATE TABLE triage_verdicts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  disposition TEXT NOT NULL,
  threat_confidence TEXT NOT NULL,
  threat_confidence_reason TEXT NOT NULL,
  llm_severity_opinion TEXT,
  mitre_techniques JSONB NOT NULL,
  summary TEXT NOT NULL,
  narrative JSONB NOT NULL,
  contradicting_evidence TEXT,
  recommended_actions JSONB NOT NULL,
  tool_trace JSONB NOT NULL,
  citation_valid BOOL NOT NULL,
  invalid_citations JSONB NOT NULL DEFAULT '[]',
  model TEXT NOT NULL,
  tokens_in INT, tokens_out INT,
  cost_usd NUMERIC(10,6),
  latency_ms INT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**`confidence REAL` (docs/02's original single column) is gone.** It collapsed two genuinely
different numbers into one: how *unusual* an entity's behaviour is (now `incidents.
anomaly_confidence`, calibrated, 0-100, never touched by the LLM) and how well the evidence
supports *this specific* security interpretation (`threat_confidence` here — the LLM's own
low/moderate/high judgement, paired with a mandatory `threat_confidence_reason` so that judgement
is never a bare, unexplained enum value). `app.agent.schemas.TriageVerdictOut` mirrors this split
exactly; `app.agent.verifier.verify_anomaly_confidence` is the hard, deterministic check that
nothing in the agent path ever smuggles a changed `anomaly_confidence` back through this table
(it isn't even a column here — there is nothing for the LLM's output to overwrite).

Not tenant-scoped — no `tenant_id` column in docs/02's SQL. Isolation is transitive through
`incident_id`, which cascades from `incidents` (a tenant-scoped table).

Note `mitre_techniques` here is **JSONB** (the LLM's structured technique list with whatever
per-technique detail docs/07's tool schema returns), unlike `tier2_signatures.mitre_techniques`
(`TEXT[]`) — the two tables use the same column name for genuinely different shapes; both are
matched to docs/02 verbatim, not unified.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import REAL, Boolean, ForeignKey, Integer, Numeric, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base


class TriageVerdict(Base):
    __tablename__ = "triage_verdicts"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    disposition: Mapped[str] = mapped_column(Text, nullable=False)
    # docs/v2_migration change 3: replaces the old single `confidence REAL` -- see this module's
    # own docstring. `threat_confidence` is one of low/moderate/high (app.agent.schemas.
    # TriageVerdictOut), never a raw float; `threat_confidence_reason` is mandatory so the level
    # is never a bare, unexplained enum value.
    threat_confidence: Mapped[str] = mapped_column(Text, nullable=False)
    threat_confidence_reason: Mapped[str] = mapped_column(Text, nullable=False)
    # Computed by `app.agent.confidence` from the Judge's rubric grades -- no model emits it.
    # Nullable because a triage that never reached the Judge has no evidence assessment at all,
    # which is a different fact from one that was assessed and scored badly; the UI renders the
    # two differently and collapsing them into 0.0 would lie about both.
    evidence_confidence: Mapped[float | None] = mapped_column(REAL, nullable=True)
    evidence_confidence_band: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The decomposition behind the number: which rubric items failed, their text, any cap
    # applied. Persisted so a score stays explainable without re-running triage.
    evidence_confidence_basis: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    llm_severity_opinion: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitre_techniques: Mapped[Any] = mapped_column(JSONB, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    narrative: Mapped[Any] = mapped_column(JSONB, nullable=False)
    contradicting_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommended_actions: Mapped[Any] = mapped_column(JSONB, nullable=False)
    tool_trace: Mapped[Any] = mapped_column(JSONB, nullable=False)
    citation_valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    invalid_citations: Mapped[Any] = mapped_column(JSONB, nullable=False, server_default="[]")
    model: Mapped[str] = mapped_column(Text, nullable=False)
    tokens_in: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tokens_out: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(10, 6), nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
