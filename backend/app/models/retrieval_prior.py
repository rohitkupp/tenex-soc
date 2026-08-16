"""`retrieval_priors` — change 21 mechanism 13, "retrieval prior tuning" (auto).

"Track which retrieved techniques the Analyst supports vs. ignores. Retrieved 40 times and never
supported for an evidence pattern -> down-weight for that pattern." One row per
`(tenant_id, technique_id)` — a per-pattern breakdown is out of scope for this milestone (it would
need the evidence-payload shape the Analyst stage retrieves against, `app/agent`'s ownership, not
built against here); technique-level is the coarsest faithful grain this package's own data
(`triage_verdicts.mitre_techniques`, `analyst_feedback.corrected_technique`) can support without
fabricating pattern buckets that don't exist yet.

`weight` starts at `1.0` (neutral) and is recomputed, monotonically from full history each call
(mirrors `app.learning.weights.retune_detector_weights`'s own "recomputed from scratch, not
incrementally drifted" convention) — see `app.learning.retrieval_priors` for the formula.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import REAL, Integer, PrimaryKeyConstraint, Text, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime

from app.core.db import Base
from app.models.base import TenantScopedMixin


class RetrievalPrior(Base, TenantScopedMixin):
    __tablename__ = "retrieval_priors"

    technique_id: Mapped[str] = mapped_column(Text)
    retrieved_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    supported_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    weight: Mapped[float] = mapped_column(REAL, nullable=False, server_default="1.0")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (PrimaryKeyConstraint("tenant_id", "technique_id"),)


__all__ = ["RetrievalPrior"]
