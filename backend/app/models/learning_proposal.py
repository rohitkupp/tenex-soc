"""`learning_proposals` — shared staging table for change 21's eight *gated* mechanisms
(6, 7, 8, 10, 11, 12, 14, 15). "Requires human approval ... auto-suppression is how you miss a
breach" applies to all eight identically, and each is, structurally, the same three-step shape:
propose -> (human reviews) -> approve (apply for real, golden-set gate) or reject (stays inert).
One table for the shared shape, `payload` (JSONB) for what differs per mechanism, mirrors
`app.models.suppression_candidate`'s own precedent (a single staging table for one gated
consumer) generalized to eight.

`status` starts `"pending"`; `app.learning.proposals.accept_proposal` runs the candidate through
`evals.gate.evaluate_gate` (this codebase's one real golden-set regression gate, already built for
`make eval` — reused here rather than re-implemented) and moves it to `"approved"` (state applied,
a `learning_events` row with `applied=True` is written) or `"rejected"` (state left inert, the
`learning_events` row stays `applied=False`, and the rejection is recorded in both
`evals/gate_history.jsonl` via `evals.gate.record_history` and this row's own `after_state`/
`reviewed_at` — "keep the rejection history," change 21). A rejected proposal is **not** deleted or
re-queued automatically; a human decides whether to submit a revised candidate.

`supporting_feedback_ids` is the evidentiary trail: which `analyst_feedback` rows this candidate
was clustered/derived from, so a reviewer (or a later audit) can see *why* the system proposed
this change, not just what it proposes.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ARRAY, ForeignKey, Integer, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"


class LearningProposal(Base, TenantScopedMixin):
    __tablename__ = "learning_proposals"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    mechanism: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=STATUS_PENDING)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    supporting_feedback_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(Uuid(as_uuid=True)), nullable=False, server_default=text("'{}'")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    learning_event_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("learning_events.id"), nullable=True
    )


__all__ = ["STATUS_APPROVED", "STATUS_PENDING", "STATUS_REJECTED", "LearningProposal"]
