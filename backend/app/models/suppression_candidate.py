"""`suppression_candidates` — M13 learning loop, docs/08 Part 2 "Suppression rule generation".

Not in docs/02-DATA-MODEL.md's literal SQL: that document predates the learning consumers this
table backs. docs/09-API-CONTRACT.md's `GET /api/learning/suppressions` (pending candidates) and
`POST /api/learning/suppressions/{id}/accept` need somewhere to hold a generated-but-unreviewed
candidate between "an analyst dismissed something with a reason" and "an analyst accepted or
rejected the resulting rule" — this is that somewhere. Additive only: no existing docs/02 table
is touched, and this migration lives entirely in `app/learning`'s own ownership.

**Why a table instead of writing straight to `app/detection/rules/suppressions/`.** docs/08 is
explicit and non-negotiable: "Never auto-apply. Analyst review is the gate... auto-suppression is
how you miss a breach." A row here is inert — it changes no detector's behavior. Only
`POST /api/learning/suppressions/{id}/accept` (`app/api/learning.py`) writes the YAML file, and
only after a human clicks accept. See `app/learning/suppression.py` for the generation logic and
the same reasoning stated again at the point it matters.

`rule_yaml` is the fully rendered Sigma exception candidate (the same schema
`app.detection.sigma.rule.load_rule_file` parses) — stored pre-rendered so the review UI can show
an analyst exactly what would be written, and so acceptance is a pure file write, not a second
render pass that could drift from what was reviewed.

`synthetic` flags a candidate generated from `make seed`'s synthetic feedback history
(`app/scripts/seed_feedback.py`) rather than real analyst activity — surfaced directly in
`GET /api/learning/suppressions` per this milestone's demo-honesty requirement (docs/08 "Demo
honesty").
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin

STATUS_PENDING = "pending"
STATUS_ACCEPTED = "accepted"
STATUS_REJECTED = "rejected"


class SuppressionCandidate(Base, TenantScopedMixin):
    __tablename__ = "suppression_candidates"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    feedback_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("analyst_feedback.id"), nullable=False
    )
    detector_key: Mapped[str] = mapped_column(Text, nullable=False)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_value: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    rule_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=STATUS_PENDING)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    written_path: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        # Backs `GET /api/learning/suppressions`, which lists pending candidates for one
        # tenant -- the only query shape this table serves besides a by-id lookup.
        Index("ix_suppression_candidates_status", "tenant_id", "status"),
    )
