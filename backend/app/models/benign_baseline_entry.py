"""`benign_baseline_entries` — M13 learning loop, docs/08 Part 2 "Benign corpus expansion".

Not in docs/02-DATA-MODEL.md's literal SQL, for the same reason as
`app.models.suppression_candidate.SuppressionCandidate`: this table backs a learning consumer,
not the core detection/response data model. `mark_benign_baseline=true` on `analyst_feedback`
(a real docs/02 column) is the trigger; this table is where the resulting entity-windows land so
a future corpus build (`datagen`, out of this milestone's ownership — see `app/learning/
benign_corpus.py`) has something concrete to read.

One row per `(entity_type, entity_value, window)` the incident's own signals touched — sourced
directly from `signals.entity_type`/`entity_value`/`window_start`/`window_end` for the feedback's
incident, not from `entities` (that table has no window information; the "entity-window" this
consumer flags is exactly the grain `signals` already scores at, docs/04's L3 §"entity-window").

`synthetic` mirrors `app.models.suppression_candidate.SuppressionCandidate.synthetic` — same
demo-honesty requirement, same mechanism.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import BigInteger, DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class BenignBaselineEntry(Base, TenantScopedMixin):
    __tablename__ = "benign_baseline_entries"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    feedback_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("analyst_feedback.id"), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_value: Mapped[str] = mapped_column(Text, nullable=False)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # Set once a retrain (app/learning/retrain.py) actually folds this row into a training
    # corpus export. NULL means "flagged, not yet consumed" -- the honest default, since no
    # retraining pipeline consumes it automatically the moment the flag is set (docs/08 never
    # promises that; it promises the row is *available* for "the next training corpus").
    included_in_training_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
