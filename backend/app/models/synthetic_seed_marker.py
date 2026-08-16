"""`learning_synthetic_seed` — the single mechanism behind every `synthetic: true` flag this
milestone's API surfaces (docs/08 "Demo honesty": "seed a synthetic feedback history... say so
plainly... rather than implying the data is real").

**Why a generic marker table instead of a `synthetic` column on each seeded table.** Seeded rows
land in real, shared tables: `uploads`, `analyses`, `signals`, `incidents`, `triage_verdicts`,
`analyst_feedback` — none of which this milestone owns, several of which (`analyst_feedback`,
`incidents`, `signals`, `triage_verdicts`) have docstrings elsewhere stating they are matched to
docs/02 *exactly*. Adding a column to any
of them would mean editing a table this task's brief does not grant, and `docs/02-DATA-MODEL.md`
itself is off limits to this milestone. A separate, purely additive marker table sidesteps both:
`app/scripts/seed_feedback.py` inserts one row per synthetic row it creates (`table_name`,
`row_id`), and every API handler that must disclose synthetic provenance
(`GET /api/learning/metrics`, `GET /api/learning/suppressions`, `GET /api/models/calibration`,
`GET /api/models/versions`) joins or `EXISTS`-checks against this table rather than trusting a
column that would have to live on someone else's schema.

`row_id` is `TEXT`, not `Uuid`, because the tables it marks mix UUID primary keys
(`incidents.id`, `triage_verdicts.id`, `analyst_feedback.id`, ...) with `BIGSERIAL` ones
(`signals.id`) — a single generic marker needs a single generic key type.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import BigInteger, DateTime

from app.core.db import Base
from app.models.base import TenantScopedMixin


class SyntheticSeedMarker(Base, TenantScopedMixin):
    __tablename__ = "learning_synthetic_seed"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    table_name: Mapped[str] = mapped_column(Text, nullable=False)
    row_id: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "table_name", "row_id", name="uq_learning_synthetic_seed_table_name_row_id"
        ),
    )
