"""`baseline_profiles` — docs/v2_migration/MIGRATION-01-evidence-first.md, change 1, matched
exactly:

```sql
CREATE TABLE baseline_profiles (
  tenant_id UUID NOT NULL,
  entity_type TEXT NOT NULL,
  entity_value TEXT NOT NULL,
  metric TEXT NOT NULL,               -- bytes_out, n_events, n_unique_domains, ...
  p50 DOUBLE PRECISION, p95 DOUBLE PRECISION, p99 DOUBLE PRECISION,
  mean DOUBLE PRECISION, mad DOUBLE PRECISION,
  n_windows INT NOT NULL,
  PRIMARY KEY (tenant_id, entity_type, entity_value, metric)
);
```

One row per `(entity, metric)` — the pre-aggregated distribution `app.baseline.resolve
.percentile_for` reads instead of recomputing over raw `baseline_windows` on every call. Loaded
from `data/baseline/baseline_profiles.json`
(`docs/v2_migration/generate_corpus.py::build_baseline()`), keyed `"{user}|{metric}"` there;
`n_windows` is what makes cold start (`n_windows < 20` -> `baseline_status:
"insufficient_history"`, `app.baseline.resolve`) a first-class part of the read path rather than
a caller's problem.

No surrogate `id` — the composite `(tenant_id, entity_type, entity_value, metric)` primary key
is exactly the migration's own SQL, and it is also the natural upsert key `app.baseline.loader`
uses to keep re-running idempotent.

Not given a `tenants` FK, matching `baseline_windows`/`baseline_contacts` and every other
high-volume detection table (`app.models.event.Event`, `app.models.signal.Signal`) — the
migration's SQL above declares `tenant_id UUID NOT NULL` with no `REFERENCES tenants(id)`.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Double, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class BaselineProfile(Base, TenantScopedMixin):
    __tablename__ = "baseline_profiles"

    # Overrides TenantScopedMixin's tenant_id (no FK, no bare index; part of the composite PK
    # instead) — see module docstring.
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    entity_type: Mapped[str] = mapped_column(Text, primary_key=True)
    entity_value: Mapped[str] = mapped_column(Text, primary_key=True)
    metric: Mapped[str] = mapped_column(Text, primary_key=True)
    p50: Mapped[float | None] = mapped_column(Double, nullable=True)
    p95: Mapped[float | None] = mapped_column(Double, nullable=True)
    p99: Mapped[float | None] = mapped_column(Double, nullable=True)
    mean: Mapped[float | None] = mapped_column(Double, nullable=True)
    mad: Mapped[float | None] = mapped_column(Double, nullable=True)
    n_windows: Mapped[int] = mapped_column(Integer, nullable=False)
