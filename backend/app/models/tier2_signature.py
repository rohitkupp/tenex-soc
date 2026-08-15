"""`tier2_signatures` — docs/02-DATA-MODEL.md "Ops & Tier 2", matched exactly:

```sql
CREATE TABLE tier2_signatures (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_hash TEXT NOT NULL,
  incident_type TEXT NOT NULL,
  mitre_techniques TEXT[] NOT NULL,
  source_types TEXT[] NOT NULL,
  confidence REAL NOT NULL,
  indicator_hashes TEXT[] NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL,
  embedding VECTOR(1024)
);
```

**Deliberately not tenant-scoped, and deliberately not `tenant_id`.** docs/02 is explicit:
`tenant_hash` (an HMAC, `app.core...pseudonymize`-style but with the *shared* cross-tenant salt
docs/06 documents for Tier 2 specifically — "indicator hashes ... use a shared salt across
tenants so cross-tenant overlap is detectable") is what this table carries instead of
`tenant_id`. That is exactly what lets "this C2 domain appeared in 3 other tenants" be answered
without any tenant seeing another's raw data — a real `tenant_id` FK/column here would either
leak identity or defeat the whole point of the table, so this model does **not** mix in
`app.models.base.TenantScopedMixin` and never should.

Note `mitre_techniques` here is **`TEXT[]`**, unlike `triage_verdicts.mitre_techniques`
(`JSONB`) — see that model's docstring; both are matched to docs/02 verbatim.

`embedding` is `VECTOR(1024)` (`pgvector.sqlalchemy.Vector`) — nullable, docs/02 gives it no
`NOT NULL`, and unlike `incidents.embedding` there is no HNSW index specified for this column
in docs/02, so none is created here.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import ARRAY, REAL, Text, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base


class Tier2Signature(Base):
    __tablename__ = "tier2_signatures"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    tenant_hash: Mapped[str] = mapped_column(Text, nullable=False)
    incident_type: Mapped[str] = mapped_column(Text, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    source_types: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    confidence: Mapped[float] = mapped_column(REAL, nullable=False)
    indicator_hashes: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1024), nullable=True)
