"""Event store — docs/02-DATA-MODEL.md `events` table, matched exactly.

Hot columns carry the fields every filter/detector needs without touching `ocsf`; full
OCSF fidelity (whatever docs/03's mappers produce) lives in `ocsf` JSONB, and
enrichment output (docs/03 "Enrichment") in `enrichment` JSONB, defaulting to `{}` until
the enrichment stage (M5) runs. Rows are bulk-loaded with `COPY`
(`app.storage.event_writer`) — docs/02 is explicit that row-by-row INSERT is not an
option at this table's expected volume (1M+ events/analysis, docs/13 M3 acceptance).

**Why `tenant_id` here carries neither a `tenants` FK nor its own index**, unlike the
M1 core tables (`app.models.user`, `app.models.upload`, `app.models.analysis`), which
do: docs/02's own `CREATE TABLE events` declares `tenant_id UUID NOT NULL` with no
`REFERENCES tenants(id)` — the same pattern as every other high-volume/detection table
in that doc (`signals`, `incidents`, `entities`, ...), as opposed to the low-volume core
tables that do carry the FK. That split reads as deliberate, not an oversight: an FK
constraint checked on every row of a million-row `COPY` is real throughput cost this
table cannot afford, and docs/02 lists exactly five indexes for `events` — a sixth,
bare `tenant_id` index is not one of them, and would rarely be chosen by the planner
anyway, since every real query here is scoped by `analysis_id` first (the composite
indexes below already lead with it), with `tenant_id` riding along as a residual
predicate rather than the driving one.

Structural tenant scoping (docs/06: enforce it "via a SQLAlchemy base query class, not
by remembering") still applies in full — `Event` mixes in `TenantScopedMixin`
(`app.models.base`) exactly like the M1 tables. The guard in `app.models.base` keys off
`issubclass(mapper.class_, TenantScopedMixin)` alone; it does not inspect the column's
FK or index, so overriding the mixin's `tenant_id` column below (to drop the FK/index
and match docs/02's literal SQL) does not weaken the isolation guarantee one bit — a
bare `Session` still raises `MissingTenantScopeError` instead of leaking `events` rows,
and a tenant-bound session still gets `WHERE tenant_id = :tenant_id` ANDed onto every
SELECT/UPDATE/DELETE against this table, exactly like `users`/`uploads`/`analyses`. See
`tests/test_events_model.py` and `tests/test_events_api.py` for proof against the real
database.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, ForeignKey, Index, Integer, Text
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Base
from app.models.base import TenantScopedMixin


class Event(Base, TenantScopedMixin):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    # Overrides TenantScopedMixin's `tenant_id` column (no FK, no bare index) — see the
    # module docstring for why. A subclass's own mapped_column of the same name takes
    # precedence over the mixin's in SQLAlchemy's declarative attribute resolution; the
    # structural scoping guard (app.models.base) is keyed off the class, not the
    # column, so it is unaffected.
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_type: Mapped[str] = mapped_column(Text, nullable=False)
    raw_line_no: Mapped[int] = mapped_column(Integer, nullable=False)
    ocsf_class_uid: Mapped[int] = mapped_column(Integer, nullable=False)

    # --- hot columns ---
    principal: Mapped[str | None] = mapped_column(Text, nullable=True)
    # psycopg3 hands INET columns back as `ipaddress.IPv4Address`/`IPv6Address`
    # instances at runtime (not `str`) regardless of this static annotation —
    # app.schemas.event stringifies them at the API boundary.
    src_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    domain: Mapped[str | None] = mapped_column(Text, nullable=True)
    url_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_method: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_in: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes_out: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_key: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- device/asset hot columns (this task) ---
    # Zscaler Client Connector device fields (docs/v1/zscaler-nss-web-fields.md), projected from
    # `ocsf->device` exactly like every other hot column here is a projection of `ocsf` (module
    # docstring). `hostname` is deliberately not called `device_hostname`: `app.privacy.
    # event_privacy` already reserved that exact key, `"hostname": "host"`, for "a client
    # machine's own hostname, distinct from `domain`" before any parser emitted one — this is that
    # field, arriving under the name that module was already waiting for. Unindexed, like
    # `user_agent`/`http_method` above: nothing here is on the five-index list docs/02 curates,
    # consistent with those two already-unindexed hot columns.
    hostname: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_owner: Mapped[str | None] = mapped_column(Text, nullable=True)
    os_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    os_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    bypassed_traffic: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    flow_type: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Phase 2 detection-field hot column (this task) ---
    # `ja4_str` (docs/v1/zscaler-nss-web-fields.md "SSL/TLS") is the one Phase 2 field promoted to
    # a hot, indexed column — the task's own framing is that it is "a better cross-tenant Tier 2
    # indicator than a domain" precisely because malware rotates domains and IPs far more readily
    # than its TLS stack, so cheap, indexed "same JA4, different domain" lookups across an
    # analysis's whole event set are the query this column exists to make fast. Every other Phase
    # 2 field (cert posture, file hashes, domain fronting, geo risk, upload metadata,
    # threat severity) rides in `ocsf` JSONB only, unindexed — the same treatment
    # `urlcategory`/`appname`/`threatname`/... already get; promoting all twenty to hot columns
    # would be scope well beyond what any of them individually earns today. Unlike `principal`/
    # `src_ip`/`domain`, this is not one of docs/02's original five hot-column indexes, so it gets
    # its own dedicated index below rather than folding into an existing composite one.
    ja4_hash: Mapped[str | None] = mapped_column(Text, nullable=True)

    ocsf: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    enrichment: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")

    __table_args__ = (
        # The five indexes docs/02 lists for `events`, exactly, no more:
        Index("ix_events_analysis_id_ts", "analysis_id", "ts"),
        Index("ix_events_analysis_id_principal_ts", "analysis_id", "principal", "ts"),
        Index("ix_events_analysis_id_domain", "analysis_id", "domain"),
        Index("ix_events_analysis_id_src_ip", "analysis_id", "src_ip"),
        Index(
            "ix_events_ocsf_gin",
            "ocsf",
            postgresql_using="gin",
            postgresql_ops={"ocsf": "jsonb_path_ops"},
        ),
        # Sixth index, added by this task's Phase 2 — see `ja4_hash`'s own comment above for why
        # this one field earns it where the other nineteen Phase 2 fields don't.
        Index("ix_events_analysis_id_ja4_hash", "analysis_id", "ja4_hash"),
    )
