"""Pseudonymised event copies in the Tier 2 database.

Written by the `anonymize` stage, which now runs *after* `triage` and immediately before
`tier2` — the point at which data actually crosses the tenant boundary. Everything upstream of
it (detection, correlation, the agent) works on the real values, because a detector cannot
correlate `u_8f3a91c204de` against a baseline built from `alice@corp.example`; everything on
this side of it only ever sees the pseudonym.

That ordering is what makes the stage mean something. Running between `enrich` and `detect`, as
it originally did, it could not rewrite anything — every downstream stage needed the plaintext —
so it degraded to counting how many identifiers *would* have been pseudonymised. Here the count
and the act are the same thing.

Nothing in this table is a source of truth: every row is derived from `events` in the primary
database and can be rebuilt by re-running the analysis. It exists so Tier 2's insights and
analytics have something to aggregate over without reaching into tenant-scoped storage.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Index, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import DateTime, Uuid

from app.core.db import Tier2Base


class Tier2Event(Tier2Base):
    """One pseudonymised event. `tenant_hash` is the same salted tenant identifier
    `tier2_signatures` uses, so the two join on equal terms without either carrying a real
    tenant id.

    The identity columns hold pseudonyms only (`app.privacy.pseudonymize`): `principal`,
    `src_ip`, `dst_ip`, `hostname`, `device_name`, `device_owner`. `domain` is deliberately
    *not* pseudonymised — docs/06 exempts it because a domain is threat intelligence rather
    than an identity, and hashing it per tenant would make the cross-tenant overlap Tier 2
    exists to compute impossible.
    """

    __tablename__ = "tier2_events"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    tenant_hash: Mapped[str] = mapped_column(Text, nullable=False)
    # The originating analysis, so a re-run can replace its own rows rather than duplicating
    # them. Carried as an opaque id: it identifies a pipeline run, not a person.
    analysis_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    source_event_id: Mapped[int] = mapped_column(BigInteger, nullable=False)

    ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    principal: Mapped[str | None] = mapped_column(Text, nullable=True)
    src_ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    hostname: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_owner: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Not identities — docs/06's do-NOT list. Kept in the clear because Tier 2's whole value is
    # comparing these across tenants.
    domain: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_method: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_code: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes_in: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes_out: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Free text, redacted (`app.privacy.redact`) — secrets and PII stripped before they land.
    url_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    enrichment: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )

    __table_args__ = (
        Index("ix_tier2_events_analysis", "analysis_id"),
        Index("ix_tier2_events_tenant_domain", "tenant_hash", "domain"),
    )
