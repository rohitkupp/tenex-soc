"""Per-run agent context — the one place tenant/incident scope, the pseudonymization salt, and
the pseudonym<->raw lookup cache are assembled, so `tools.py`, `verifier.py`, and
`orchestrator.py` all work off exactly the same scope instead of each re-deriving it.

## Why events need on-the-fly pseudonymization here at all

docs/07's `query_events` docstring is explicit: it "returns pseudonymized, redacted events". The
real production pipeline's anonymizer *worker* is still a skeleton
(`app.workers.anonymizer` — "pass-through only, real redaction/pseudonymization lands at M5" —
M5 built the `app.privacy` library but nothing in this checkout has wired it into that worker
yet), and this milestone's own verification data (`app.graph.pipeline_demo`) does not call it
either. So `events` rows reaching this package are, today, raw. Rather than assume upstream
anonymization has happened (a assumption that would silently leak PII the moment it's wrong),
every tool in this package pseudonymizes and redacts defensively, every time, using
`app.privacy`'s public API directly — CLAUDE.md rule 4 ("Pseudonymize before any external
call") applies at the boundary of *this* package, not at the boundary of the pipeline stage that
was supposed to do it upstream.

## Why pseudonyms need a reverse cache

Once `query_events` pseudonymizes `principal="user83@corp.example"` into `"u_8f3a91c204de"` and
hands that to the model, the model's *later* tool calls (`get_entity_timeline`,
`get_entity_baseline`, `get_related_signals`) will reference that entity by the pseudonym it was
shown — it never sees the raw value. Those tools still need to query Postgres, which stores the
raw value. `AgentContext.resolve_entity_value` is the one place that reverse lookup happens: an
in-memory, single-run cache (never persisted, never the tenant's real reverse-map table) seeded
at construction with every entity already known to be in the incident's scope, and extended
every time `pseudonymize_value` mints a new pseudonym during the run.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.base import tenant_scope
from app.models.entity import Entity
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.tenant import Tenant
from app.privacy.pseudonymize import PseudonymKind, pseudonymize
from app.privacy.redact import redact_text

__all__ = [
    "AgentContext",
    "AgentContextError",
    "build_agent_context",
]

# entity_type (docs/02 `signals.entity_type` / `entities.type`) -> pseudonymize() kind.
# "domain" is deliberately absent: docs/06's do-NOT list ("Do not pseudonymize: domains").
# Anything else (asn, country) passes through unpseudonymized too -- neither is in
# app.privacy.pseudonymize.PREFIX, and neither is individually identifying.
_ENTITY_KIND: dict[str, PseudonymKind] = {
    "user": "user",
    "src_ip": "ip",
    "dst_ip": "ip",
}

# Free-text event fields subject to docs/06's 256-char truncation + redaction before any of them
# reaches a prompt or a tool result.
TRUNCATE_FIELDS: tuple[str, ...] = ("url_path", "user_agent", "referrer")
FIELD_TRUNCATE_LEN = 256

# docs/07 citation verification #3: "within the incident's time window +/- 1h".
CITATION_TEMPORAL_SLACK = timedelta(hours=1)


class AgentContextError(Exception):
    """Raised when an incident cannot be triaged at all (missing incident, missing tenant) --
    a caller-facing 404/409, not something the agent loop should try to recover from."""


@dataclass(slots=True)
class AgentContext:
    session: Session
    tenant_id: uuid.UUID
    analysis_id: uuid.UUID
    incident_id: uuid.UUID
    pseudonym_salt: bytes
    window_start: datetime
    window_end: datetime
    # (entity_type, raw_value) pairs this incident's own entities/signals belong to -- docs/07
    # citation check #2 ("the event's entities intersect the incident's entity_ids").
    entity_scope: frozenset[tuple[str, str]]
    _pseudonym_to_raw: dict[str, str] = field(default_factory=dict)

    def pseudonymize_value(self, value: str, entity_type: str) -> str:
        """Pseudonymize one entity value per docs/06's do/do-NOT list, and remember the mapping
        so a later tool call referencing the pseudonym can be resolved back to the raw value
        (see module docstring). Values not in `_ENTITY_KIND` (domains, asn, country, ...) pass
        through unchanged -- there is nothing to reverse-map for those."""
        kind = _ENTITY_KIND.get(entity_type)
        if kind is None:
            return value
        pseudonym = pseudonymize(value, kind, self.pseudonym_salt)
        self._pseudonym_to_raw[pseudonym] = value
        return pseudonym

    def resolve_entity_value(self, value: str, entity_type: str) -> str:
        """Reverse of `pseudonymize_value`: given a value the model supplied as a tool argument
        (which, for a pseudonymizable `entity_type`, is always a pseudonym this same run minted
        or that was seeded from the incident's own scope), return the raw value to query
        Postgres with. A pseudonym this context has never seen resolves to itself -- the caller
        (`tools.py`) treats "no rows found" as the correct response to an entity the model
        invented or misremembered, not a crash."""
        if entity_type not in _ENTITY_KIND:
            return value
        return self._pseudonym_to_raw.get(value, value)

    def sanitize_free_text(self, value: str | None) -> str | None:
        """docs/06 defense #3 (truncate to 256 chars) + M5's secret/PII redaction, applied in
        that order -- truncate first so redaction never has to scan a padded prompt-injection
        payload past the point docs/06 says it should have been cut off anyway."""
        if value is None:
            return None
        truncated = value[:FIELD_TRUNCATE_LEN]
        return redact_text(truncated).text

    def event_entity_pairs(
        self,
        *,
        principal: str | None,
        src_ip: IPv4Address | IPv6Address | str | None,
        dst_ip: IPv4Address | IPv6Address | str | None,
        domain: str | None,
    ) -> set[tuple[str, str]]:
        """The (entity_type, raw_value) pairs one event belongs to, for the citation "scope"
        check. `src_ip`/`dst_ip` arrive from psycopg as `ipaddress.*Address` objects (see
        `app.models.event.Event`'s own docstring on this), never `str` -- stringify before
        comparing against `entity_scope`, which is keyed on the same string form
        `app.graph.builder` uses when it builds entity keys from raw event rows."""
        pairs: set[tuple[str, str]] = set()
        if principal:
            pairs.add(("user", principal))
        if src_ip:
            pairs.add(("src_ip", str(src_ip)))
        if dst_ip:
            pairs.add(("dst_ip", str(dst_ip)))
        if domain:
            pairs.add(("domain", domain))
        return pairs


def _incident_window(session: Session, incident: Incident) -> tuple[datetime, datetime]:
    """The incident's time window, for the citation temporal-plausibility check. Mirrors
    `app.graph.timeline.build_timeline`'s own fallback reasoning (window_start/window_end when a
    detector reported one, else the evidence events' own timestamps) rather than reinventing a
    different notion of "the incident's window" -- but computed directly here instead of
    importing `app.graph.timeline` (out of this package's ownership; the two modules solve
    adjacent but distinct problems and duplicating ~10 lines of aggregation is cheaper than a
    cross-milestone coupling for it).
    """
    if not incident.signal_ids:
        return incident.created_at, incident.created_at

    signals = (
        session.execute(select(Signal).where(Signal.id.in_(incident.signal_ids))).scalars().all()
    )

    starts: list[datetime] = []
    ends: list[datetime] = []
    for s in signals:
        if s.window_start is not None:
            starts.append(s.window_start)
        if s.window_end is not None:
            ends.append(s.window_end)

    if starts and ends:
        return min(starts), max(ends)

    # No detector reported a window (e.g. an L1 rule match on a single event) -- fall back to
    # the evidence events' own timestamps, same spirit as app.graph.timeline's fallback.
    all_event_ids = {eid for s in signals for eid in s.evidence_event_ids}
    if not all_event_ids:
        return incident.created_at, incident.created_at

    from app.models.event import Event  # local import: avoids a module-level cycle risk with

    rows = session.execute(select(Event.ts).where(Event.id.in_(all_event_ids))).scalars().all()
    if not rows:
        return incident.created_at, incident.created_at
    return min(rows), max(rows)


def _entity_scope(session: Session, incident: Incident) -> frozenset[tuple[str, str]]:
    """The incident's own entities, as (type, raw_value) pairs. Prefer `entities` rows keyed by
    `incident.entity_ids` (the real, pipeline-populated path); fall back to the union of the
    incident's own signals' (entity_type, entity_value) when `entity_ids` is empty -- some
    incident-producing paths in this codebase (synthetic feedback seeding) don't populate the
    `entities` table at all, and an incident with signals but an empty scope would fail every
    citation's scope check by construction, which is a data-provenance gap, not evidence the
    incident has no real entities."""
    scope: set[tuple[str, str]] = set()
    if incident.entity_ids:
        rows = session.execute(
            select(Entity.type, Entity.value).where(Entity.id.in_(incident.entity_ids))
        ).all()
        scope.update((t, v) for t, v in rows)
    if not scope and incident.signal_ids:
        rows = session.execute(
            select(Signal.entity_type, Signal.entity_value).where(
                Signal.id.in_(incident.signal_ids)
            )
        ).all()
        scope.update((t, v) for t, v in rows)
    return frozenset(scope)


def build_agent_context(
    session: Session, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> AgentContext:
    """Load everything one incident's triage run needs, once, up front.

    `tenant_id` is a required argument, not derived from the incident row — `app.models.base`'s
    tenant guard rejects *any* query against a tenant-scoped table (including a bare
    `session.get(Incident, ...)`) on a session with no tenant bound, and `bypass_tenant_scope` is
    explicitly reserved for the one pre-authentication lookup that has no other option (see that
    module's docstring: "Do not reach for this anywhere else"). Every caller of this function
    already knows the tenant before it knows which incident it's about to triage — the API layer
    from the authenticated session, `app.graph.pipeline_demo`-driven verification scripts from
    the run they just did — exactly the same shape `app.learning.memory`'s
    `get_prior_analyst_decisions_for_incident(session, *, tenant_id, incident_id, ...)` already
    uses. If the given `incident_id` does not belong to `tenant_id`, the scoped lookup below
    simply finds no row, which is the correct, tenant-safe failure mode
    (`AgentContextError`, not a cross-tenant leak).
    """
    with tenant_scope(session, tenant_id):
        incident = session.get(Incident, incident_id)
        if incident is None:
            raise AgentContextError(f"incident {incident_id} not found for tenant {tenant_id}")
        window_start, window_end = _incident_window(session, incident)
        scope = _entity_scope(session, incident)

    tenant = session.get(Tenant, tenant_id)  # Tenant itself is not tenant-scoped (it IS the scope)
    if tenant is None:  # pragma: no cover - FK guarantees this in practice
        raise AgentContextError(f"tenant {tenant_id} not found")

    ctx = AgentContext(
        session=session,
        tenant_id=incident.tenant_id,
        analysis_id=incident.analysis_id,
        incident_id=incident.id,
        pseudonym_salt=bytes(tenant.pseudonym_salt),
        window_start=window_start,
        window_end=window_end,
        entity_scope=scope,
    )
    # Seed the reverse cache with every entity already known to be in scope, so a tool call
    # referencing one of the incident's own entities resolves even before query_events has
    # pseudonymized it in this run.
    for entity_type, raw_value in scope:
        ctx.pseudonymize_value(raw_value, entity_type)
    return ctx
