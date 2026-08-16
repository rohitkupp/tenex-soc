"""Per-run agent context — the one place tenant/incident scope, the pseudonymization salt, and
the pseudonym<->raw lookup cache are assembled, so `tools.py`, `verifier.py`, and
`orchestrator.py` all work off exactly the same scope instead of each re-deriving it.

## Why events need on-the-fly pseudonymization here at all

docs/07's `query_events` docstring is explicit: it "returns pseudonymized, redacted events". The
real `anonymize` worker (`app.pipeline.stages.anonymize`) *does* run — but by design it never
rewrites `events` rows in place; its own module docstring explains why a redacted-copy-at-rest
would be actively wrong (every downstream detector and the graph need the real values to
correlate correctly), and reports a genuine per-analysis pseudonymization/redaction *audit*
instead. So `events` rows reaching this package are, deliberately, still raw — the actual
enforcement point for CLAUDE.md rule 4 ("Pseudonymize before any external call") is the boundary
of *this* package, the one place data is about to leave the tenant for an LLM call, not the
pipeline stage upstream of it. Every tool here pseudonymizes and redacts defensively, every
time, using `app.privacy`'s public API directly.

## Why pseudonyms need a reverse cache

Once `query_events` pseudonymizes `principal="user83@corp.example"` into `"u_8f3a91c204de"` and
hands that to the model, the model's *later* tool calls (`get_entity_timeline`,
`get_entity_baseline`, `get_related_signals`) will reference that entity by the pseudonym it was
shown — it never sees the raw value. Those tools still need to query Postgres, which stores the
raw value. `AgentContext.resolve_entity_value` is the one place that reverse lookup happens: an
in-memory, single-run cache (never persisted, never the tenant's real reverse-map table) seeded
at construction with every entity already known to be in the incident's scope, and extended
every time `pseudonymize_value` mints a new pseudonym during the run.

## Change 7's other two citation namespaces: `BASELINE-n` and the retrieval trace

`EVIDENCE-n`/`LOG-n` citations resolve against data that already has a stable, deterministic id
(`EvidencePayload.evidence_id`, `Event.raw_line_no`) before the run even starts. `BASELINE-n` does
not — `get_entity_baseline` (`tools.py`) computes an ad hoc comparison on demand, mid-run, so
*this run* is the only place an id for it can be minted. `AgentContext.cite_baseline` is that
mint: called once per `get_entity_baseline` call, it assigns the next `BASELINE-{n}` id, remembers
the full result dict so `app.agent.verifier` can check numbers cited against it later, and hands
the id back so the tool result the model sees already carries its own citation id (the model never
has to invent one).

Similarly, change 7 check 3 ("retrieval match... a technique the model recalled from training and
never retrieved is a hallucination") needs to know the full set of technique ids this run actually
retrieved — both the automatic evidence-driven retrieval (`app.agent.retrieval.
retrieve_candidates`, run once before the Analyst's first turn) and anything the Analyst pulled
mid-investigation via the `search_mitre` tool. `record_retrieved_techniques` accumulates both into
one set for the verifier to check cited technique ids against.

## Where `EvidencePayload`s come from at triage time (change 2's own gap)

`app.detection.evidence.run.run_evidence_layer` is the pipeline-worker entrypoint that would
normally produce and persist an analysis's `EvidencePayload`s, but change 2's own module docstring
is explicit that payloads "are not persisted to a table" — and nothing in this checkout's actual
pipeline path (`app.workers.detector` is still a skeleton; `app.graph.pipeline_demo`, the only
thing that runs detection end to end today, predates the evidence-extractor package and never
calls it) produces or stores them anywhere a later triage run could read back. `compute_evidence_
payloads` below closes that gap the only way available without persisting anything or touching
`app.detection.evidence` itself: it re-runs the same pure/DB-read-only steps `run_evidence_layer`
composes (`fetch_event_rows` -> every extractor's `raw_evidence_*` -> `resolve_evidence` ->
`finalize_evidence`), deliberately *not* calling `run_evidence_layer` itself, because that
function's own job also includes `persist_signals` — calling it a second time per triage run would
insert duplicate `signals` rows. Every function this module calls is side-effect-free (baseline
lookups are reads), so re-running this per triage call is safe, if not free — see this function's
own docstring for the cost tradeoff and the injection escape hatch `build_agent_context` exposes.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.detection.evidence.beaconing import raw_evidence_beaconing
from app.detection.evidence.burst import raw_evidence_burst
from app.detection.evidence.dga import load_artifact as load_dga_artifact
from app.detection.evidence.dga import raw_evidence_dga
from app.detection.evidence.events_dao import fetch_event_rows
from app.detection.evidence.payload import EvidencePayload, RawEvidence, finalize_evidence
from app.detection.evidence.rarity import raw_evidence_rarity
from app.detection.evidence.resolve_evidence import resolve_evidence
from app.detection.evidence.stl import raw_evidence_stl
from app.detection.evidence.url_path import raw_evidence_url_entropy
from app.models.base import tenant_scope
from app.models.entity import Entity
from app.models.event import Event
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.tenant import Tenant
from app.privacy.pseudonymize import PseudonymKind, pseudonymize
from app.privacy.redact import redact_text

__all__ = [
    "AgentContext",
    "AgentContextError",
    "build_agent_context",
    "compute_evidence_payloads",
    "log_citation_id",
]

log = get_logger(__name__)

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
    # docs/v2_migration change 3: the incident's own `anomaly_confidence` (0-100, calibrated,
    # `app.detection.fusion.anomaly_confidence_from_fused_score`), read once here so every
    # consumer of this context (the prompt builder, the verifier) works off the same value the
    # incident row actually carries. Rounded defensively to the same one-decimal precision
    # `anomaly_confidence_from_fused_score` already produces, in case Postgres' `REAL` (4-byte
    # float) column round-trip introduced representation noise -- see
    # `app.agent.verifier.verify_anomaly_confidence`'s tolerance for why exact equality still
    # works after this rounding.
    anomaly_confidence: float
    # docs/v2_migration change 2: this incident's own `EvidencePayload`s, already filtered to its
    # entity scope + time window (`_filter_evidence_for_incident`) — see `compute_evidence_
    # payloads` and this module's own docstring for where these come from.
    evidence_payloads: tuple[EvidencePayload, ...] = ()
    _pseudonym_to_raw: dict[str, str] = field(default_factory=dict)
    # change 7's `BASELINE-n` citation namespace — see this module's own docstring.
    _baseline_citations: dict[str, dict[str, Any]] = field(default_factory=dict)
    # change 7 check 3 (retrieval match) — every technique id this run has actually retrieved,
    # either by the automatic evidence-driven step or via the `search_mitre` tool mid-run.
    _retrieved_technique_ids: set[str] = field(default_factory=set)

    def cite_baseline(self, result: dict[str, Any]) -> str:
        """Mint the next `BASELINE-{n}` id for one `get_entity_baseline` result, remember it for
        `app.agent.verifier`, and return the id so the tool result itself can carry it."""
        baseline_id = f"BASELINE-{len(self._baseline_citations) + 1}"
        self._baseline_citations[baseline_id] = result
        return baseline_id

    @property
    def baseline_citations(self) -> dict[str, dict[str, Any]]:
        return dict(self._baseline_citations)

    def record_retrieved_techniques(self, technique_ids: Sequence[str]) -> None:
        self._retrieved_technique_ids.update(technique_ids)

    @property
    def retrieved_technique_ids(self) -> frozenset[str]:
        return frozenset(self._retrieved_technique_ids)

    def log_ids_for_event_ids(self, event_ids: set[int]) -> dict[int, str]:
        """`Event.id -> LOG-{raw_line_no}` for a small, explicit set of event ids -- translates
        `Signal.evidence_event_ids` (DB primary keys, existing schema) into the citation
        identifiers change 7 actually wants cited. A targeted `IN (...)` query, never a
        full-analysis scan (CLAUDE.md rule 1). Shared by `tools.get_related_signals` and
        `orchestrator._build_incident_context_block` so the two places that render a `Signal`'s
        evidence for the model always agree on the id."""
        if not event_ids:
            return {}
        with tenant_scope(self.session, self.tenant_id):
            rows = self.session.execute(
                select(Event.id, Event.raw_line_no)
                .where(Event.analysis_id == self.analysis_id)
                .where(Event.id.in_(event_ids))
            ).all()
        return {event_id: log_citation_id(raw_line_no) for event_id, raw_line_no in rows}

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


def log_citation_id(raw_line_no: int) -> str:
    """`LOG-{n}` for a raw file line number — change 7's `[LOG-1291]` citation form, keyed on
    `Event.raw_line_no` (the *file's* line number), not `Event.id` (the DB primary key). This
    matches `EvidencePayload.contributing_line_numbers` exactly (change 2's own module docstring:
    "the file's line numbers, not events.id"), so a citation minted from an evidence payload and
    one minted from a tool-retrieved event are the same identifier space."""
    return f"LOG-{raw_line_no}"


def compute_evidence_payloads(
    session: Session, *, analysis_id: uuid.UUID, tenant_id: uuid.UUID
) -> list[EvidencePayload]:
    """Re-derive this analysis's full `EvidencePayload` list on demand — see this module's own
    docstring ("Where EvidencePayloads come from at triage time") for why this recomputes rather
    than reading a persisted copy. Every step is pure or DB-read-only; nothing here inserts a row.

    ## Cost

    This re-runs every evidence extractor over every one of the analysis's events. For a single
    `triage_incident` call that is the going cost of not having a persisted evidence store yet.
    `triage_top_incidents_for_analysis` computes this **once** per analysis and passes the same
    list into every incident's `build_agent_context` call (its own `evidence_payloads` override)
    rather than paying this cost once per triaged incident — see that function.
    """
    with tenant_scope(session, tenant_id):
        rows = fetch_event_rows(session, analysis_id)

        try:
            artifact = load_dga_artifact()
        except FileNotFoundError:
            # Degrade, never fail a triage run over a missing DGA model artifact (parallel to
            # `orchestrator._prior_analyst_decisions_block`'s own degrade-on-failure policy) — DGA
            # evidence is one of six extractors, not a triage precondition.
            log.warning("agent.dga_artifact_missing", analysis_id=str(analysis_id))
            artifact = None

        raw_evidence: list[RawEvidence] = [
            *raw_evidence_beaconing(rows),
            *(raw_evidence_dga(rows, artifact=artifact) if artifact is not None else []),
            *raw_evidence_burst(rows),
            *raw_evidence_rarity(rows),
            *raw_evidence_stl(rows),
            *raw_evidence_url_entropy(rows),
        ]
        drafts = resolve_evidence(session, tenant_id, raw_evidence)
    return finalize_evidence(drafts)


def _filter_evidence_for_incident(
    payloads: Sequence[EvidencePayload],
    *,
    entity_scope: frozenset[tuple[str, str]],
    window_start: datetime,
    window_end: datetime,
) -> tuple[EvidencePayload, ...]:
    """An `EvidencePayload` belongs to this incident when its own entity is one of the incident's
    entities (same pairing `_entity_scope` already builds) and its window overlaps the incident's
    own window, padded by `CITATION_TEMPORAL_SLACK` on each side — the same slack the citation
    "scope" check uses, so an evidence payload that would pass a citation's scope check is never
    excluded from the context that citation is drawn from."""
    lo = window_start - CITATION_TEMPORAL_SLACK
    hi = window_end + CITATION_TEMPORAL_SLACK
    out = []
    for p in payloads:
        pair = (p.entity.get("type", ""), p.entity.get("value", ""))
        if pair not in entity_scope:
            continue
        p_start, p_end = p.window
        if p_start <= hi and lo <= p_end:
            out.append(p)
    return tuple(out)


def build_agent_context(
    session: Session,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    *,
    evidence_payloads: Sequence[EvidencePayload] | None = None,
) -> AgentContext:
    """Load everything one incident's triage run needs, once, up front.

    `evidence_payloads`, when given, is used as-is (still filtered to this incident's scope) --
    the escape hatch `triage_top_incidents_for_analysis` uses to compute an analysis's evidence
    once and share it across every incident's context instead of paying `compute_evidence_
    payloads`'s cost once per incident. `None` (the default, and every direct `build_agent_context`
    call in this package's own tests) computes it fresh.

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

    all_evidence = (
        evidence_payloads
        if evidence_payloads is not None
        else compute_evidence_payloads(
            session, analysis_id=incident.analysis_id, tenant_id=tenant_id
        )
    )
    incident_evidence = _filter_evidence_for_incident(
        all_evidence, entity_scope=scope, window_start=window_start, window_end=window_end
    )

    ctx = AgentContext(
        session=session,
        tenant_id=incident.tenant_id,
        analysis_id=incident.analysis_id,
        incident_id=incident.id,
        pseudonym_salt=bytes(tenant.pseudonym_salt),
        window_start=window_start,
        window_end=window_end,
        entity_scope=scope,
        anomaly_confidence=round(incident.anomaly_confidence, 1),
        evidence_payloads=incident_evidence,
    )
    # Seed the reverse cache with every entity already known to be in scope, so a tool call
    # referencing one of the incident's own entities resolves even before query_events has
    # pseudonymized it in this run.
    for entity_type, raw_value in scope:
        ctx.pseudonymize_value(raw_value, entity_type)
    return ctx
