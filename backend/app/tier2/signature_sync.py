"""Tier 2 signature sync — docs/13 M14: "After an incident is triaged, emit a
tier2_signatures row."

`build_signature` is a pure function: given an already-triaged incident and the data it
needs, it returns an unsaved `Tier2Signature` ORM instance. `sync_incident_to_tier2` is the
thin, DB-touching wrapper most callers actually want: it derives the two inputs
`build_signature` can't derive itself (which entities on the incident are indicators, and
which source types the analysis came from) and persists the result.

**Where this is called from.** The live pipeline hook is `app.pipeline`'s `tier2` stage
(currently a documented pass-through skeleton, `app.pipeline.stages.skeleton` --
"real signature sync lands at M14", i.e. here). This package does not itself modify
`app/pipeline/**` or `app/workers/tier2_sync.py` -- wiring `sync_incident_to_tier2` into
that worker as its real handler is that stage's owner's job, not this package's; what this
module guarantees is a self-contained, fully tested function with exactly the signature a
future handler needs: an `Incident`, a `TriageVerdict`, a `Tenant`, and nothing else that
isn't already sitting in the database by the time triage (M11) has produced a verdict.

**What gets synced, and what deliberately doesn't.** Only dispositions worth cross-tenant
correlation are synced (`should_sync_to_tier2`) -- `benign` and `false_positive` incidents
are, by definition, not threat intelligence, and syncing them would dilute the "N tenants
saw this" signal with noise. `needs_review` is synced: an incident the agent couldn't fully
resolve is still evidence a tenant saw *something*, and cross-tenant corroboration is
exactly the kind of information that could turn a `needs_review` into a confident verdict
next time (docs/07's few-shot memory hands this exact opportunity to M13's learning loop,
downstream of this table).
"""

from __future__ import annotations

from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.models.base import tenant_scope
from app.models.entity import Entity
from app.models.incident import Incident
from app.models.tenant import Tenant
from app.models.tier2_signature import Tier2Signature
from app.models.triage_verdict import TriageVerdict
from app.models.upload import Upload
from app.tier2.hashing import indicator_hash, tenant_hash

log = get_logger(__name__)

# entities.type values (docs/02: "user|src_ip|domain|dst_ip|asn|country") that are
# indicators in the docs/06 sense ("domains, dst IPs"). src_ip is deliberately excluded --
# a source IP is closer to a principal (whose network the traffic left from) than an
# indicator of compromise, and docs/06's Tier 2 exception names "domains, dst IPs" only.
_INDICATOR_ENTITY_TYPES: dict[str, Literal["domain", "ip"]] = {"domain": "domain", "dst_ip": "ip"}

# Only these dispositions represent something worth cross-tenant correlation. See this
# module's docstring for why `benign`/`false_positive` are excluded and `needs_review`
# isn't.
_SYNCABLE_DISPOSITIONS = frozenset({"true_positive", "needs_review"})

# MITRE technique ID -> a small, stable incident_type taxonomy, matched to the vocabulary
# docs/11-SYNTHETIC-DATA.md's scenario table already uses (c2 beaconing, data
# exfiltration, insider mass download, peer-group deviation, seasonal deviation) so a
# signature's `incident_type` reads the same whether the incident came from a synthetic
# eval scenario or a real triage. Sub-technique IDs (e.g. "T1567.002") are tried before
# falling back to their parent ("T1567") via `_technique_incident_type`.
_TECHNIQUE_INCIDENT_TYPE: dict[str, str] = {
    "T1071.001": "c2_beaconing",
    "T1071": "c2_beaconing",
    "T1567.002": "data_exfiltration",
    "T1567": "data_exfiltration",
    "T1530": "insider_mass_download",
    "T1078": "peer_group_deviation",
    "T1029": "seasonal_deviation",
}
_FALLBACK_INCIDENT_TYPE = "uncategorized"


def should_sync_to_tier2(verdict: TriageVerdict) -> bool:
    """False for `benign`/`false_positive` — see module docstring."""
    return verdict.disposition in _SYNCABLE_DISPOSITIONS


def _technique_ids(raw: Any) -> list[str]:
    """Defensive extraction from `triage_verdicts.mitre_techniques` (JSONB, docs/07's
    `[{id, name, rationale}, ...]` shape) — tolerates a malformed or legacy entry (a bare
    string, or a dict missing `id`) by skipping it rather than raising, since a sync
    failure should never be able to take down triage itself."""
    if not isinstance(raw, list):
        return []
    ids: list[str] = []
    for entry in raw:
        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
            ids.append(entry["id"])
        elif isinstance(entry, str):
            ids.append(entry)
    return ids


def _technique_incident_type(technique_ids: list[str]) -> str:
    for technique_id in technique_ids:
        if technique_id in _TECHNIQUE_INCIDENT_TYPE:
            return _TECHNIQUE_INCIDENT_TYPE[technique_id]
        base = technique_id.split(".")[0]
        if base in _TECHNIQUE_INCIDENT_TYPE:
            return _TECHNIQUE_INCIDENT_TYPE[base]
    return _FALLBACK_INCIDENT_TYPE


def derive_indicators(
    session: Session, incident: Incident
) -> list[tuple[Literal["domain", "ip"], str]]:
    """The `(kind, raw_value)` pairs to hash for `incident.indicator_hashes` — every
    `domain`/`dst_ip` entity attached to this incident (`incident.entity_ids`, docs/02).
    Queried directly against `entities` (not through `app.graph`, which this package does
    not import) since `entities` is just a table by this point in the pipeline."""
    if not incident.entity_ids:
        return []
    rows = session.execute(
        select(Entity.type, Entity.value).where(
            Entity.id.in_(incident.entity_ids),
            Entity.type.in_(_INDICATOR_ENTITY_TYPES),
        )
    ).all()
    return [(_INDICATOR_ENTITY_TYPES[row.type], row.value) for row in rows]


def derive_source_types(session: Session, incident: Incident) -> list[str]:
    """`uploads.detected_sources` (docs/02) for the upload that produced this incident's
    analysis — one query, `analyses.upload_id -> uploads.detected_sources`. Isolation is
    transitive through `incident.analysis_id`/`upload.tenant_id`, both tenant-scoped
    tables, so this must run on a session already bound to the incident's tenant (the same
    requirement `sync_incident_to_tier2` has)."""
    from app.models.analysis import Analysis

    upload_id = session.execute(
        select(Analysis.upload_id).where(Analysis.id == incident.analysis_id)
    ).scalar_one_or_none()
    if upload_id is None:
        return []
    detected = session.execute(
        select(Upload.detected_sources).where(Upload.id == upload_id)
    ).scalar_one_or_none()
    return list(detected or [])


def build_signature(
    *,
    incident: Incident,
    verdict: TriageVerdict,
    tenant: Tenant,
    source_types: list[str],
    indicators: list[tuple[Literal["domain", "ip"], str]],
    settings: Settings | None = None,
) -> Tier2Signature:
    """Pure builder — no I/O, no session. `incident` and `tenant` must agree
    (`incident.tenant_id == tenant.id`); `verdict.incident_id` must equal `incident.id`.
    Does not check `should_sync_to_tier2` itself — callers that want that gate (every
    real caller does) call it before this, so a caller that deliberately wants a signature
    for every disposition (e.g. a backfill script) isn't forced to fight the guard.
    """
    if incident.id != verdict.incident_id:
        raise ValueError(
            f"verdict {verdict.id} belongs to incident {verdict.incident_id}, not {incident.id}"
        )
    if incident.tenant_id != tenant.id:
        raise ValueError(
            f"incident {incident.id} belongs to tenant {incident.tenant_id}, not {tenant.id}"
        )

    settings = settings or get_settings()
    shared_salt = settings.tier2_indicator_salt.get_secret_value().encode()

    technique_ids = _technique_ids(verdict.mitre_techniques)
    # dict.fromkeys, not set(), for deterministic order (first-seen) — the eventual
    # tier2_signatures.mitre_techniques row should read the same on every sync of the
    # same verdict, and set() iteration order is not guaranteed to be that.
    unique_techniques = list(dict.fromkeys(technique_ids))
    unique_indicator_hashes = list(
        dict.fromkeys(indicator_hash(value, kind, shared_salt) for kind, value in indicators)
    )

    return Tier2Signature(
        tenant_hash=tenant_hash(tenant.id, tenant.pseudonym_salt),
        incident_type=_technique_incident_type(unique_techniques),
        mitre_techniques=unique_techniques,
        source_types=list(dict.fromkeys(source_types)),
        # The calibrated fusion score, not the LLM's own hypothesis-evaluation judgment
        # (`verdict.threat_confidence` -- docs/v2_migration change 3, and low/moderate/high
        # besides, not even a float this column could hold) -- CLAUDE.md rule 5 ("The LLM does
        # not set priority... contributes disposition, narrative, and technique mapping only")
        # applies here one hop downstream: a cross-tenant "how confident is this signal" number
        # should come from the same calibrated detector fusion every other ranking in this
        # system uses, not from the model's own opinion of itself.
        confidence=incident.fused_score,
        indicator_hashes=unique_indicator_hashes,
        # When the incident's activity actually happened, not when triage got around to
        # looking at it — `incident.created_at` is when correlation formed the incident
        # from its signals; `verdict.created_at` is only processing latency after that.
        observed_at=incident.created_at,
        # Reused, not recomputed: `incidents.embedding` (docs/02) already exists for
        # recurrence search in the same 1024-dim space `tier2_signatures.embedding`
        # declares — computing a second, independent embedding for the same incident
        # would be pure waste and a second place for the two to silently disagree.
        embedding=incident.embedding,
    )


def sync_incident_to_tier2(
    session: Session,
    *,
    incident: Incident,
    verdict: TriageVerdict,
    tenant: Tenant,
    settings: Settings | None = None,
) -> Tier2Signature | None:
    """The end-to-end entry point: derive indicators/source types from the DB, build the
    signature, persist it. Returns `None` (and writes nothing) if
    `should_sync_to_tier2(verdict)` is false. Caller is responsible for `session.commit()`
    (matching every other write path in this codebase — see `app.core.db.get_db`'s
    docstring) except when this is the last thing done in an already-committing scope, in
    which case a `flush()` is enough for the returned row's `id` to be populated.

    Binds `session` to `tenant.id` for the duration of this call (`app.models.base.
    tenant_scope`) — `derive_source_types` reads `analyses`/`uploads`, both tenant-scoped
    tables (docs/06: enforced structurally, not by remembering), so this function needs
    tenant scope regardless of whether the caller's session already happens to have it;
    `tenant_scope` nests safely if it does.
    """
    if not should_sync_to_tier2(verdict):
        log.info(
            "tier2.sync_skipped",
            incident_id=str(incident.id),
            disposition=verdict.disposition,
        )
        return None

    with tenant_scope(session, tenant.id):
        indicators = derive_indicators(session, incident)
        source_types = derive_source_types(session, incident)
    signature = build_signature(
        incident=incident,
        verdict=verdict,
        tenant=tenant,
        source_types=source_types,
        indicators=indicators,
        settings=settings,
    )
    # tier2_signatures itself is never tenant-scoped (see this module's docstring), so
    # the add/flush below deliberately happens *outside* the `tenant_scope` block above —
    # this write does not want the tenant guard involved at all, not even redundantly.
    session.add(signature)
    session.flush()
    log.info(
        "tier2.sync_written",
        incident_id=str(incident.id),
        signature_id=str(signature.id),
        incident_type=signature.incident_type,
        n_indicator_hashes=len(signature.indicator_hashes),
    )
    return signature
