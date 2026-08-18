"""Tier 2 signature sync — docs/13 M14: "After an incident is triaged, emit a
tier2_signatures row."

`build_signature` is a pure function: given an already-triaged incident and the data it
needs, it returns an unsaved `Tier2Signature` ORM instance. `sync_incident_to_tier2` is the
thin, DB-touching wrapper most callers actually want: it derives the two inputs
`build_signature` can't derive itself (which entities on the incident are indicators, and
which source types the analysis came from) and persists the result.

**Where this is called from.** The live pipeline hook is `app.pipeline.stages.tier2`, which
calls `sync_incident_to_tier2` once per incident that has a verdict — see that module's own
docstring. This package guarantees a self-contained, fully tested function with exactly the
signature that stage needs: an `Incident`, a `TriageVerdict`, a `Tenant`, and nothing else that
isn't already sitting in the database by the time triage has produced a verdict.

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

from typing import Any, Literal, Final

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
from app.tier2.embedding import canonical_text, embed_text
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

# The closed vocabulary a signature's `incident_type` can ever hold, fallback included. Public
# because it is a contract, not an implementation detail: anything that writes `tier2_signatures`
# (the fleet seeder in `app.scripts.seed_tier2_fleet`) must draw from exactly this set, or the
# Tier 2 overview groups the same threat under two spellings.
INCIDENT_TYPES: Final[frozenset[str]] = frozenset(
    {*_TECHNIQUE_INCIDENT_TYPE.values(), _FALLBACK_INCIDENT_TYPE}
)

# The subset a *mapped* technique yields — `INCIDENT_TYPES` minus the fallback. Seeding draws
# from this rather than the full set: `uncategorized` is what a signature gets when its technique
# is not in the mapping, so a fleet that seeds it uniformly makes the fallback the second-largest
# category in the Tier 2 overview and reads as a broken mapping rather than as the rare edge it is.
CLASSIFIED_INCIDENT_TYPES: Final[frozenset[str]] = frozenset(_TECHNIQUE_INCIDENT_TYPE.values())


def should_sync_to_tier2(verdict: TriageVerdict) -> bool:
    """False for `benign`/`false_positive`, and false when no technique maps to a known
    incident type — see module docstring.

    **The unmapped case.** A verdict whose techniques fall outside `_TECHNIQUE_INCIDENT_TYPE`
    (including the common `NO_KNOWN_MAPPING` case, where the Analyst honestly reported that
    proxy telemetry cannot establish a technique) used to sync under the `uncategorized`
    fallback. That produced a Tier 2 row carrying an indicator hash and a tenant hash but no
    statement about *what* was seen, which is not threat intelligence: the entire value of this
    store is answering "three other tenants saw this doing X", and a row that cannot name X
    dilutes every aggregate built over it while contributing nothing to any of them. The
    `uncategorized` bucket then sat in the incident-type breakdown as a category no analyst
    could act on.

    The fallback constant stays: `_technique_incident_type` still needs a total function, and a
    row already in the store keeps its label. This only stops new ones being created.
    """
    if verdict.disposition not in _SYNCABLE_DISPOSITIONS:
        return False
    technique_ids = [t.get("id", "") for t in (verdict.mitre_techniques or []) if isinstance(t, dict)]
    return _technique_incident_type(technique_ids) != _FALLBACK_INCIDENT_TYPE


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
        # The second axis, and the reason both columns exist. `confidence` above answers "how
        # unusual was this traffic", calibrated from detectors. This answers "how well did the
        # evidence support the conclusion we drew about it", computed by `app.agent.confidence`
        # from the Judge's rubric grades. Cross-tenant, the pair is more informative than either
        # alone: an indicator every tenant scores high on but whose triages all rest on thin
        # evidence is a very different fleet-wide signal from one that is consistently
        # well-evidenced. `None` for a verdict that never reached the Judge.
        evidence_confidence=verdict.evidence_confidence,
        indicator_hashes=unique_indicator_hashes,
        # When the incident's activity actually happened, not when triage got around to
        # looking at it — `incident.created_at` is when correlation formed the incident
        # from its signals; `verdict.created_at` is only processing latency after that.
        observed_at=incident.created_at,
        # Computed here, from this signature's own structural content. It used to be read
        # straight off `incidents.embedding`, which existed for recurrence (duplicate) search in
        # the same 1024-dim space. Recurrence detection is deleted and that column with it, so
        # Tier 2 owns its embedding now — `app.tier2.embedding`, the same deterministic
        # HashingVectorizer, over the techniques/types this signature actually carries.
        embedding=embed_text(
            canonical_text(
                technique_ids=unique_techniques,
                detector_keys=[],
                entity_types=list(dict.fromkeys(source_types)),
                enrichment_tags=[],
            )
        ),
    )


def sync_incident_to_tier2(
    session: Session,
    *,
    tier2_session: Session,
    incident: Incident,
    verdict: TriageVerdict,
    tenant: Tenant,
    settings: Settings | None = None,
) -> Tier2Signature | None:
    """The end-to-end entry point: derive indicators/source types from the DB, build the
    signature, persist it. Returns `None` (and writes nothing) if
    `should_sync_to_tier2(verdict)` is false.

    **Two sessions, deliberately.** `session` reads the tenant-scoped tables in the primary
    database (`incidents`, `entities`, `analyses`, `uploads`); `tier2_session` writes the
    signature into the physically separate Tier 2 database. They are different engines over
    different databases, so one session cannot do both — which is the point: a cross-tenant row
    and a tenant-scoped row can no longer end up in the same transaction, or the same database,
    by accident.

    Caller is responsible for committing `tier2_session` (matching every other write path in
    this codebase — see `app.core.db.get_db`'s docstring); a `flush()` is enough for the
    returned row's `id` to be populated.

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
    # tier2_signatures is never tenant-scoped (see this module's docstring) and now does not
    # even live in the same database, so this write goes to `tier2_session` and deliberately
    # happens outside the `tenant_scope` block above — it does not want the tenant guard
    # involved at all, not even redundantly.
    tier2_session.add(signature)
    tier2_session.flush()
    log.info(
        "tier2.sync_written",
        incident_id=str(incident.id),
        signature_id=str(signature.id),
        incident_type=signature.incident_type,
        n_indicator_hashes=len(signature.indicator_hashes),
    )
    return signature
