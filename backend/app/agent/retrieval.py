"""Evidence-driven MITRE ATT&CK retrieval -- MIGRATION-01-evidence-first.md change 4, "Retrieval
is evidence-driven".

> Build the query from the evidence payload, not from the raw logs. `app/detection/evidence/
> payload.py` defines `EvidencePayload` -- read it. A large unusual upload + cloud-storage
> destination + rare-for-user should retrieve T1567, T1567.002, T1041: a small, evidence-relevant
> candidate set rather than free association across all of security.

`app.agent.mitre.search_mitre` is free-text and stays that way -- it is the LLM-callable tool
(`tools.py`) an Analyst can use to look something up mid-investigation. This module is the other
retrieval path the migration asks for: **automatic**, run *before* the Analyst ever sees a
prompt, over the evidence this system's own extractors already produced. It never touches raw log
lines -- only `EvidencePayload.measurements`/`.historical`/`.entity` (already-reduced, structured
numbers, exactly what CLAUDE.md rule 1 requires everywhere else in this pipeline) and the small,
fixed vocabulary of ZScaler's own vendor-verdict fields.

## Two evidence sources, kept structurally separate

`data/kb/zscaler/verdict_vs_evidence.yml` states the rule this module enforces in code: a
ZScaler threat-field hit ("Zscaler said so") and our own extractors' output ("our model detected
it") are never merged into one representation.

* `EvidencePayload` (`app.detection.evidence.payload`) -- our own deterministic extractors.
  `build_query_from_evidence` / `search_mitre_for_evidence` consume it.
* `ZscalerVerdictEvidence` (below) -- a read-only view over the subset of OCSF fields this
  system's parser already populates from ZScaler's own `threatname`/`threatcategory`/
  `riskscore`/`urlcategory`/`action` (`app/ocsf/common.py`, `app/parsers/zscaler.py`). Not a new
  persisted schema -- a plain, structurally distinct dataclass so a caller physically cannot pass
  one where the other is expected. `build_query_from_zscaler_verdict` /
  `search_mitre_for_zscaler_verdict` consume it.

`retrieve_candidates` runs both paths (either can be omitted) and returns `RetrievalCandidate`
rows carrying an `evidence_sources` trace, so "this technique was retrieved because of our own
beaconing evidence", "because ZScaler's own signature matched", or "both, independently" stay
distinguishable all the way through -- never collapsed into a single undifferentiated candidate
list.

## Why this works with a TF-IDF corpus

`app.agent.mitre` indexes each technique's `zscaler_observables` / `evidence_required` /
`supporting_detectors` / `required_fields` / `attack_detection_guidance` text (its own module
docstring, "change what it indexes"). This module deliberately builds query text out of the same
kind of vocabulary -- extractor names, literal measurement field names, qualitative descriptions
of what a measurement means -- rather than prose, so cosine similarity has real token overlap to
work with. Neither half is meaningful alone; the corpus and the query-builder are designed
together.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

import yaml

from app.agent.mitre import Technique, search_mitre
from app.detection.evidence.constants import (
    EXTRACTOR_BEACONING,
    EXTRACTOR_BURST,
    EXTRACTOR_DGA,
    EXTRACTOR_RARITY,
    EXTRACTOR_STL,
    EXTRACTOR_URL_ENTROPY,
)
from app.detection.evidence.payload import EvidencePayload

__all__ = [
    "EVIDENCE_SOURCE_MODEL_DETECTED",
    "EVIDENCE_SOURCE_ZSCALER_VERDICT",
    "RetrievalCandidate",
    "ZscalerKBError",
    "ZscalerVerdictEvidence",
    "build_query_from_evidence",
    "build_query_from_zscaler_verdict",
    "retrieve_candidates",
    "search_mitre_for_evidence",
    "search_mitre_for_zscaler_verdict",
]

# docs/v2_migration change 4's own distinction, made concrete -- see this module's docstring and
# data/kb/zscaler/verdict_vs_evidence.yml. Plain string constants (not an Enum) to match this
# codebase's own convention for small fixed vocabularies (app.detection.evidence.constants).
EVIDENCE_SOURCE_MODEL_DETECTED: Final[str] = "model_detected"
EVIDENCE_SOURCE_ZSCALER_VERDICT: Final[str] = "zscaler_verdict"

_DEFAULT_TOP_K: Final[int] = 5

_NON_ALNUM: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9]+")


def _tokenize_identifier(value: str) -> str:
    """A hostname/path/identifier -> lowercase, space-separated tokens, so `storage.googleapis.
    com` contributes `storage googleapis com` to a query -- real overlap with a technique
    document's own vocabulary (`data/kb/mitre/techniques/T1567.002.yml`'s zscaler_observables
    literally lists "storage", "blob", "s3", "drive", "bucket"). This reads entity identifiers
    already present in an `EvidencePayload`/`ZscalerVerdictEvidence` (already-reduced, structured
    data, never a raw log line), lowercased and stripped of punctuation -- there is no code
    execution or template interpretation here, only tokens fed to a TF-IDF vectorizer, so even a
    fully attacker-controlled string cannot do anything beyond mildly perturbing a cosine-
    similarity ranking (CLAUDE.md rule 3's "delimit and mark as data" concern does not apply to a
    bag-of-words feature vector the way it applies to a prompt)."""
    return _NON_ALNUM.sub(" ", value.lower()).strip()


# ---------------------------------------------------------------------------- model-detected evidence

# Base vocabulary per extractor -- deliberately overlaps with the corresponding technique
# documents' zscaler_observables/evidence_required/attack_detection_guidance text
# (app.agent.mitre's own docstring: corpus and query-builder are designed together).
_EXTRACTOR_QUERY_TERMS: Final[dict[str, str]] = {
    EXTRACTOR_BEACONING: (
        "beaconing periodic interval regular callback heartbeat command and control "
        "c2 communication recurring connection stable destination"
    ),
    EXTRACTOR_DGA: (
        "domain generation algorithm dga random gibberish high entropy domain lexical "
        "newly generated domain command and control fallback resolver"
    ),
    EXTRACTOR_BURST: (
        "volumetric burst spike sudden increase requests per minute bytes per minute "
        "unique domains upload transfer scanning fan out exfiltration outbound byte "
        "volume increase data movement"
    ),
    EXTRACTOR_RARITY: (
        "rare rarity first contact never seen before unusual destination new domain "
        "first seen baseline deviation newly registered"
    ),
    EXTRACTOR_STL: (
        "seasonal residual deviation trend anomaly off hours scheduled recurring "
        "time series unusual timing periodic component"
    ),
    EXTRACTOR_URL_ENTROPY: (
        "high entropy url path encoded token random path base64 hex webshell "
        "command parameter shell"
    ),
}


def _numeric(value: Any) -> float | None:
    return value if isinstance(value, int | float) and not isinstance(value, bool) else None


def _beaconing_hints(measurements: Mapping[str, Any]) -> str:
    hints: list[str] = []
    cv = _numeric(measurements.get("interval_cv"))
    if cv is not None and cv < 0.2:
        hints.append("highly regular low variance machine timing")
    strength = _numeric(measurements.get("spectral_strength"))
    if strength is not None and strength >= 6.0:
        hints.append("strong dominant frequency peak")
    requests = _numeric(measurements.get("requests"))
    if requests is not None and requests >= 50:
        hints.append("sustained high volume of check-ins")
    return " ".join(hints)


def _burst_hints(measurements: Mapping[str, Any]) -> str:
    hints: list[str] = []
    bytes_per_min = _numeric(measurements.get("bytes_per_min"))
    if bytes_per_min is not None and bytes_per_min > 0:
        hints.append("large data volume upload transfer outbound bytes")
    unique_domains = _numeric(measurements.get("unique_domains_per_min"))
    if unique_domains is not None and unique_domains >= 5:
        hints.append("many distinct destinations fan out scanning")
    return " ".join(hints)


def _rarity_hints(measurements: Mapping[str, Any], historical: Mapping[str, Any]) -> str:
    hints: list[str] = []
    if historical.get("org_first_seen") or historical.get("user_first_seen"):
        hints.append("first contact never seen before rare destination new domain")
    rarity = _numeric(historical.get("baseline_domain_rarity"))
    if rarity is not None and rarity > 0.5:
        hints.append("rare destination low contact count")
    org_count = _numeric(measurements.get("org_contact_count"))
    if org_count is not None and org_count == 0:
        hints.append("zero prior contact org wide")
    return " ".join(hints)


def _stl_hints(measurements: Mapping[str, Any]) -> str:
    hints: list[str] = []
    z = _numeric(measurements.get("residual_z"))
    if (z is not None and abs(z) >= 3.5) or measurements.get("residual_z_is_infinite"):
        hints.append("significant deviation from seasonal baseline unusual timing new pattern")
    return " ".join(hints)


def _url_entropy_hints(measurements: Mapping[str, Any]) -> str:
    hints: list[str] = []
    path = measurements.get("path")
    if isinstance(path, str) and path:
        hints.append(_tokenize_identifier(path))
    entropy = _numeric(measurements.get("shannon_entropy"))
    if entropy is not None and entropy >= 3.5:
        hints.append("high entropy encoded random looking token")
    return " ".join(hints)


def _dga_hints(measurements: Mapping[str, Any]) -> str:
    hints: list[str] = []
    probability = _numeric(measurements.get("probability"))
    if probability is not None and probability >= 0.5:
        hints.append("high dga probability malicious algorithmically generated domain")
    return " ".join(hints)


_EXTRACTOR_HINTS: Final[dict[str, Any]] = {
    EXTRACTOR_BEACONING: lambda p: _beaconing_hints(p.measurements),
    EXTRACTOR_BURST: lambda p: _burst_hints(p.measurements),
    EXTRACTOR_RARITY: lambda p: _rarity_hints(p.measurements, p.historical),
    EXTRACTOR_STL: lambda p: _stl_hints(p.measurements),
    EXTRACTOR_URL_ENTROPY: lambda p: _url_entropy_hints(p.measurements),
    EXTRACTOR_DGA: lambda p: _dga_hints(p.measurements),
}


def build_query_from_evidence(payloads: Sequence[EvidencePayload]) -> str:
    """The evidence-driven query text for one or more `EvidencePayload`s -- change 4's "build the
    query from the evidence payload, not from raw logs", made concrete. Pure and deterministic:
    same payloads in, same query string out, every time (no wall-clock, no randomness, no dict-
    iteration-order dependency beyond the payload sequence's own given order).

    Combines, per payload: the extractor's base vocabulary (`_EXTRACTOR_QUERY_TERMS`), the
    entity's type and identifying values tokenized (`_tokenize_identifier` -- this is how a
    destination like `storage.googleapis.com` reaches the query as `storage googleapis com`,
    giving the cloud-storage techniques' own vocabulary something to match against), and
    extractor-specific qualitative hints derived from the actual measurement/historical values
    (`_EXTRACTOR_HINTS`) rather than the raw numbers themselves -- a TF-IDF query has no use for
    a bare float, but "highly regular low variance machine timing" is real vocabulary.

    Returns `""` for an empty sequence, exactly like `search_mitre("")` does for a blank query --
    callers do not need a special case.
    """
    terms: list[str] = []
    for p in payloads:
        terms.append(_EXTRACTOR_QUERY_TERMS.get(p.extractor, p.extractor))
        entity_type = p.entity.get("type")
        if entity_type:
            terms.append(entity_type)
        for key in ("value", "domain"):
            v = p.entity.get(key)
            if v:
                terms.append(_tokenize_identifier(v))
        hint_fn = _EXTRACTOR_HINTS.get(p.extractor)
        if hint_fn is not None:
            hint = hint_fn(p)
            if hint:
                terms.append(hint)
    return " ".join(t for t in terms if t)


def search_mitre_for_evidence(
    payloads: Sequence[EvidencePayload], top_k: int = _DEFAULT_TOP_K
) -> list[Technique]:
    """`search_mitre` over a query built from our own extractors' output. See
    `build_query_from_evidence`."""
    query = build_query_from_evidence(payloads)
    return search_mitre(query, top_k=top_k)


# ---------------------------------------------------------------------------- ZScaler's own verdicts


@dataclass(frozen=True, slots=True)
class ZscalerVerdictEvidence:
    """A ZScaler-native threat verdict for one event or entity-window -- "Zscaler said so",
    structurally distinct from `EvidencePayload` ("our model detected it") per
    `data/kb/zscaler/verdict_vs_evidence.yml`. Not a new persisted schema: a read-only view over
    the subset of OCSF fields this system's parser already populates from ZScaler's own
    `threatname`/`threatcategory`/`riskscore`/`urlcategory`/`urlsupercategory`/`action`
    (`app/ocsf/common.py` `Malware.classification_ids`, `HTTPActivity.risk_score`/
    `http_request.url.category_ids`; `app/parsers/zscaler.py`). Building one of these from a
    fetched `HTTPActivity` is the caller's job (out of this module's scope -- this module owns
    retrieval, not event-to-verdict extraction); this type only has to be constructible cheaply
    from data the pipeline already has in hand.
    """

    evidence_id: str
    entity: dict[str, str]
    threat_name: str | None = None
    threat_category: str | None = None
    risk_score: int | None = None
    url_category: str | None = None
    url_supercategory: str | None = None
    action: str | None = None
    contributing_line_numbers: tuple[int, ...] = ()


_ZSCALER_KB_ROOT: Final[Path] = Path(__file__).resolve().parents[2] / "data" / "kb" / "zscaler"

_HIGH_RISK_SCORE_THRESHOLD: Final[int] = 80


class ZscalerKBError(Exception):
    """The Zscaler semantics KB (`data/kb/zscaler/`) is missing or malformed -- a packaging bug,
    parallel to `app.agent.mitre.MitreCorpusError`."""


def _read_zscaler_yaml(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ZscalerKBError(f"could not read {path}: {exc}") from exc
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ZscalerKBError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise ZscalerKBError(f"{path} must contain a YAML mapping at the top level")
    return doc


def _kb_entry_terms(entry: Mapping[str, Any]) -> str:
    """Query vocabulary for one `data/kb/zscaler/{threat_verdicts,url_categories}.yml` category
    entry: its own category/appclass/supercategory names plus whichever descriptive prose field
    it carries (`meaning` or `note`) -- the same fields a human reads to understand the category,
    tokenized for TF-IDF rather than duplicated by hand into a parallel Python literal."""
    parts = [
        str(entry.get("category", "")),
        str(entry.get("appclass", "")),
        str(entry.get("supercategory", "")),
    ]
    prose = entry.get("meaning") or entry.get("note")
    if isinstance(prose, str):
        parts.append(prose)
    return _tokenize_identifier(" ".join(parts))


@dataclass(frozen=True, slots=True)
class _ZscalerTermMaps:
    url_category_terms: dict[str, str]
    threat_category_terms: dict[str, str]


@lru_cache(maxsize=1)
def _load_zscaler_term_maps(root: Path = _ZSCALER_KB_ROOT) -> _ZscalerTermMaps:
    """Builds the `urlcategory`/`threatcategory` -> query-term vocabulary directly from
    `data/kb/zscaler/threat_verdicts.yml` and `url_categories.yml` -- change 4's "Zscaler
    semantics" corpus is what `build_query_from_zscaler_verdict` actually reads, not a
    hand-maintained copy of it. `threat_category_terms` is keyed on `appclass`
    (threat_verdicts.yml's `security_url_categories`), which is the field this KB's own vendor
    vocabulary uses that corresponds to ZScaler's `threatcategory` values (e.g. "Botnet") --
    documented in that file's own comments.
    """
    url_terms: dict[str, str] = {}
    threat_terms: dict[str, str] = {}

    threat_doc = _read_zscaler_yaml(root / "threat_verdicts.yml")
    for entry in threat_doc.get("security_url_categories", []) or []:
        text = _kb_entry_terms(entry)
        category = str(entry.get("category", "")).strip().lower()
        appclass = str(entry.get("appclass", "")).strip().lower()
        if category:
            url_terms[category] = text
        if appclass:
            threat_terms[appclass] = text

    categories_doc = _read_zscaler_yaml(root / "url_categories.yml")
    all_entries = [
        *(categories_doc.get("categories", []) or []),
        *(categories_doc.get("named_categories", []) or []),
    ]
    for entry in all_entries:
        category = str(entry.get("category", "")).strip().lower()
        if category and category not in url_terms:
            url_terms[category] = _kb_entry_terms(entry)

    return _ZscalerTermMaps(url_category_terms=url_terms, threat_category_terms=threat_terms)


def build_query_from_zscaler_verdict(verdicts: Sequence[ZscalerVerdictEvidence]) -> str:
    """The evidence-driven query text for one or more `ZscalerVerdictEvidence` records -- the
    vendor-verdict counterpart to `build_query_from_evidence`. Deliberately a separate function
    (not an overload/union parameter) so the two evidence sources can never be silently combined
    into one query without a caller choosing to do so explicitly via `retrieve_candidates`.

    Maps ZScaler's own category/threat-category vocabulary to query terms by loading
    `data/kb/zscaler/threat_verdicts.yml` and `url_categories.yml` (`_load_zscaler_term_maps`),
    plus entity identifiers tokenized the same way `build_query_from_evidence` does.
    """
    term_maps = _load_zscaler_term_maps()
    terms: list[str] = []
    for v in verdicts:
        entity_type = v.entity.get("type")
        if entity_type:
            terms.append(entity_type)
        for key in ("value", "domain"):
            val = v.entity.get(key)
            if val:
                terms.append(_tokenize_identifier(val))
        if v.threat_category:
            terms.append(
                term_maps.threat_category_terms.get(
                    v.threat_category.strip().lower(), v.threat_category
                )
            )
        if v.threat_name:
            terms.append(_tokenize_identifier(v.threat_name))
        if v.url_category:
            terms.append(
                term_maps.url_category_terms.get(v.url_category.strip().lower(), v.url_category)
            )
        if v.risk_score is not None and v.risk_score >= _HIGH_RISK_SCORE_THRESHOLD:
            terms.append("high risk severe threat")
    return " ".join(t for t in terms if t)


def search_mitre_for_zscaler_verdict(
    verdicts: Sequence[ZscalerVerdictEvidence], top_k: int = _DEFAULT_TOP_K
) -> list[Technique]:
    """`search_mitre` over a query built from ZScaler's own verdict fields. See
    `build_query_from_zscaler_verdict`."""
    query = build_query_from_zscaler_verdict(verdicts)
    return search_mitre(query, top_k=top_k)


# ---------------------------------------------------------------------------- combined retrieval


@dataclass(frozen=True, slots=True)
class RetrievalCandidate:
    """One retrieved technique plus the evidence source(s) that nominated it --
    `data/kb/zscaler/verdict_vs_evidence.yml`'s "retrieval_implication": a technique retrieved
    only because of a ZScaler verdict and one retrieved only because of our own beaconing
    evidence are not the same strength of candidate, and a caller (the Analyst prompt, out of
    this module's scope) needs to be able to tell them apart rather than receiving one
    undifferentiated list."""

    technique: Technique
    evidence_sources: tuple[str, ...]


def retrieve_candidates(
    *,
    evidence: Sequence[EvidencePayload] = (),
    zscaler_verdicts: Sequence[ZscalerVerdictEvidence] = (),
    top_k: int = _DEFAULT_TOP_K,
) -> list[RetrievalCandidate]:
    """The combined evidence-driven retrieval entrypoint: runs `search_mitre_for_evidence` and/or
    `search_mitre_for_zscaler_verdict` (either sequence may be empty) and merges the results,
    keeping each candidate's source trace distinct rather than merging the two evidence kinds
    into one score.

    Deterministic: each sub-search is deterministic (`app.agent.mitre.search_mitre`'s own
    guarantee), and the merge iterates the two result lists in a fixed order (model-detected
    first, then zscaler-verdict) with a stable sort on score, so identical inputs always produce
    an identical, identically-ordered candidate list.
    """
    model_results = search_mitre_for_evidence(evidence, top_k=top_k) if evidence else []
    verdict_results = (
        search_mitre_for_zscaler_verdict(zscaler_verdicts, top_k=top_k) if zscaler_verdicts else []
    )

    by_id: dict[str, RetrievalCandidate] = {}
    order: list[str] = []

    def _add(technique: Technique, source: str) -> None:
        existing = by_id.get(technique.id)
        if existing is None:
            by_id[technique.id] = RetrievalCandidate(
                technique=technique, evidence_sources=(source,)
            )
            order.append(technique.id)
            return
        sources = existing.evidence_sources
        if source not in sources:
            sources = (*sources, source)
        # Independent agreement is a stronger signal than either source's score alone -- keep the
        # higher-scoring `Technique` row so a candidate two sources agree on is never ranked (or
        # truncated) as if only its weaker-scoring source had found it.
        best = existing.technique
        if (technique.score or 0.0) > (best.score or 0.0):
            best = technique
        by_id[technique.id] = replace(existing, technique=best, evidence_sources=sources)

    for t in model_results:
        _add(t, EVIDENCE_SOURCE_MODEL_DETECTED)
    for t in verdict_results:
        _add(t, EVIDENCE_SOURCE_ZSCALER_VERDICT)

    candidates = [by_id[tid] for tid in order]
    candidates.sort(key=lambda c: -(c.technique.score or 0.0))
    return candidates[:top_k]
