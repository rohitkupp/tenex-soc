"""MITRE ATT&CK RAG corpus -- docs/07-AGENT.md `search_mitre`, restructured by
MIGRATION-01-evidence-first.md change 4 ("RAG restructured: proxy-observable filter +
detection-strategy docs + Zscaler KB").

## What changed from the pre-migration corpus

The old corpus (`data/mitre/techniques.json`) held ~70 hand-curated ATT&CK techniques spanning
tactics a web proxy cannot observe (Discovery, Lateral Movement, Impact, ...). Change 4 is
explicit about why that is a liability, not generosity: *"A web proxy cannot observe registry
modification, LSASS dumping, or process injection, and retrieving those techniques invites
hypotheses the telemetry can never support -- which is precisely how RAG creates false
attribution."* This module now loads exactly the thirteen techniques in
`data/kb/mitre/allowlist.yml`, no more, no fewer, and each one carries **detection knowledge, not
just a description**: whether it is observable from this data source at all, which of this
system's own extractors could support it, and -- the field that most needs genuine thought --
what evidence would argue *against* the hypothesis (`evidence_that_weakens`). See each file under
`data/kb/mitre/techniques/` for the full per-technique content and `allowlist.yml` for the gate
itself.

## Still fully offline, still TF-IDF

**The anti-hallucination guarantee lives here, not just in the prompt.** `search_mitre` can only
ever return technique ids that are literal keys of the loaded corpus, and `technique_exists`/
`get_technique` remain the single source of truth every other module in this package (`tools.py`'s
tool schema, `schemas.py`'s structured-output enum) uses to reject a fabricated id. There is no
code path in this package that can echo a technique id that didn't come from this loader --
and after this change, that id set is the thirteen-technique allowlist, not all of ATT&CK.

Retrieval keeps the same mechanism as before (`docs/07`: "a few hundred techniques fits in memory
as a numpy matrix -- no vector DB needed... zero network calls"): TF-IDF vectors built once,
in-process, with `sklearn.feature_extraction.text.TfidfVectorizer`, cosine-similarity ranked.
Change 4 asks to "change what it indexes and what the query is built from" -- the *what it
indexes* half is this module (`_corpus_text` below now pulls from the richer per-technique
detection fields, not just name+description, so the vocabulary a query needs to match against
includes things like "beaconing", "cloud storage", "bytes_out"); the *what the query is built
from* half is `app.agent.retrieval`, which builds queries from an `EvidencePayload` or a
`ZscalerVerdictEvidence` rather than free text. `search_mitre` itself is unchanged in signature
and stays available as the free-text tool the LLM can call directly (`tools.py`'s `search_mitre`
tool) -- change 4 adds a second, evidence-driven retrieval path in `retrieval.py`, it does not
remove this one.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Final

import numpy as np
import numpy.typing as npt
import yaml
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.detection.evidence.constants import (
    EXTRACTOR_BEACONING,
    EXTRACTOR_BURST,
    EXTRACTOR_DGA,
    EXTRACTOR_RARITY,
    EXTRACTOR_STL,
    EXTRACTOR_URL_ENTROPY,
)

__all__ = [
    "ALLOWLISTED_TECHNIQUE_COUNT",
    "OBSERVABILITY_VALUES",
    "Technique",
    "all_technique_ids",
    "get_technique",
    "search_mitre",
    "technique_exists",
]

_KB_ROOT: Final[Path] = Path(__file__).resolve().parents[2] / "data" / "kb" / "mitre"
_ALLOWLIST_PATH: Final[Path] = _KB_ROOT / "allowlist.yml"
_TECHNIQUES_DIR: Final[Path] = _KB_ROOT / "techniques"

# MIGRATION-01 change 4, verbatim starting set -- "exactly this starting set". A change to this
# number is a deliberate, reviewed widening of the allowlist, not a side effect of editing a file.
ALLOWLISTED_TECHNIQUE_COUNT: Final[int] = 13

OBSERVABILITY_VALUES: Final[frozenset[str]] = frozenset({"YES", "PARTIAL", "NO"})

# supporting_detectors must name real extractors from app/detection/evidence/ (change 4's own
# instruction) -- validated against the same constants those extractors declare themselves,
# never a locally-redeclared literal set that could drift.
_VALID_EXTRACTORS: Final[frozenset[str]] = frozenset(
    {
        EXTRACTOR_BEACONING,
        EXTRACTOR_DGA,
        EXTRACTOR_BURST,
        EXTRACTOR_RARITY,
        EXTRACTOR_STL,
        EXTRACTOR_URL_ENTROPY,
    }
)

_REQUIRED_DOC_FIELDS: Final[tuple[str, ...]] = (
    "technique",
    "name",
    "description",
    "observable_with_zscaler_proxy",
    "required_fields",
    "useful_additional_evidence",
    "zscaler_observables",
    "supporting_detectors",
    "evidence_required",
    "evidence_that_weakens",
    "attack_detection_guidance",
    "source",
)


@dataclass(frozen=True, slots=True)
class Technique:
    """One allowlisted ATT&CK technique, in the shape MIGRATION-01 change 4 specifies --
    detection knowledge, not just a description. `tactics` is additive beyond the migration's
    literal YAML template (sourced from MITRE's own STIX kill-chain-phase data at KB build time,
    not hand-guessed) -- kept because it is genuinely useful retrieval and prompt vocabulary and
    because dropping it would remove information from what `tools.py`'s `search_mitre` tool
    already surfaces to the LLM today; every field the migration's template does specify is
    present and unchanged in meaning.
    """

    id: str
    name: str
    tactics: tuple[str, ...]
    description: str
    observable_with_zscaler_proxy: str  # "YES" | "PARTIAL" | "NO"
    required_fields: tuple[str, ...]
    useful_additional_evidence: tuple[str, ...]
    zscaler_observables: tuple[str, ...]
    supporting_detectors: tuple[str, ...]
    evidence_required: tuple[str, ...]
    evidence_that_weakens: tuple[str, ...]
    attack_detection_guidance: str
    source: str = "MITRE ATT&CK"
    score: float | None = None  # similarity score; only populated on search_mitre results


class MitreCorpusError(Exception):
    """The KB itself is malformed, incomplete, or has drifted from the allowlist -- a packaging
    bug, not a runtime condition. Fails loudly at load time rather than surfacing as a confusing
    empty-results condition on the first `search_mitre` call, and rather than silently loading a
    non-observable technique a judge would later have to reject."""


def _read_yaml(path: Path) -> object:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MitreCorpusError(f"could not read {path}: {exc}") from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise MitreCorpusError(f"{path} is not valid YAML: {exc}") from exc


def _load_allowlist(path: Path) -> dict[str, str]:
    """`{technique_id: name}` from `allowlist.yml`, validated to be exactly
    `ALLOWLISTED_TECHNIQUE_COUNT` entries with no duplicate ids -- the hard gate every technique
    document is checked against below."""
    raw = _read_yaml(path)
    if not isinstance(raw, dict) or not isinstance(raw.get("techniques"), list):
        raise MitreCorpusError(f"{path} must contain a top-level 'techniques' list")
    entries = raw["techniques"]
    allowlist: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or "id" not in entry or "name" not in entry:
            raise MitreCorpusError(f"{path} has a malformed entry: {entry!r}")
        tid = str(entry["id"]).strip()
        if tid in allowlist:
            raise MitreCorpusError(f"{path} lists duplicate technique id {tid!r}")
        allowlist[tid] = str(entry["name"]).strip()
    if len(allowlist) != ALLOWLISTED_TECHNIQUE_COUNT:
        raise MitreCorpusError(
            f"{path} must list exactly {ALLOWLISTED_TECHNIQUE_COUNT} techniques "
            f"(MIGRATION-01 change 4's starting set); found {len(allowlist)}"
        )
    return allowlist


def _as_str_tuple(value: object, *, field: str, doc_id: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise MitreCorpusError(f"technique {doc_id!r} field {field!r} must be a list of strings")
    return tuple(v.strip() for v in value)


def _to_technique(raw: object, path: Path) -> Technique:
    if not isinstance(raw, dict):
        raise MitreCorpusError(f"{path} must contain a YAML mapping at the top level")
    missing = [f for f in _REQUIRED_DOC_FIELDS if f not in raw]
    if missing:
        raise MitreCorpusError(f"{path} is missing required field(s): {missing}")

    doc_id = str(raw["technique"]).strip()
    name = str(raw["name"]).strip()
    description = str(raw["description"]).strip()
    observability = str(raw["observable_with_zscaler_proxy"]).strip().upper()
    attack_detection_guidance = str(raw["attack_detection_guidance"]).strip()
    source = str(raw["source"]).strip()

    if not doc_id or not name or not description or not attack_detection_guidance:
        raise MitreCorpusError(f"{path} has a blank technique/name/description/guidance field")
    if observability not in OBSERVABILITY_VALUES:
        raise MitreCorpusError(
            f"{path}: observable_with_zscaler_proxy must be one of {sorted(OBSERVABILITY_VALUES)}, "
            f"got {observability!r}"
        )

    required_fields = _as_str_tuple(raw["required_fields"], field="required_fields", doc_id=doc_id)
    useful_additional_evidence = _as_str_tuple(
        raw["useful_additional_evidence"], field="useful_additional_evidence", doc_id=doc_id
    )
    zscaler_observables = _as_str_tuple(
        raw["zscaler_observables"], field="zscaler_observables", doc_id=doc_id
    )
    supporting_detectors = _as_str_tuple(
        raw["supporting_detectors"], field="supporting_detectors", doc_id=doc_id
    )
    evidence_required = _as_str_tuple(
        raw["evidence_required"], field="evidence_required", doc_id=doc_id
    )
    evidence_that_weakens = _as_str_tuple(
        raw["evidence_that_weakens"], field="evidence_that_weakens", doc_id=doc_id
    )
    if not evidence_that_weakens:
        raise MitreCorpusError(
            f"{path}: evidence_that_weakens must be non-empty -- this is the field that lets the "
            "system argue against a hypothesis; a technique document without it is incomplete"
        )
    if not required_fields:
        raise MitreCorpusError(f"{path}: required_fields must be non-empty")

    bad_detectors = set(supporting_detectors) - _VALID_EXTRACTORS
    if bad_detectors:
        raise MitreCorpusError(
            f"{path}: supporting_detectors references non-existent extractor(s) {sorted(bad_detectors)}; "
            f"must be a subset of {sorted(_VALID_EXTRACTORS)}"
        )

    tactics_raw = raw.get("tactics") or []
    if not isinstance(tactics_raw, list):
        raise MitreCorpusError(f"{path} has a non-list 'tactics' field: {tactics_raw!r}")
    tactics = tuple(str(t).strip() for t in tactics_raw)

    return Technique(
        id=doc_id,
        name=name,
        tactics=tactics,
        description=description,
        observable_with_zscaler_proxy=observability,
        required_fields=required_fields,
        useful_additional_evidence=useful_additional_evidence,
        zscaler_observables=zscaler_observables,
        supporting_detectors=supporting_detectors,
        evidence_required=evidence_required,
        evidence_that_weakens=evidence_that_weakens,
        attack_detection_guidance=attack_detection_guidance,
        source=source or "MITRE ATT&CK",
    )


def _corpus_text(t: Technique) -> str:
    """The text each technique is embedded from. Change 4: "change what it indexes" -- this pulls
    from the detection-knowledge fields (zscaler_observables, evidence_required,
    supporting_detectors, required_fields, attack_detection_guidance), not just name+description,
    so the corpus vocabulary overlaps with the vocabulary an evidence-driven query is built from
    (`app.agent.retrieval.build_query_from_evidence`) -- literal measurement/field names like
    "bytes_out" or extractor names like "beaconing" appear in both. `evidence_that_weakens` is
    deliberately excluded: it is benign-explanation vocabulary for the judge stage, and indexing
    it would let a technique's own list of reasons *not* to believe it accidentally boost its
    retrieval rank for unrelated benign-sounding queries.
    """
    return " ".join(
        (
            t.id,
            t.name,
            t.name,  # repeated so an exact-id/exact-name query still ranks its own technique first
            " ".join(t.tactics),
            t.description,
            " ".join(t.zscaler_observables),
            " ".join(t.evidence_required),
            " ".join(t.supporting_detectors),
            " ".join(t.required_fields),
            t.attack_detection_guidance,
        )
    )


@dataclass(frozen=True, slots=True)
class _Index:
    techniques: tuple[Technique, ...]
    by_id: dict[str, Technique]
    vectorizer: TfidfVectorizer
    matrix: npt.NDArray[np.float64]  # (n_techniques, n_features), TF-IDF rows, numpy — docs/07


@lru_cache(maxsize=1)
def _load_index(
    allowlist_path: Path = _ALLOWLIST_PATH, techniques_dir: Path = _TECHNIQUES_DIR
) -> _Index:
    allowlist = _load_allowlist(allowlist_path)

    if not techniques_dir.is_dir():
        raise MitreCorpusError(f"technique document directory does not exist: {techniques_dir}")
    doc_paths = sorted(techniques_dir.glob("*.yml"))
    if not doc_paths:
        raise MitreCorpusError(f"no technique documents found under {techniques_dir}")

    techniques: list[Technique] = []
    seen: set[str] = set()
    for path in doc_paths:
        t = _to_technique(_read_yaml(path), path)
        if t.id in seen:
            raise MitreCorpusError(f"duplicate technique id across documents: {t.id!r}")
        seen.add(t.id)
        # "loading rejects anything outside [the allowlist]" -- change 4's own test requirement.
        if t.id not in allowlist:
            raise MitreCorpusError(
                f"{path} declares technique {t.id!r}, which is not in the allowlist "
                f"({allowlist_path}) -- a technique document that exists on disk but is not "
                "allowlisted is a corpus-integrity error, not a silently-ignored extra file"
            )
        if allowlist[t.id] != t.name:
            raise MitreCorpusError(
                f"{path}: name {t.name!r} does not match allowlist name {allowlist[t.id]!r} "
                f"for {t.id!r}"
            )
        techniques.append(t)

    missing = sorted(set(allowlist) - seen)
    if missing:
        raise MitreCorpusError(
            f"allowlist ({allowlist_path}) lists technique(s) with no matching document under "
            f"{techniques_dir}: {missing}"
        )

    # Stable order: allowlist file order, not directory-glob order, so corpus/matrix row order
    # (and therefore nothing observable, since ids are always looked up by id/by_id) never
    # depends on filesystem iteration order.
    order = {tid: i for i, tid in enumerate(allowlist)}
    techniques.sort(key=lambda t: order[t.id])

    vectorizer = TfidfVectorizer(lowercase=True, stop_words="english", ngram_range=(1, 2))
    matrix = vectorizer.fit_transform([_corpus_text(t) for t in techniques]).toarray()

    return _Index(
        techniques=tuple(techniques),
        by_id={t.id: t for t in techniques},
        vectorizer=vectorizer,
        matrix=matrix,
    )


def all_technique_ids() -> tuple[str, ...]:
    """Every technique id in the corpus, in allowlist order. This is the enum `app.agent.tools`
    builds the `mitre_techniques[].id` tool-schema field from — the strongest form of the
    anti-hallucination guarantee: an id outside this set is not merely *invalid*, it is not a
    representable value the model's structured output can produce at all. After change 4 this is
    always exactly the thirteen-technique allowlist."""
    return tuple(t.id for t in _load_index().techniques)


def technique_exists(technique_id: str) -> bool:
    return technique_id in _load_index().by_id


def get_technique(technique_id: str) -> Technique | None:
    return _load_index().by_id.get(technique_id)


def search_mitre(query: str, top_k: int = 5) -> list[Technique]:
    """docs/07's RAG tool, free-text form. Cosine similarity of `query`'s TF-IDF vector (using the
    corpus's already-fit vocabulary — `vectorizer.transform`, never `fit_transform`, so the query
    never perturbs the corpus's own embedding space) against every technique's row. Ties broken by
    corpus order (stable sort) so results are 100% deterministic for identical input, which
    recorded-fixture tests rely on.

    An empty or whitespace-only query, or a query that shares no vocabulary with the corpus at
    all (every row scores 0.0), returns `[]` rather than `top_k` arbitrary rows — a zero-relevance
    result set is not useful "top-k" evidence and should not be presented as if it were.

    This is the free-text path (`tools.py`'s LLM-callable `search_mitre` tool). For the
    evidence-driven retrieval path change 4 asks for -- building the query from an
    `EvidencePayload`/`ZscalerVerdictEvidence` instead of free text -- see
    `app.agent.retrieval.search_mitre_for_evidence` /
    `app.agent.retrieval.search_mitre_for_zscaler_verdict`, both of which call this function with
    a constructed query rather than duplicating the ranking logic.
    """
    if top_k <= 0:
        return []
    index = _load_index()
    q = (query or "").strip()
    if not q:
        return []

    query_vec = index.vectorizer.transform([q]).toarray()
    sims = cosine_similarity(query_vec, index.matrix)[0]

    order = np.argsort(-sims, kind="stable")[:top_k]
    results: list[Technique] = []
    for i in order:
        score = float(sims[i])
        if score <= 0.0:
            continue
        t = index.techniques[i]
        results.append(
            Technique(
                id=t.id,
                name=t.name,
                tactics=t.tactics,
                description=t.description,
                observable_with_zscaler_proxy=t.observable_with_zscaler_proxy,
                required_fields=t.required_fields,
                useful_additional_evidence=t.useful_additional_evidence,
                zscaler_observables=t.zscaler_observables,
                supporting_detectors=t.supporting_detectors,
                evidence_required=t.evidence_required,
                evidence_that_weakens=t.evidence_that_weakens,
                attack_detection_guidance=t.attack_detection_guidance,
                source=t.source,
                score=round(score, 4),
            )
        )
    return results
