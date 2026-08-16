"""`app.agent.mitre` -- the MITRE ATT&CK RAG corpus and the anti-hallucination primitive every
other agent module builds on. No DB, no network -- fully offline per CLAUDE.md.

MIGRATION-01-evidence-first.md change 4 restructured this corpus from ~70 hand-curated ATT&CK
techniques (many from tactics a web proxy cannot observe) down to exactly the thirteen
proxy-observable techniques in `data/kb/mitre/allowlist.yml`. These tests assert the allowlist
gate itself (a document outside it is a load error, not a silent extra entry), that every
technique document carries the full detection-knowledge schema the migration specifies, and that
the free-text `search_mitre` RAG path still behaves deterministically over the new, smaller
corpus.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
import yaml

from app.agent import mitre
from app.agent.mitre import (
    ALLOWLISTED_TECHNIQUE_COUNT,
    OBSERVABILITY_VALUES,
    MitreCorpusError,
    all_technique_ids,
    get_technique,
    search_mitre,
    technique_exists,
)
from app.detection.evidence.constants import (
    EXTRACTOR_BEACONING,
    EXTRACTOR_BURST,
    EXTRACTOR_DGA,
    EXTRACTOR_RARITY,
    EXTRACTOR_STL,
    EXTRACTOR_URL_ENTROPY,
)

# MIGRATION-01 change 4's exact starting set, verbatim.
ALLOWLISTED_TECHNIQUE_IDS = (
    "T1071.001",
    "T1102",
    "T1567",
    "T1567.002",
    "T1567.004",
    "T1041",
    "T1029",
    "T1568.002",
    "T1105",
    "T1090",
    "T1505.003",
    "T1595",
    "T1204",
)

# Real ATT&CK ids that were in the pre-migration corpus (data/mitre/techniques.json) but are
# outside proxy-observable scope and therefore must NOT survive the change-4 filter -- these are
# not fabricated ids (technique_exists's "plausible but nonexistent" case, tested separately),
# they are real MITRE ids the migration deliberately excludes.
EXCLUDED_REAL_TECHNIQUE_IDS = (
    "T1078",  # Valid Accounts -- not proxy-observable in the sense this corpus targets
    "T1552.001",  # Credentials In Files
    "T1530",  # Data from Cloud Storage (collection, not exfiltration)
    "T1020",  # Automated Exfiltration -- superseded by the T1029/T1567 family in this allowlist
)

_VALID_EXTRACTORS = frozenset(
    {
        EXTRACTOR_BEACONING,
        EXTRACTOR_DGA,
        EXTRACTOR_BURST,
        EXTRACTOR_RARITY,
        EXTRACTOR_STL,
        EXTRACTOR_URL_ENTROPY,
    }
)


# ---------------------------------------------------------------------------- allowlist gate


def test_allowlist_has_exactly_thirteen_techniques() -> None:
    assert ALLOWLISTED_TECHNIQUE_COUNT == 13
    ids = all_technique_ids()
    assert len(ids) == 13
    assert len(set(ids)) == 13


def test_corpus_ids_match_the_migration_starting_set_exactly() -> None:
    assert set(all_technique_ids()) == set(ALLOWLISTED_TECHNIQUE_IDS)


@pytest.mark.parametrize("excluded_id", EXCLUDED_REAL_TECHNIQUE_IDS)
def test_technique_outside_allowlist_is_rejected_even_though_it_is_a_real_attck_id(
    excluded_id: str,
) -> None:
    """The exact behavior change 4 asks for: "loading rejects anything outside it." A real ATT&CK
    id that simply isn't proxy-observable enough to make this system's allowlist must be
    indistinguishable, from this module's public API, from an id that was never a real technique
    at all -- otherwise a downstream consumer could be tempted to special-case "real but
    unlisted" ids instead of treating the allowlist as the hard gate it is."""
    assert technique_exists(excluded_id) is False
    assert get_technique(excluded_id) is None
    assert excluded_id not in all_technique_ids()


def _minimal_doc(technique_id: str, name: str, **overrides: object) -> dict[str, object]:
    doc: dict[str, object] = {
        "technique": technique_id,
        "name": name,
        "tactics": ["Command and Control"],
        "description": "test description",
        "observable_with_zscaler_proxy": "YES",
        "required_fields": ["domain"],
        "useful_additional_evidence": ["endpoint_telemetry"],
        "zscaler_observables": ["some observable pattern"],
        "supporting_detectors": ["beaconing"],
        "evidence_required": ["some evidence"],
        "evidence_that_weakens": ["a benign explanation"],
        "attack_detection_guidance": "some guidance",
        "source": "MITRE ATT&CK",
    }
    doc.update(overrides)
    return doc


def _write_corpus(
    tmp_path: Path, entries: list[tuple[str, str]], docs: dict[str, dict[str, object]]
) -> tuple[Path, Path]:
    """Writes a throwaway allowlist.yml + techniques/*.yml tree under tmp_path and returns
    (allowlist_path, techniques_dir) for a direct `mitre._load_index(...)` call -- whitebox
    testing of the loader's own corpus-integrity checks, which the real, valid on-disk corpus
    never exercises (it always passes)."""
    allowlist_path = tmp_path / "allowlist.yml"
    allowlist_path.write_text(
        yaml.safe_dump({"techniques": [{"id": tid, "name": name} for tid, name in entries]})
    )
    techniques_dir = tmp_path / "techniques"
    techniques_dir.mkdir()
    for filename, doc in docs.items():
        (techniques_dir / filename).write_text(yaml.safe_dump(doc))
    return allowlist_path, techniques_dir


def _thirteen_fake_entries() -> list[tuple[str, str]]:
    return [(f"T9{i:03d}", f"Fake Technique {i}") for i in range(13)]


def test_loading_rejects_a_document_not_in_the_allowlist(tmp_path: Path) -> None:
    entries = _thirteen_fake_entries()
    docs = {f"{tid}.yml": _minimal_doc(tid, name) for tid, name in entries}
    # A fourteenth document exists on disk but was never added to the allowlist.
    docs["T9999.yml"] = _minimal_doc("T9999", "Not Allowlisted")
    allowlist_path, techniques_dir = _write_corpus(tmp_path, entries, docs)

    with pytest.raises(MitreCorpusError, match="not in the allowlist"):
        mitre._load_index(allowlist_path=allowlist_path, techniques_dir=techniques_dir)


def test_loading_rejects_an_allowlist_entry_with_no_matching_document(tmp_path: Path) -> None:
    entries = _thirteen_fake_entries()
    docs = {f"{tid}.yml": _minimal_doc(tid, name) for tid, name in entries}
    del docs[f"{entries[0][0]}.yml"]  # allowlist still lists it; the document is missing
    allowlist_path, techniques_dir = _write_corpus(tmp_path, entries, docs)

    with pytest.raises(MitreCorpusError, match="no matching document"):
        mitre._load_index(allowlist_path=allowlist_path, techniques_dir=techniques_dir)


def test_loading_rejects_wrong_allowlist_count(tmp_path: Path) -> None:
    entries = _thirteen_fake_entries()[:5]  # only five, not thirteen
    docs = {f"{tid}.yml": _minimal_doc(tid, name) for tid, name in entries}
    allowlist_path, techniques_dir = _write_corpus(tmp_path, entries, docs)

    with pytest.raises(MitreCorpusError, match="exactly 13"):
        mitre._load_index(allowlist_path=allowlist_path, techniques_dir=techniques_dir)


def test_loading_rejects_empty_evidence_that_weakens(tmp_path: Path) -> None:
    entries = _thirteen_fake_entries()
    docs = {f"{tid}.yml": _minimal_doc(tid, name) for tid, name in entries}
    bad_id, bad_name = entries[0]
    docs[f"{bad_id}.yml"] = _minimal_doc(bad_id, bad_name, evidence_that_weakens=[])
    allowlist_path, techniques_dir = _write_corpus(tmp_path, entries, docs)

    with pytest.raises(MitreCorpusError, match="evidence_that_weakens"):
        mitre._load_index(allowlist_path=allowlist_path, techniques_dir=techniques_dir)


def test_loading_rejects_unknown_observability_value(tmp_path: Path) -> None:
    entries = _thirteen_fake_entries()
    docs = {f"{tid}.yml": _minimal_doc(tid, name) for tid, name in entries}
    bad_id, bad_name = entries[0]
    docs[f"{bad_id}.yml"] = _minimal_doc(bad_id, bad_name, observable_with_zscaler_proxy="MAYBE")
    allowlist_path, techniques_dir = _write_corpus(tmp_path, entries, docs)

    with pytest.raises(MitreCorpusError, match="observable_with_zscaler_proxy"):
        mitre._load_index(allowlist_path=allowlist_path, techniques_dir=techniques_dir)


def test_loading_rejects_unknown_supporting_detector(tmp_path: Path) -> None:
    entries = _thirteen_fake_entries()
    docs = {f"{tid}.yml": _minimal_doc(tid, name) for tid, name in entries}
    bad_id, bad_name = entries[0]
    docs[f"{bad_id}.yml"] = _minimal_doc(
        bad_id,
        bad_name,
        supporting_detectors=["autoencoder"],  # not a real extractor
    )
    allowlist_path, techniques_dir = _write_corpus(tmp_path, entries, docs)

    with pytest.raises(MitreCorpusError, match="non-existent extractor"):
        mitre._load_index(allowlist_path=allowlist_path, techniques_dir=techniques_dir)


# ---------------------------------------------------------------------------- document schema


@pytest.mark.parametrize("technique_id", ALLOWLISTED_TECHNIQUE_IDS)
def test_every_technique_document_has_the_full_detection_knowledge_schema(
    technique_id: str,
) -> None:
    """MIGRATION-01 change 4: "Write all 13 documents with real, accurate content" and
    "`observable_with_zscaler_proxy` and `useful_additional_evidence` are load-bearing." Every
    allowlisted technique must parse and carry every field, non-empty, including a non-empty
    `evidence_that_weakens` -- "the field that most needs genuine thought."""
    t = get_technique(technique_id)
    assert t is not None
    assert t.id == technique_id
    assert t.name
    assert t.tactics
    assert t.description
    assert t.observable_with_zscaler_proxy in OBSERVABILITY_VALUES
    assert t.required_fields
    assert t.useful_additional_evidence
    assert t.zscaler_observables
    assert t.supporting_detectors
    assert set(t.supporting_detectors) <= _VALID_EXTRACTORS
    assert t.evidence_required
    assert t.evidence_that_weakens, "evidence_that_weakens must be non-empty"
    assert t.attack_detection_guidance
    assert t.source


def test_t1029_matches_the_migrations_own_worked_example() -> None:
    """Change 4 gives T1029 as the literal worked example, including specific
    evidence_that_weakens phrasing and supporting_detectors -- assert the shipped document
    actually reflects it, not just "some" content."""
    t = get_technique("T1029")
    assert t is not None
    assert t.name == "Scheduled Transfer"
    assert set(t.supporting_detectors) == {
        EXTRACTOR_BEACONING,
        EXTRACTOR_STL,
        EXTRACTOR_RARITY,
        EXTRACTOR_BURST,
    }
    # required_fields uses this system's own hot-column vocabulary (docs/03: principal/ts, not
    # the migration example's illustrative "user"/"timestamp") -- domain and bytes_out are named
    # identically either way.
    assert {"domain", "bytes_out"} <= set(t.required_fields)
    weakens = " ".join(t.evidence_that_weakens).lower()
    assert "software updater" in weakens
    assert "saas synchronisation" in weakens or "saas synchronization" in weakens
    assert "historically common for this user" in weakens


# ---------------------------------------------------------------------------- basic lookups


def test_technique_exists_true_for_real_id() -> None:
    assert technique_exists("T1071.001") is True


def test_technique_exists_false_for_fabricated_id() -> None:
    """The exact anti-hallucination check: a plausible-looking but nonexistent id must be
    rejected, not silently accepted because it merely matches the `T####` shape."""
    assert technique_exists("T9999.999") is False
    assert technique_exists("T1071.999") is False
    assert technique_exists("not-a-technique-id") is False
    assert technique_exists("") is False


def test_get_technique_returns_full_record_for_real_id() -> None:
    t = get_technique("T1071.001")
    assert t is not None
    assert t.id == "T1071.001"
    assert t.name
    assert t.description
    assert t.attack_detection_guidance
    assert "Command and Control" in t.tactics


def test_get_technique_returns_none_for_fabricated_id() -> None:
    assert get_technique("T9999.999") is None


# ---------------------------------------------------------------------------- search_mitre (free text)


def test_search_mitre_ranks_relevant_technique_first() -> None:
    results = search_mitre("beaconing command and control over HTTP", top_k=5)
    assert results
    ids = [r.id for r in results]
    assert "T1071.001" in ids
    assert results[0].score is not None
    assert all(r.score is not None for r in results)
    scores = [r.score for r in results]
    assert scores == sorted(scores, reverse=True)


def test_search_mitre_every_result_id_exists_in_corpus() -> None:
    """The RAG layer of the anti-hallucination guarantee: search results are drawn only from the
    real corpus, never synthesized."""
    for query in (
        "data exfiltration large upload newly registered domain",
        "credential theft unsecured file",
        "web shell command execution",
        "",
        "asdkjfhaksjdhfkajshdf not a real query at all",
    ):
        for result in search_mitre(query, top_k=10):
            assert technique_exists(result.id)


def test_search_mitre_empty_query_returns_empty() -> None:
    assert search_mitre("", top_k=5) == []
    assert search_mitre("   ", top_k=5) == []


def test_search_mitre_top_k_zero_returns_empty() -> None:
    assert search_mitre("beaconing", top_k=0) == []


def test_search_mitre_no_vocabulary_overlap_returns_empty_not_arbitrary_rows() -> None:
    """A query that shares no vocabulary with the corpus must not silently return top_k
    arbitrary/zero-relevance rows dressed up as results."""
    results = search_mitre("zzzqqqxxx_not_a_real_word_anywhere_zzzqqqxxx", top_k=5)
    assert results == []


def test_search_mitre_deterministic_for_identical_query() -> None:
    """Fixture-replay determinism depends on this: the same query must always produce the same
    ranked ids in the same order."""
    a = [t.id for t in search_mitre("web protocols command and control", top_k=5)]
    b = [t.id for t in search_mitre("web protocols command and control", top_k=5)]
    assert a == b


# ---------------------------------------------------------------------------- offline guarantee


def test_no_network_calls_at_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLAUDE.md / change 4: "Cache locally in data/kb/; no network calls at runtime." Blocks
    socket connections at the lowest level and proves the corpus still loads (from disk) and
    `search_mitre` still works."""

    def _blocked_connect(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network access attempted while loading/searching the MITRE KB")

    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)
    mitre._load_index.cache_clear()
    try:
        results = search_mitre("beaconing command and control", top_k=3)
        assert results
        assert all(technique_exists(r.id) for r in results)
    finally:
        mitre._load_index.cache_clear()
