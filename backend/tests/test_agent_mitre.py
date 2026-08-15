"""`app.agent.mitre` — the MITRE ATT&CK RAG corpus and the anti-hallucination primitive every
other agent module builds on. No DB, no network — fully offline per CLAUDE.md."""

from __future__ import annotations

from app.agent.mitre import all_technique_ids, get_technique, search_mitre, technique_exists

# Every technique id docs/07's build brief says the corpus must cover: referenced by
# app/detection rules, app/graph/titling.py, or datagen/scenarios (found via repo-wide grep
# during this milestone's build).
REQUIRED_TECHNIQUE_IDS = (
    "T1020",
    "T1029",
    "T1030",
    "T1048",
    "T1048.003",
    "T1071",
    "T1071.001",
    "T1078",
    "T1090",
    "T1090.003",
    "T1098.001",
    "T1105",
    "T1530",
    "T1552.001",
    "T1567",
    "T1567.002",
)


def test_corpus_covers_every_referenced_technique() -> None:
    ids = set(all_technique_ids())
    missing = [t for t in REQUIRED_TECHNIQUE_IDS if t not in ids]
    assert not missing, (
        f"corpus is missing technique(s) referenced elsewhere in the repo: {missing}"
    )


def test_corpus_has_no_duplicate_ids() -> None:
    ids = all_technique_ids()
    assert len(ids) == len(set(ids))


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
    assert t.detection
    assert "Command and Control" in t.tactics


def test_get_technique_returns_none_for_fabricated_id() -> None:
    assert get_technique("T9999.999") is None


def test_search_mitre_ranks_relevant_technique_first() -> None:
    results = search_mitre("beaconing command and control over HTTP", top_k=5)
    assert results
    ids = [r.id for r in results]
    assert "T1071.001" in ids
    # highest-scoring result should be first
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
        "lateral movement remote desktop",
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
