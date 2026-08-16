"""`app.agent.retrieval` -- MIGRATION-01-evidence-first.md change 4, "Retrieval is
evidence-driven".

Covers: building a query from an `EvidencePayload` (our own extractors' output) versus a
`ZscalerVerdictEvidence` (ZScaler's own threat-field verdict) and keeping the two retrievable but
never merged; that a beaconing-heavy evidence set retrieves C2 techniques and not
exfiltration-only ones; that a large-upload/cloud-storage/rare-for-user evidence set retrieves the
technique triple the migration names explicitly (T1567, T1567.002, T1041); determinism; and that
the Zscaler semantics KB (`data/kb/zscaler/`) loads from disk with zero network calls.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime

import pytest

from app.agent import retrieval
from app.agent.mitre import technique_exists
from app.agent.retrieval import (
    EVIDENCE_SOURCE_MODEL_DETECTED,
    EVIDENCE_SOURCE_ZSCALER_VERDICT,
    RetrievalCandidate,
    ZscalerVerdictEvidence,
    build_query_from_evidence,
    build_query_from_zscaler_verdict,
    retrieve_candidates,
    search_mitre_for_evidence,
    search_mitre_for_zscaler_verdict,
)
from app.detection.evidence.constants import (
    EXTRACTOR_BEACONING,
    EXTRACTOR_BURST,
    EXTRACTOR_RARITY,
)
from app.detection.evidence.payload import EvidencePayload

_WINDOW = (datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 1, 1, 1, tzinfo=UTC))

# Exfiltration-only techniques -- no Command and Control tactic, no beaconing in
# supporting_detectors -- the negative set for the beaconing-evidence test.
_EXFIL_ONLY_TECHNIQUE_IDS = {"T1567", "T1567.002", "T1567.004"}
_C2_TECHNIQUE_IDS = {"T1071.001", "T1090", "T1102"}


def _evidence(
    *,
    extractor: str,
    entity: dict[str, str],
    measurements: dict[str, object],
    historical: dict[str, object] | None = None,
    evidence_id: str = "EVIDENCE-1",
) -> EvidencePayload:
    return EvidencePayload(
        evidence_id=evidence_id,
        extractor=extractor,
        entity=entity,
        window=_WINDOW,
        measurements=measurements,
        historical=historical or {},
        contributing_line_numbers=[1, 2, 3],
        nominates_candidate=False,
        nomination_score=None,
    )


def _beaconing_payload(domain: str = "cdn-update-check.net") -> EvidencePayload:
    return _evidence(
        extractor=EXTRACTOR_BEACONING,
        entity={"type": "src_ip", "value": "10.1.2.3", "domain": domain},
        measurements={
            "requests": 63,
            "median_interval_s": 60.1,
            "interval_cv": 0.018,
            "mad_s": 1.0,
            "dominant_period_s": 60,
            "spectral_strength": 9.4,
            "evidence_truncated": False,
        },
        historical={"beaconing_percentile": 99.7},
        evidence_id="EVIDENCE-1",
    )


def _large_upload_evidence(domain: str = "storage.googleapis.com") -> list[EvidencePayload]:
    entity = {"type": "user", "value": "alice", "domain": domain}
    burst = _evidence(
        extractor=EXTRACTOR_BURST,
        entity=entity,
        measurements={
            "requests_per_min": 2.0,
            "bytes_per_min": 50_000_000.0,
            "unique_domains_per_min": 1.0,
        },
        evidence_id="EVIDENCE-1",
    )
    rarity = _evidence(
        extractor=EXTRACTOR_RARITY,
        entity=entity,
        measurements={
            "n_events_by_principal": 5,
            "user_contact_count": 0,
            "department_contact_count": 0,
            "org_contact_count": 0,
        },
        historical={
            "user_first_seen": True,
            "department_first_seen": True,
            "org_first_seen": True,
            "baseline_domain_rarity": 1.0,
        },
        evidence_id="EVIDENCE-2",
    )
    return [burst, rarity]


# ---------------------------------------------------------------------------- query building


def test_build_query_from_evidence_empty_sequence_is_empty_string() -> None:
    assert build_query_from_evidence([]) == ""


def test_build_query_from_evidence_includes_extractor_vocabulary_and_entity_tokens() -> None:
    query = build_query_from_evidence([_beaconing_payload()])
    assert "beaconing" in query
    assert "periodic" in query
    assert "src_ip" in query
    # entity domain value is tokenized into the query, not embedded as a raw hostname string.
    assert "cdn" in query and "update" in query and "check" in query
    assert "cdn-update-check.net" not in query


def test_build_query_from_zscaler_verdict_empty_sequence_is_empty_string() -> None:
    assert build_query_from_zscaler_verdict([]) == ""


def test_build_query_from_zscaler_verdict_differs_from_model_detected_query() -> None:
    """The two query-builders draw from structurally distinct evidence and must not collapse to
    the same vocabulary even when they describe "the same" underlying incident -- see
    data/kb/zscaler/verdict_vs_evidence.yml."""
    model_query = build_query_from_evidence([_beaconing_payload()])
    verdict_query = build_query_from_zscaler_verdict(
        [
            ZscalerVerdictEvidence(
                evidence_id="ZV-1",
                entity={"type": "src_ip", "value": "10.1.2.3", "domain": "cdn-update-check.net"},
                threat_category="Botnet",
                threat_name="Backdoor.Generic.C2",
                risk_score=98,
                url_category="Botnet Callback",
            )
        ]
    )
    assert model_query != verdict_query
    # The vendor-verdict query carries ZScaler's own category vocabulary ("botnet") that the
    # model-detected query, built purely from our own extractor's measurements, has no way to
    # produce -- the two are drawing on genuinely different information, not just different words
    # for the same thing.
    assert "botnet" in verdict_query
    assert "botnet" not in model_query


# ---------------------------------------------------------------------------- beaconing -> C2, not exfil-only


def test_beaconing_evidence_retrieves_c2_techniques_not_exfiltration_only() -> None:
    results = search_mitre_for_evidence([_beaconing_payload()], top_k=5)
    result_ids = {t.id for t in results}
    assert result_ids, "beaconing-heavy evidence must retrieve something"
    assert result_ids & _C2_TECHNIQUE_IDS, f"expected at least one C2 technique in {result_ids}"
    assert not (result_ids & _EXFIL_ONLY_TECHNIQUE_IDS), (
        f"beaconing evidence must not retrieve exfiltration-only techniques, got {result_ids}"
    )


# ---------------------------------------------------------------------------- large upload -> T1567 family


def test_large_upload_to_cloud_storage_rare_for_user_retrieves_the_named_technique_triple() -> None:
    """MIGRATION-01 change 4, verbatim: "A large unusual upload + cloud-storage destination +
    rare-for-user should retrieve T1567, T1567.002, T1041.\""""
    results = search_mitre_for_evidence(_large_upload_evidence(), top_k=5)
    result_ids = {t.id for t in results}
    assert {"T1567", "T1567.002", "T1041"} <= result_ids, result_ids


def test_large_upload_query_is_evidence_driven_not_raw_log_text() -> None:
    """The query never contains anything that looks like a raw log line (e.g. a full URL, a
    User-Agent string) -- only the entity identifiers and measurement-derived vocabulary an
    EvidencePayload actually carries."""
    query = build_query_from_evidence(_large_upload_evidence())
    assert "http" not in query
    assert "GET" not in query and "POST" not in query
    assert "storage" in query and "googleapis" in query


# ---------------------------------------------------------------------------- determinism


def test_search_mitre_for_evidence_is_deterministic() -> None:
    payloads = _large_upload_evidence()
    a = [t.id for t in search_mitre_for_evidence(payloads, top_k=5)]
    b = [t.id for t in search_mitre_for_evidence(payloads, top_k=5)]
    assert a == b
    assert a  # not trivially deterministic because it's empty


def test_retrieve_candidates_is_deterministic() -> None:
    payloads = _large_upload_evidence()
    verdicts = [
        ZscalerVerdictEvidence(
            evidence_id="ZV-1",
            entity={"type": "user", "value": "alice", "domain": "storage.googleapis.com"},
            url_category="File Host",
            risk_score=40,
        )
    ]
    a = [c.technique.id for c in retrieve_candidates(evidence=payloads, zscaler_verdicts=verdicts)]
    b = [c.technique.id for c in retrieve_candidates(evidence=payloads, zscaler_verdicts=verdicts)]
    assert a == b
    assert a


def test_retrieve_candidates_empty_inputs_returns_empty_list() -> None:
    assert retrieve_candidates() == []
    assert retrieve_candidates(evidence=[], zscaler_verdicts=[]) == []


# ---------------------------------------------------------------------------- every result is a real technique


def test_search_mitre_for_evidence_every_result_id_exists_in_corpus() -> None:
    for payloads in (_large_upload_evidence(), [_beaconing_payload()]):
        for t in search_mitre_for_evidence(payloads, top_k=10):
            assert technique_exists(t.id)


def test_search_mitre_for_zscaler_verdict_every_result_id_exists_in_corpus() -> None:
    verdicts = [
        ZscalerVerdictEvidence(
            evidence_id="ZV-1",
            entity={"type": "src_ip", "value": "10.1.2.3", "domain": "evil-c2.example"},
            threat_category="Botnet",
            threat_name="Backdoor.Generic.C2",
            risk_score=98,
            url_category="Botnet Callback",
            url_supercategory="Security",
        )
    ]
    results = search_mitre_for_zscaler_verdict(verdicts, top_k=10)
    assert results
    for t in results:
        assert technique_exists(t.id)


# ---------------------------------------------------------------------------- Zscaler verdict vs model-detected


def test_zscaler_verdict_evidence_is_retrievable() -> None:
    verdicts = [
        ZscalerVerdictEvidence(
            evidence_id="ZV-1",
            entity={"type": "src_ip", "value": "10.1.2.3", "domain": "evil-c2.example"},
            threat_category="Botnet",
            threat_name="Backdoor.Generic.C2",
            risk_score=98,
            url_category="Botnet Callback",
        )
    ]
    results = search_mitre_for_zscaler_verdict(verdicts, top_k=5)
    assert results
    assert {"T1071.001", "T1041", "T1090", "T1102"} & {t.id for t in results}


def test_zscaler_verdict_and_model_detected_evidence_are_distinguishable_in_combined_retrieval() -> (
    None
):
    """The structural half of "never merge the two" (data/kb/zscaler/verdict_vs_evidence.yml):
    `retrieve_candidates` must be able to report, per candidate, which evidence source(s)
    actually nominated it -- a candidate found via only the vendor verdict, only our own
    beaconing evidence, or (when they agree) both, must all be distinguishable outcomes."""
    beacon = _beaconing_payload(domain="evil-c2.example")
    verdict = ZscalerVerdictEvidence(
        evidence_id="ZV-1",
        entity={"type": "src_ip", "value": "10.1.2.3", "domain": "evil-c2.example"},
        threat_category="Botnet",
        threat_name="Backdoor.Generic.C2",
        risk_score=98,
        url_category="Botnet Callback",
    )

    candidates = retrieve_candidates(evidence=[beacon], zscaler_verdicts=[verdict], top_k=8)
    assert candidates
    assert all(isinstance(c, RetrievalCandidate) for c in candidates)

    sources_seen = {c.evidence_sources for c in candidates}
    # At least one candidate must be traceable to model-detected evidence and at least one to
    # the Zscaler verdict -- if everything collapsed to one merged source this would fail.
    assert any(EVIDENCE_SOURCE_MODEL_DETECTED in s for s in sources_seen)
    assert any(EVIDENCE_SOURCE_ZSCALER_VERDICT in s for s in sources_seen)
    # No evidence_sources tuple is empty, and the two constants are themselves distinct strings.
    assert EVIDENCE_SOURCE_MODEL_DETECTED != EVIDENCE_SOURCE_ZSCALER_VERDICT
    assert all(c.evidence_sources for c in candidates)


def test_a_technique_found_by_both_sources_records_both_in_evidence_sources() -> None:
    beacon = _beaconing_payload(domain="evil-c2.example")
    verdict = ZscalerVerdictEvidence(
        evidence_id="ZV-1",
        entity={"type": "src_ip", "value": "10.1.2.3", "domain": "evil-c2.example"},
        threat_category="Botnet",
        threat_name="Backdoor.Generic.C2",
        risk_score=98,
        url_category="Botnet Callback",
    )
    # T1041 ranks #1 in both the model-detected and the zscaler-verdict search independently for
    # this scenario (a beaconing pair whose destination ZScaler's own signature engine also
    # flagged as Botnet Callback) -- both sources genuinely support it, so it must survive the
    # merge with both sources recorded, not just whichever search happened to run first.
    model_ids = {t.id for t in search_mitre_for_evidence([beacon], top_k=3)}
    verdict_ids = {t.id for t in search_mitre_for_zscaler_verdict([verdict], top_k=3)}
    assert "T1041" in model_ids
    assert "T1041" in verdict_ids

    candidates = retrieve_candidates(evidence=[beacon], zscaler_verdicts=[verdict], top_k=5)
    by_id = {c.technique.id: c for c in candidates}
    assert "T1041" in by_id
    assert set(by_id["T1041"].evidence_sources) == {
        EVIDENCE_SOURCE_MODEL_DETECTED,
        EVIDENCE_SOURCE_ZSCALER_VERDICT,
    }


# ---------------------------------------------------------------------------- Zscaler KB loads from disk, offline


def test_zscaler_term_maps_load_from_disk_and_are_non_empty() -> None:
    term_maps = retrieval._load_zscaler_term_maps()
    assert term_maps.url_category_terms
    assert term_maps.threat_category_terms
    assert "botnet callback" in term_maps.url_category_terms
    assert "botnet" in term_maps.threat_category_terms
    assert "file host" in term_maps.url_category_terms


def test_no_network_calls_during_retrieval(monkeypatch: pytest.MonkeyPatch) -> None:
    def _blocked_connect(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network access attempted during evidence-driven retrieval")

    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)
    retrieval._load_zscaler_term_maps.cache_clear()
    try:
        results = search_mitre_for_evidence(_large_upload_evidence(), top_k=5)
        assert results
        verdict_results = search_mitre_for_zscaler_verdict(
            [
                ZscalerVerdictEvidence(
                    evidence_id="ZV-1",
                    entity={"type": "user", "value": "alice", "domain": "storage.googleapis.com"},
                    url_category="File Host",
                )
            ],
            top_k=5,
        )
        assert verdict_results
    finally:
        retrieval._load_zscaler_term_maps.cache_clear()
