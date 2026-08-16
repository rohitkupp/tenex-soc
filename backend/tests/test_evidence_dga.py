"""Unit tests for `app.detection.evidence.dga`.

Two layers, deliberately kept separate:

1. `detect_dga`'s *mechanics* (grouping by registrable domain, threshold gating, explanation
   shape) tested against a small, hand-built `DGAArtifact` -- deterministic and independent of
   whatever numbers a real `dga_train.py` run happens to fit, so these tests do not become
   brittle every time the shipped artifact is regenerated.
2. The *shipped* artifact (`backend/data/models/dga_weights.json`, `dga_train.py`'s output) --
   loaded for real and checked against loose, direction-only bounds (a held-out accuracy floor,
   "an obviously-random label scores higher than a real brand name"), which is what actually
   matters about a fitted model without pinning exact floating-point coefficients in a test.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.detection.evidence.constants import EXTRACTOR_DGA
from app.detection.evidence.dga import (
    DGAArtifact,
    detect_dga,
    load_artifact,
    raw_evidence_dga,
    score_label,
)
from app.detection.evidence.dga_features import BigramModel
from app.detection.evidence.events_dao import EventRow

_T0 = datetime(2026, 1, 1, tzinfo=UTC)

_BENIGN_TRAINING_WORDS = (
    "google",
    "facebook",
    "microsoft",
    "github",
    "amazon",
    "apple",
    "wikipedia",
    "yahoo",
    "linkedin",
    "netflix",
)


def _toy_artifact(*, decision_threshold: float = 0.5) -> DGAArtifact:
    """Only `neg_ngram_ll` has a nonzero weight -- isolates the bigram-model half of the
    formula so these tests exercise `detect_dga`'s grouping/gating logic without depending on
    a real fit's exact coefficients for entropy/digit_ratio/consonant_run/len_norm too."""
    bigram = BigramModel.fit(_BENIGN_TRAINING_WORDS)
    return DGAArtifact(
        weights=(0.0, 1.0, 0.0, 0.0, 0.0),
        intercept=-3.0,
        decision_threshold=decision_threshold,
        bigram=bigram,
        len_norm_cap=32.0,
        metadata={},
    )


def _rows(domain: str, n: int, *, start: datetime = _T0) -> list[EventRow]:
    return [
        EventRow(
            id=i,
            ts=start + timedelta(seconds=i),
            src_ip="10.0.0.1",
            domain=domain,
            principal="victim@corp.example",
        )
        for i in range(n)
    ]


class TestMechanics:
    def test_random_looking_label_scores_higher_than_a_trained_word(self) -> None:
        artifact = _toy_artifact()
        random_score, _ = score_label("zvqxjkpl", artifact)
        trained_score, _ = score_label("google", artifact)
        assert random_score > trained_score

    def test_detect_dga_fires_on_the_random_looking_domain_only(self) -> None:
        artifact = _toy_artifact()
        rows = _rows("zvqxjkpl.top", 5) + _rows("google.com", 5)

        drafts = detect_dga(rows, artifact=artifact)

        entity_values = {d.entity_value for d in drafts}
        assert "zvqxjkpl.top" in entity_values
        assert "google.com" not in entity_values

    def test_explanation_has_the_expected_shape(self) -> None:
        artifact = _toy_artifact()
        rows = _rows("zvqxjkpl.top", 5)

        (draft,) = detect_dga(rows, artifact=artifact)

        assert draft.explanation["second_level_label"] == "zvqxjkpl"
        assert draft.explanation["tld"] == "top"
        assert draft.explanation["n_events"] == 5
        assert draft.explanation["hostnames"] == ["zvqxjkpl.top"]
        for key in (
            "shannon_entropy",
            "neg_ngram_log_likelihood",
            "digit_ratio",
            "max_consonant_run",
            "len_norm",
            "weights",
            "intercept",
            "decision_threshold",
        ):
            assert key in draft.explanation

    def test_subdomains_of_the_same_registrable_domain_are_grouped_into_one_signal(self) -> None:
        artifact = _toy_artifact()
        rows = _rows("a1.zvqxjkpl.top", 3) + _rows(
            "a2.zvqxjkpl.top", 3, start=_T0 + timedelta(hours=1)
        )

        drafts = detect_dga(rows, artifact=artifact)

        assert len(drafts) == 1
        assert drafts[0].entity_value == "zvqxjkpl.top"
        assert drafts[0].explanation["n_events"] == 6
        assert set(drafts[0].explanation["hostnames"]) == {"a1.zvqxjkpl.top", "a2.zvqxjkpl.top"}

    def test_rows_without_a_domain_are_skipped(self) -> None:
        rows = [EventRow(id=1, ts=_T0, src_ip="10.0.0.1", domain=None, principal="u")]
        assert detect_dga(rows, artifact=_toy_artifact()) == []

    def test_decision_threshold_from_the_artifact_is_respected(self) -> None:
        rows = _rows("zvqxjkpl.top", 3)
        lenient = detect_dga(rows, artifact=_toy_artifact(decision_threshold=0.01))
        strict = detect_dga(rows, artifact=_toy_artifact(decision_threshold=0.999))
        assert len(lenient) == 1
        assert strict == []

    def test_raw_evidence_dga_mirrors_the_fired_signal_with_no_baseline_lookup(self) -> None:
        artifact = _toy_artifact()
        rows = _rows("zvqxjkpl.top", 5)

        (raw,) = raw_evidence_dga(rows, artifact=artifact)

        assert raw.extractor == EXTRACTOR_DGA
        assert raw.entity == {"type": "domain", "value": "zvqxjkpl.top"}
        for key in (
            "probability",
            "shannon_entropy",
            "neg_ngram_log_likelihood",
            "digit_ratio",
            "max_consonant_run",
        ):
            assert key in raw.measurements
        assert raw.baseline_queries == ()
        assert raw.contact_query is None
        assert raw.contributing_line_numbers

    def test_raw_evidence_dga_only_covers_domains_that_also_fire_as_signals(self) -> None:
        artifact = _toy_artifact()
        rows = _rows("google.com", 5)

        assert detect_dga(rows, artifact=artifact) == []
        assert raw_evidence_dga(rows, artifact=artifact) == []


class TestShippedArtifact:
    def test_loads_and_reports_a_reasonable_held_out_accuracy(self) -> None:
        artifact = load_artifact()
        # 0.85 is a generous floor well below the ~0.99 actually observed at fit time (see the
        # M7 verification report for the exact number) -- this guards against a badly broken
        # future re-fit, not against ordinary retraining variance.
        assert artifact.metadata["held_out_accuracy"] > 0.85
        assert artifact.metadata["n_benign_total"] > 1000
        assert artifact.metadata["n_dga_total"] > 1000

    def test_ranks_an_algorithmically_generated_label_above_a_real_brand(self) -> None:
        artifact = load_artifact()
        dga_like, _ = score_label("zvqxjkplrmthbn", artifact)
        real_brand, _ = score_label("microsoft", artifact)
        assert dga_like > real_brand

    def test_detects_a_dga_style_scenario_domain_end_to_end(self) -> None:
        artifact = load_artifact()
        rows = _rows("qzxvbkpjhfml.top", 10)

        drafts = detect_dga(rows, artifact=artifact)

        assert len(drafts) == 1
        assert drafts[0].raw_score >= artifact.decision_threshold
