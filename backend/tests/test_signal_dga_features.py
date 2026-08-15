"""Unit tests for `app.detection.signal.dga_features` -- the pure feature math shared by
`dga_train.py` (fits) and `dga.py` (scores). No filesystem, no DB, no fitted artifact: every
test here constructs its own tiny `BigramModel` or checks a formula directly.
"""

from __future__ import annotations

import math

import pytest

from app.detection.signal.dga_features import (
    BigramModel,
    consonant_run,
    digit_ratio,
    feature_vector,
    len_norm,
    second_level_label,
    shannon_entropy,
    sigmoid,
)


def test_shannon_entropy_of_empty_label_is_zero() -> None:
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_of_single_repeated_character_is_zero() -> None:
    assert shannon_entropy("aaaaaa") == 0.0


def test_shannon_entropy_of_uniform_alphabet_is_maximal() -> None:
    # 4 distinct, equally-frequent characters -> exactly 2 bits.
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_shannon_entropy_is_higher_for_more_uniform_strings() -> None:
    assert shannon_entropy("zvthfkqx") > shannon_entropy("googleplex")


def test_digit_ratio_bounds() -> None:
    assert digit_ratio("") == 0.0
    assert digit_ratio("abcdef") == 0.0
    assert digit_ratio("123456") == 1.0
    assert digit_ratio("abc123") == pytest.approx(0.5)


def test_consonant_run_finds_the_longest_run() -> None:
    assert consonant_run("google") == 2  # "gl" is the longest consonant run in "g-o-o-g-l-e"
    assert consonant_run("zvthfkqx") == 8  # all consonants
    assert consonant_run("aeiou") == 0  # all vowels
    assert consonant_run("") == 0


def test_consonant_run_ignores_digits_and_hyphens() -> None:
    # Digits/hyphens reset the run rather than extending it.
    assert consonant_run("bcd123fgh") == 3


def test_len_norm_saturates_at_one() -> None:
    assert len_norm("a" * 100, cap=32.0) == 1.0
    assert len_norm("", cap=32.0) == 0.0
    assert len_norm("a" * 16, cap=32.0) == pytest.approx(0.5)


def test_second_level_label_strips_the_suffix() -> None:
    assert second_level_label("abcdefgh.top", "top") == "abcdefgh"
    assert second_level_label("example.co.uk", "co.uk") == "example"


def test_second_level_label_with_no_tld_returns_input_unchanged() -> None:
    assert second_level_label("192.0.2.1", "") == "192.0.2.1"


def test_sigmoid_matches_reference_at_zero_and_extremes() -> None:
    assert sigmoid(0.0) == pytest.approx(0.5)
    assert sigmoid(100.0) == pytest.approx(1.0)
    assert sigmoid(-100.0) == pytest.approx(0.0)


def test_sigmoid_does_not_overflow_on_large_negative_input() -> None:
    # A naive `1 / (1 + exp(-x))` raises OverflowError for x this negative.
    assert sigmoid(-800.0) == 0.0


class TestBigramModel:
    def test_fitting_on_repeated_labels_assigns_high_probability_to_seen_bigrams(self) -> None:
        model = BigramModel.fit(["google", "google", "google"])
        # "go" is a bigram the model has actually seen many times; a bigram it has never seen
        # anywhere ("qz") should score a lower (more negative) log-probability.
        assert model.mean_log_prob("google") > model.mean_log_prob("qzqzqz")

    def test_benign_looking_label_scores_higher_than_random_looking_label(self) -> None:
        benign = ["google", "facebook", "microsoft", "github", "wikipedia", "amazon", "apple"]
        model = BigramModel.fit(benign)
        assert model.mean_log_prob("microsoft") > model.mean_log_prob("zqxvbkpj")

    def test_empty_label_has_zero_mean_log_prob(self) -> None:
        model = BigramModel.fit(["google", "facebook"])
        assert model.mean_log_prob("") == 0.0

    def test_round_trips_through_to_dict_from_dict(self) -> None:
        model = BigramModel.fit(["google", "facebook", "microsoft"], alpha=0.5)
        restored = BigramModel.from_dict(model.to_dict())
        for label in ("google", "zzqx123", ""):
            assert restored.mean_log_prob(label) == pytest.approx(model.mean_log_prob(label))
        assert restored.alpha == model.alpha

    def test_unseen_prev_character_falls_back_to_uniform_smoothing(self) -> None:
        # A model that has only ever seen lowercase letters must still return a finite (not
        # KeyError, not -inf) log-probability for a bigram involving a digit.
        model = BigramModel.fit(["google", "facebook"])
        value = model.mean_log_prob("42")
        assert math.isfinite(value)


def test_feature_vector_matches_the_documented_five_features() -> None:
    model = BigramModel.fit(["google", "facebook", "microsoft", "github"])
    features = feature_vector("zqxvbkpjhf", model)
    assert features.shannon_entropy == pytest.approx(shannon_entropy("zqxvbkpjhf"))
    assert features.digit_ratio == 0.0
    assert features.max_consonant_run == float(consonant_run("zqxvbkpjhf"))
    assert features.len_norm == pytest.approx(len_norm("zqxvbkpjhf"))
    assert features.neg_ngram_ll == pytest.approx(-model.mean_log_prob("zqxvbkpjhf"))
