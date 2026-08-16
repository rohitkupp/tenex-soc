"""Domain entropy / DGA feature math (docs/04 §L2 "Domain entropy / DGA").

```
H        = Shannon entropy of character distribution
ngram_ll = mean log-prob under a bigram model fit on a top-domains list
score    = sigmoid(w1*H + w2*(-ngram_ll) + w3*digit_ratio + w4*max_consonant_run + w5*len_norm)
```

This module owns only the five raw features and the bigram model that produces the second one
-- never the fitted `w1..w5`. `dga_train.py` (offline, run once) fits the weights against a
labeled set and writes them to `backend/data/models/dga_weights.json`; `dga.py` (the runtime
detector) loads that artifact and applies it. Both import `feature_vector` from here, so
training and inference compute the identical five numbers from the identical formulas -- the
artifact file is the only place a train/serve mismatch could hide.

`FEATURE_NAMES` fixes the order both sides read `w1..w5` in: `(shannon_entropy, neg_ngram_ll,
digit_ratio, max_consonant_run, len_norm)`. `neg_ngram_ll` (not `ngram_ll`) is deliberate --
docs/04's formula already has the negation baked into the term (`w2*(-ngram_ll)`), so storing
the pre-negated feature means the fitted weight `w2` and every other weight are used the exact
same way: `score = sigmoid(sum(w_i * feature_i) + intercept)`, no sign flip hidden in the
scoring code that a reader of the artifact wouldn't see.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from itertools import pairwise
from typing import Any, Final

__all__ = [
    "BOUNDARY",
    "FEATURE_NAMES",
    "LEN_NORM_CAP",
    "BigramModel",
    "DGAFeatures",
    "consonant_run",
    "digit_ratio",
    "feature_vector",
    "len_norm",
    "second_level_label",
    "shannon_entropy",
    "sigmoid",
]

_CONSONANTS: Final[frozenset[str]] = frozenset("bcdfghjklmnpqrstvwxyz")
BOUNDARY: Final[str] = "^"  # start/end-of-label token, so the bigram model also learns
# which characters typically open/close a real word.
_OOV: Final[str] = "?"  # anything outside the alphabet below (unicode, punycode, ...)
_ALPHABET: Final[tuple[str, ...]] = (*"abcdefghijklmnopqrstuvwxyz0123456789-", _OOV)
_ALPHABET_SET: Final[frozenset[str]] = frozenset(_ALPHABET)
_SYMBOLS: Final[tuple[str, ...]] = (BOUNDARY, *_ALPHABET)

LEN_NORM_CAP: Final[float] = 32.0  # labels at/beyond this length saturate len_norm at 1.0

FEATURE_NAMES: Final[tuple[str, str, str, str, str]] = (
    "shannon_entropy",
    "neg_ngram_ll",
    "digit_ratio",
    "max_consonant_run",
    "len_norm",
)


# ---------------------------------------------------------------------------- labels


def second_level_label(registrable_domain: str, tld: str) -> str:
    """`"abcdefgh.top", "top"` -> `"abcdefgh"`. Falls back to the whole registrable domain for
    a direct-IP host or anything else `app.enrichment.domain_enrichment.enrich_domain` hands
    back with an empty `tld` -- there is no suffix to strip."""
    if not tld:
        return registrable_domain
    suffix = f".{tld}"
    if registrable_domain.endswith(suffix):
        return registrable_domain[: -len(suffix)]
    return registrable_domain


# ---------------------------------------------------------------------------- raw features


def shannon_entropy(label: str) -> float:
    """Bits of entropy of `label`'s own character distribution. 0.0 for an empty or
    single-repeated-character label (no uncertainty); higher for a more uniform character mix,
    which is what a randomly-generated label produces and a real word does not."""
    if not label:
        return 0.0
    n = len(label)
    counts = Counter(label)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def digit_ratio(label: str) -> float:
    if not label:
        return 0.0
    return sum(1 for ch in label if ch.isdigit()) / len(label)


def consonant_run(label: str) -> int:
    """Longest run of consecutive alphabetic consonants (case-insensitive). Digits, vowels, and
    anything else reset the run -- a DGA label frequently strings together consonant clusters no
    real word does (e.g. `"zvthfk"`)."""
    best = run = 0
    for ch in label.lower():
        if ch in _CONSONANTS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def len_norm(label: str, *, cap: float = LEN_NORM_CAP) -> float:
    if cap <= 0:
        return 0.0
    return max(0.0, min(1.0, len(label) / cap))


def sigmoid(x: float) -> float:
    """Numerically stable logistic sigmoid -- avoids `OverflowError` from `math.exp` on a large
    negative `x` by exponentiating whichever of `x`/`-x` is non-positive."""
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


@dataclass(frozen=True, slots=True)
class DGAFeatures:
    shannon_entropy: float
    neg_ngram_ll: float
    digit_ratio: float
    max_consonant_run: float
    len_norm: float

    def as_vector(self) -> tuple[float, float, float, float, float]:
        """Order matches `FEATURE_NAMES` exactly."""
        return (
            self.shannon_entropy,
            self.neg_ngram_ll,
            self.digit_ratio,
            self.max_consonant_run,
            self.len_norm,
        )


# ---------------------------------------------------------------------------- bigram model


def _normalize_char(ch: str) -> str:
    return ch if ch in _ALPHABET_SET else _OOV


def _wrap(label: str) -> str:
    return BOUNDARY + "".join(_normalize_char(c) for c in label.lower()) + BOUNDARY


class BigramModel:
    """Order-1 (bigram) character language model over `_SYMBOLS`, Laplace-smoothed, fit on
    benign second-level labels -- docs/04 says "a bigram model fit on a top-domains list"; the
    actual bundled list is `backend/datagen/data/top_domains.txt` (see `dga_train.py`, which is
    the only place this class's `.fit` is called at build time; `dga.py` only ever calls
    `.from_dict` on the persisted artifact).

    Stored as a dense `len(_SYMBOLS) x len(_SYMBOLS)` log-probability table (39x39 = 1521
    floats) rather than sparse counts -- small enough that JSON-serializing the whole table
    costs nothing, and it means `mean_log_prob` never has to re-derive Laplace smoothing for an
    unseen bigram at score time; `.fit` already baked every entry, seen or not.
    """

    __slots__ = ("_log_probs", "alpha")

    def __init__(self, *, log_probs: Mapping[str, Mapping[str, float]], alpha: float = 1.0) -> None:
        self._log_probs: dict[str, dict[str, float]] = {
            prev: dict(nexts) for prev, nexts in log_probs.items()
        }
        self.alpha = alpha

    @classmethod
    def fit(cls, labels: Iterable[str], *, alpha: float = 1.0) -> BigramModel:
        counts: dict[str, Counter[str]] = {s: Counter() for s in _SYMBOLS}
        for label in labels:
            wrapped = _wrap(label)
            for prev, nxt in pairwise(wrapped):
                counts[prev][nxt] += 1

        vocab = len(_SYMBOLS)
        log_probs: dict[str, dict[str, float]] = {}
        for prev in _SYMBOLS:
            total = sum(counts[prev].values())
            denom = total + alpha * vocab
            log_probs[prev] = {
                nxt: math.log((counts[prev][nxt] + alpha) / denom) for nxt in _SYMBOLS
            }
        return cls(log_probs=log_probs, alpha=alpha)

    def mean_log_prob(self, label: str) -> float:
        """Mean bigram log-probability of `label`, boundary tokens included. An empty label
        (after normalization) has no bigrams at all -- `0.0` is a neutral value on the log-prob
        scale's own terms only in the degenerate sense that there is nothing to be surprised
        by; callers never see this in practice since a domain with an empty label never reaches
        `events.domain` in the first place."""
        if not label:
            # Guarded before wrapping: `_wrap("")` would otherwise produce a single synthetic
            # "^" -> "^" boundary bigram, which is an artifact of wrapping, not a real character
            # transition -- there is nothing in an empty label to be surprised by.
            return 0.0
        wrapped = _wrap(label)
        pairs = list(pairwise(wrapped))
        total = sum(self._log_probs[prev][nxt] for prev, nxt in pairs)
        return total / len(pairs)

    def to_dict(self) -> dict[str, Any]:
        return {"alpha": self.alpha, "log_probs": self._log_probs}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BigramModel:
        return cls(log_probs=data["log_probs"], alpha=float(data["alpha"]))


# ---------------------------------------------------------------------------- combined vector


def feature_vector(label: str, bigram: BigramModel, *, cap: float = LEN_NORM_CAP) -> DGAFeatures:
    return DGAFeatures(
        shannon_entropy=shannon_entropy(label),
        neg_ngram_ll=-bigram.mean_log_prob(label),
        digit_ratio=digit_ratio(label),
        max_consonant_run=float(consonant_run(label)),
        len_norm=len_norm(label, cap=cap),
    )


def dot(weights: Sequence[float], features: DGAFeatures) -> float:
    """`w . feature_vector` in `FEATURE_NAMES` order -- the argument to `sigmoid` in docs/04's
    formula, minus the intercept (added by the caller, which owns the fitted artifact)."""
    return sum(w * x for w, x in zip(weights, features.as_vector(), strict=True))
