"""Markov / n-gram baseline (docs/04 §L4 "Markov / n-gram baseline").

"Fit bigram and trigram transition probabilities on benign sessions. Score = mean negative
log-probability of observed transitions. Fully interpretable: 'P(user.mfa.factor.deactivate |
user.session.start from new geo) = 0.0003'. This is what commercial UEBA ships for pattern
anomalies. It is a serious baseline, not a strawman."

## The interpolation, spelled out

Both an order-2 (bigram) and an order-3 (trigram) model are fit, and every scored transition uses
both -- not "bigram OR trigram," an interpolation between them, because a pure trigram model is
useless exactly where it matters most: a rare-but-legitimate 3-token context that the benign
corpus saw once or twice gets a wildly noisy trigram estimate, while an attack's own novel context
(by construction, since the ordering *is* the attack) gets one that is uninformatively flat. The
standard fix -- and what is implemented here -- is context-count-weighted linear interpolation
(a simplified Jelinek-Mercer / Katz-style backoff):

```
P(next | ctx2, ctx1) = lambda * P3(next | ctx2, ctx1) + (1 - lambda) * P2(next | ctx1)
lambda = count(ctx2, ctx1) / (count(ctx2, ctx1) + backoff_k)
```

`lambda -> 0` (trust the bigram) when the trigram context was rarely or never seen in training;
`lambda -> 1` (trust the trigram) when it was seen often. `P2` and `P3` are each Lidstone
(additive-`alpha`)-smoothed over the vocabulary, so no transition -- however novel -- ever gets
exactly zero probability (a hard zero would make `-log(p)` infinite and one novel event would
saturate the whole session's score, discarding every other transition's information).

Every session is scored starting from `<CLS>` as the initial two-token context (`vocabulary.py`),
so the very first event of a session is itself a scored transition, `P(token_1 | <CLS>, <CLS>)` /
`P(token_1 | <CLS>)` -- "what does this principal normally do first" is exactly the kind of
question a Markov baseline should be able to answer, and scenario 6's push-bombing burst in
particular can open on an atypical first move.

`score_session`'s `session_score` is the mean of `-log(P(...))` over every transition in the
session (docs/04's literal formula); `explanation.surprising_transitions` is the
`_TOP_SURPRISING` lowest-probability transitions, each carrying the exact `{from, to, log_prob}`
shape docs/04 specifies for both L4 models.
"""

from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from app.detection.sequence.sessions import Session
from app.detection.sequence.vocabulary import CLS_TOKEN, Vocabulary

__all__ = [
    "SEQUENCE_MARKOV",
    "MarkovModel",
    "SessionScore",
    "fit",
]

# Matches `datagen.types.SEQUENCE_MARKOV`'s string value by convention, not by import -- detection
# code does not depend on the synthetic-data generator (see `app/detection/features.py`'s module
# docstring for the same rule stated for the L3 boundary).
SEQUENCE_MARKOV: Final[str] = "sequence.markov"

_DEFAULT_ALPHA: Final[float] = 0.5  # Lidstone smoothing constant
_DEFAULT_BACKOFF_K: Final[float] = 5.0  # trigram/bigram interpolation strength, docstring above
_TOP_SURPRISING: Final[int] = 5
_BACKEND_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
DEFAULT_ARTIFACT_PATH: Final[Path] = _BACKEND_ROOT / "data" / "models" / "seq_markov.json"


@dataclass(slots=True)
class SessionScore:
    session_score: float
    explanation: dict[str, Any]


@dataclass(slots=True)
class MarkovModel:
    vocab: Vocabulary
    bigram_counts: dict[str, Counter[str]]
    trigram_counts: dict[tuple[str, str], Counter[str]]
    alpha: float = _DEFAULT_ALPHA
    backoff_k: float = _DEFAULT_BACKOFF_K
    # Number of distinct symbols the smoothing denominator normalizes over -- every real token
    # plus <UNK> and <CLS> (a legitimate prediction target, e.g. a session that opens and closes
    # inside one turn) but not <PAD>/<MASK>, which are never a true "next token".
    _emission_vocab_size: int = field(default=0)

    def __post_init__(self) -> None:
        if self._emission_vocab_size == 0:
            self._emission_vocab_size = len(self.vocab) - 2  # exclude <PAD>, <MASK>

    # ------------------------------------------------------------------ probabilities

    def _bigram_prob(self, prev: str, nxt: str) -> float:
        counter = self.bigram_counts.get(prev)
        total = sum(counter.values()) if counter else 0
        count = counter[nxt] if counter else 0
        v = self._emission_vocab_size
        return (count + self.alpha) / (total + self.alpha * v)

    def _trigram_prob(self, ctx2: str, ctx1: str, nxt: str) -> tuple[float, int]:
        counter = self.trigram_counts.get((ctx2, ctx1))
        total = sum(counter.values()) if counter else 0
        count = counter[nxt] if counter else 0
        v = self._emission_vocab_size
        p3 = (count + self.alpha) / (total + self.alpha * v)
        return p3, total

    def transition_prob(self, ctx2: str, ctx1: str, nxt: str) -> float:
        """The interpolated `P(nxt | ctx2, ctx1)` described in the module docstring."""
        p2 = self._bigram_prob(ctx1, nxt)
        p3, ctx_total = self._trigram_prob(ctx2, ctx1, nxt)
        lam = ctx_total / (ctx_total + self.backoff_k)
        return lam * p3 + (1.0 - lam) * p2

    # ------------------------------------------------------------------ scoring

    def score_session(self, session: Session) -> SessionScore:
        toks = [self.vocab.normalize(k) for k in session.token_keys]
        if not toks:
            explanation: dict[str, Any] = {
                "surprising_transitions": [],
                "session_score": 0.0,
                "n_transitions": 0,
                "principal": session.principal,
            }
            return SessionScore(session_score=0.0, explanation=explanation)

        ctx2, ctx1 = CLS_TOKEN, CLS_TOKEN
        transitions: list[dict[str, Any]] = []
        for tok, event in zip(toks, session.events, strict=True):
            prob = self.transition_prob(ctx2, ctx1, tok)
            log_prob = math.log(prob)
            transitions.append(
                {
                    "from": ctx1,
                    "to": tok,
                    "log_prob": log_prob,
                    "prob": prob,
                    "line_no": event.line_no,
                    "ts": event.ts.isoformat(),
                }
            )
            ctx2, ctx1 = ctx1, tok

        mean_nll = -sum(t["log_prob"] for t in transitions) / len(transitions)
        surprising = sorted(transitions, key=lambda t: t["log_prob"])[:_TOP_SURPRISING]
        explanation = {
            "surprising_transitions": [
                {"from": t["from"], "to": t["to"], "log_prob": t["log_prob"]} for t in surprising
            ],
            "session_score": mean_nll,
            "n_transitions": len(transitions),
            "principal": session.principal,
        }
        return SessionScore(session_score=mean_nll, explanation=explanation)

    # ------------------------------------------------------------------ persistence

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "alpha": self.alpha,
            "backoff_k": self.backoff_k,
            "vocab": self.vocab.to_dict(),
            "bigram_counts": {ctx: dict(counter) for ctx, counter in self.bigram_counts.items()},
            "trigram_counts": [
                {"ctx2": ctx2, "ctx1": ctx1, "next": nxt, "count": count}
                for (ctx2, ctx1), counter in self.trigram_counts.items()
                for nxt, count in counter.items()
            ],
        }

    def save(self, path: Path = DEFAULT_ARTIFACT_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> MarkovModel:
        vocab = Vocabulary.from_dict(payload["vocab"])
        bigram_counts: dict[str, Counter[str]] = {
            ctx: Counter({k: int(v) for k, v in counts.items()})
            for ctx, counts in payload["bigram_counts"].items()
        }
        trigram_counts: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        for row in payload["trigram_counts"]:
            trigram_counts[(row["ctx2"], row["ctx1"])][row["next"]] = int(row["count"])
        return cls(
            vocab=vocab,
            bigram_counts=bigram_counts,
            trigram_counts=dict(trigram_counts),
            alpha=float(payload["alpha"]),
            backoff_k=float(payload["backoff_k"]),
        )

    @classmethod
    def load(cls, path: Path = DEFAULT_ARTIFACT_PATH) -> MarkovModel:
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))


def fit(
    sessions: Iterable[Session],
    vocab: Vocabulary,
    *,
    alpha: float = _DEFAULT_ALPHA,
    backoff_k: float = _DEFAULT_BACKOFF_K,
) -> MarkovModel:
    """Fit bigram and trigram transition counts on `sessions` (benign only, per docs/04)."""
    bigram_counts: dict[str, Counter[str]] = defaultdict(Counter)
    trigram_counts: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)

    for session in sessions:
        toks = [vocab.normalize(k) for k in session.token_keys]
        if not toks:
            continue
        ctx2, ctx1 = CLS_TOKEN, CLS_TOKEN
        for tok in toks:
            bigram_counts[ctx1][tok] += 1
            trigram_counts[(ctx2, ctx1)][tok] += 1
            ctx2, ctx1 = ctx1, tok

    return MarkovModel(
        vocab=vocab,
        bigram_counts=dict(bigram_counts),
        trigram_counts=dict(trigram_counts),
        alpha=alpha,
        backoff_k=backoff_k,
    )
