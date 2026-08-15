"""Token vocabulary for L4 sequence models (docs/04 §L4).

"Native discrete vocabulary — `eventType x outcome` *is* the log key. ~150 tokens. No Drain3
needed." The vocabulary here is exactly `event_key` as the Okta parser already produces it
(`app/parsers/okta.py`: `event_key = f"{event_type}:{result}"`) — this module does no template
mining of its own; it only assigns stable integer ids to whatever strings the benign training
corpus actually contains, plus a small set of model-mechanics special tokens.

Four special tokens, shared by both `markov.py` and `logbert.py` so the two models are scored
against the same symbol space:

* `<PAD>` (id 0) — fills a session out to `sessions.SESSION_MAX_LEN`. Never a real prediction
  target; both models are built to ignore it (`padding_idx` on the embedding, excluded from
  n-gram counts, excluded from masked-LM sampling).
* `<UNK>` (id 1) — an `event_key` the training corpus never saw. `Vocabulary.normalize` maps any
  such key to this token *before* either model scores it, so an eval file's rare-but-benign
  combination degrades to "one more UNK transition" rather than a `KeyError` or a silent zero
  count that would make Laplace smoothing do the wrong thing.
* `<MASK>` (id 2) — LogBERT's masked-log-key-prediction input token (`logbert.py`). Markov never
  emits it; it is reserved here anyway so both models draw ids from one shared table instead of
  disagreeing about what id 2 means.
* `<CLS>` (id 3) — two unrelated jobs, one token, deliberately: LogBERT's pooling position for the
  hypersphere objective (`logbert.py`, prepended at position 0 of every model input), and the
  Markov model's session-start context (`markov.py`: the first transition scored is
  `P(token_1 | <CLS>)`, not left undefined). Session-start is itself informative — an attack
  chain's opening move can be exactly as surprising as an internal transition — so both models
  need a concrete "what comes first" context rather than skipping position 0.

Real tokens start at id 4, ordered by descending training-corpus frequency (ties broken
lexicographically for determinism) — purely cosmetic (neither model's math depends on id order)
but it makes a saved vocabulary file readable: the common `user.session.start:SUCCESS` sits near
the top, a rare `user.mfa.factor.deactivate:SUCCESS` near the bottom.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

__all__ = [
    "CLS_ID",
    "CLS_TOKEN",
    "MASK_ID",
    "MASK_TOKEN",
    "PAD_ID",
    "PAD_TOKEN",
    "UNK_ID",
    "UNK_TOKEN",
    "Vocabulary",
    "build_vocabulary",
]

# Vocabulary mechanics tokens, not secrets -- ruff's hardcoded-password heuristic (S105) matches
# on the `*_TOKEN` naming, which is the correct NLP term here, not a credential.
PAD_TOKEN: Final[str] = "<PAD>"  # noqa: S105
UNK_TOKEN: Final[str] = "<UNK>"  # noqa: S105
MASK_TOKEN: Final[str] = "<MASK>"  # noqa: S105
CLS_TOKEN: Final[str] = "<CLS>"  # noqa: S105

PAD_ID: Final[int] = 0
UNK_ID: Final[int] = 1
MASK_ID: Final[int] = 2
CLS_ID: Final[int] = 3

# Order fixes the id assignment below -- SPECIAL_TOKENS[i] always gets id i.
SPECIAL_TOKENS: Final[tuple[str, ...]] = (PAD_TOKEN, UNK_TOKEN, MASK_TOKEN, CLS_TOKEN)


@dataclass(slots=True)
class Vocabulary:
    """`event_key <-> int` mapping plus the frequency table it was built from.

    `frequency` is carried purely for reporting (the benchmark table's "vocabulary size observed"
    line, and a human skimming the saved artifact) -- no scoring path reads it back.
    """

    token_to_id: dict[str, int]
    id_to_token: list[str]
    frequency: dict[str, int] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.id_to_token)

    def __contains__(self, event_key: str) -> bool:
        return event_key in self.token_to_id

    def normalize(self, event_key: str) -> str:
        """`event_key` if the training corpus saw it, else `<UNK>`. The string-space analogue of
        `encode` -- `markov.py` scores on normalized strings rather than ids so its explanation
        payload never has to decode anything back."""
        return event_key if event_key in self.token_to_id else UNK_TOKEN

    def encode(self, event_key: str) -> int:
        return self.token_to_id.get(event_key, UNK_ID)

    def decode(self, token_id: int) -> str:
        if 0 <= token_id < len(self.id_to_token):
            return self.id_to_token[token_id]
        return UNK_TOKEN

    def to_dict(self) -> dict[str, Any]:
        return {"id_to_token": self.id_to_token, "frequency": self.frequency}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Vocabulary:
        id_to_token = [str(t) for t in payload["id_to_token"]]
        token_to_id = {tok: i for i, tok in enumerate(id_to_token)}
        frequency = {str(k): int(v) for k, v in dict(payload.get("frequency", {})).items()}
        return cls(token_to_id=token_to_id, id_to_token=id_to_token, frequency=frequency)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> Vocabulary:
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))


def build_vocabulary(event_keys: Iterable[str]) -> Vocabulary:
    """Fit a `Vocabulary` on the observed `event_key` strings of a benign training corpus.

    Deterministic id assignment: special tokens first (fixed order above), then real tokens by
    descending frequency, lexicographic tiebreak -- two runs over the same corpus always produce
    byte-identical saved vocabularies.
    """
    counts = Counter(event_keys)
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    id_to_token = list(SPECIAL_TOKENS) + [tok for tok, _ in ordered]
    token_to_id = {tok: i for i, tok in enumerate(id_to_token)}
    return Vocabulary(token_to_id=token_to_id, id_to_token=id_to_token, frequency=dict(counts))
