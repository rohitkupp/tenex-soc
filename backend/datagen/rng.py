"""Seeded randomness discipline for the generator.

Every draw in `datagen` comes from here. Two properties the eval harness depends on:

1. **Sub-streams derive from a string key, never from draw order.** Order-derived streams make
   the benign corpus shift when a scenario is added or a loop is reordered — the exact
   reproducibility bug this milestone exists to prevent.
2. **Keys hash with blake2b, not `hash()`.** CPython salts string hashing per process
   (PYTHONHASHSEED), so `hash()` would produce a different corpus on every run and machine.

Consequence worth stating explicitly: `SeededRandom(42).substream("user:jdoe")` is the same
stream regardless of what else was generated first, so two runs that differ only in which
scenarios were injected still share a byte-identical benign corpus.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING, TypeVar

import numpy as np

if TYPE_CHECKING:
    from collections.abc import Iterator

T = TypeVar("T")

__all__ = ["SeededRandom", "derive_seed", "stable_hash"]

_SEED_BYTES = 8
_SEED_MASK = (1 << (_SEED_BYTES * 8)) - 1


def stable_hash(text: str) -> int:
    """Process-independent 64-bit hash. `hash()` is salted per process and unusable here."""
    return int.from_bytes(hashlib.blake2b(text.encode("utf-8"), digest_size=_SEED_BYTES).digest())


def derive_seed(root_seed: int, *keys: str) -> int:
    """Seed for a named sub-stream. Pure function of (root seed, key path)."""
    return stable_hash("|".join((str(int(root_seed) & _SEED_MASK), *keys)))


class SeededRandom:
    """A named point in a seed tree, exposing both `random.Random` and a numpy `Generator`.

    Both engines are lazy: constructing a sub-stream for an entity that never draws costs
    nothing, which matters when the org has thousands of keyed streams.
    """

    __slots__ = ("_children", "_np", "_path", "_py", "_seed")

    def __init__(self, seed: int, path: tuple[str, ...] = ()) -> None:
        self._seed = int(seed) & _SEED_MASK
        self._path = path
        self._py: random.Random | None = None
        self._np: np.random.Generator | None = None
        self._children: dict[str, SeededRandom] = {}

    # ---------------------------------------------------------------- identity

    @property
    def seed(self) -> int:
        return self._seed

    @property
    def path(self) -> tuple[str, ...]:
        """Key path from the root, e.g. `("benign", "user:jdoe")`."""
        return self._path

    def __repr__(self) -> str:
        return f"SeededRandom(seed={self._seed}, path={'/'.join(self._path) or '<root>'})"

    # ---------------------------------------------------------------- engines

    @property
    def py(self) -> random.Random:
        """Python engine. Use for choices over Python objects."""
        if self._py is None:
            self._py = random.Random(self._seed)
        return self._py

    @property
    def np(self) -> np.random.Generator:
        """Numpy engine. Use for vectorised draws (timestamps, byte counts, batches)."""
        if self._np is None:
            self._np = np.random.default_rng(self._seed)
        return self._np

    # ---------------------------------------------------------------- streams

    def substream(self, key: str) -> SeededRandom:
        """Child stream for `key`. Cached, so an entity keeps one continuing stream."""
        child = self._children.get(key)
        if child is None:
            path = (*self._path, key)
            child = SeededRandom(derive_seed(self._seed, *path), path)
            self._children[key] = child
        return child

    def for_entity(self, kind: str, value: str) -> SeededRandom:
        """Sub-stream for an entity, e.g. `for_entity("user", "jdoe@corp.example")`."""
        return self.substream(f"{kind}:{value}")

    def fresh(self, key: str) -> SeededRandom:
        """Uncached child. Use when a caller needs a stream that ignores prior draws."""
        path = (*self._path, key)
        return SeededRandom(derive_seed(self._seed, *path), path)

    # ---------------------------------------------------------------- scalars

    def randint(self, low: int, high: int) -> int:
        """Inclusive on both ends, matching `random.randint`."""
        return self.py.randint(low, high)

    def uniform(self, low: float, high: float) -> float:
        return self.py.uniform(low, high)

    def normal(self, mean: float, sigma: float) -> float:
        return float(self.np.normal(mean, sigma))

    def lognormal(self, mean_log: float, sigma_log: float) -> float:
        return float(self.np.lognormal(mean_log, sigma_log))

    def exponential(self, scale: float) -> float:
        return float(self.np.exponential(scale))

    def poisson(self, lam: float) -> int:
        return int(self.np.poisson(lam))

    def pareto(self, shape: float, scale: float = 1.0) -> float:
        return float(scale * (1.0 + self.np.pareto(shape)))

    def chance(self, probability: float) -> bool:
        return self.py.random() < probability

    def random(self) -> float:
        """Uniform in [0, 1)."""
        return self.py.random()

    def jitter(self, value: float, pct: float) -> float:
        """Multiplicative jitter, e.g. beacon interval jitter of 12%."""
        return value * self.uniform(1.0 - pct, 1.0 + pct)

    def clamped_normal(self, mean: float, sigma: float, low: float, high: float) -> float:
        return min(max(self.normal(mean, sigma), low), high)

    # ---------------------------------------------------------------- sequences

    def choice(self, seq: Sequence[T]) -> T:
        return self.py.choice(seq)

    def choices(self, seq: Sequence[T], k: int, weights: Sequence[float] | None = None) -> list[T]:
        """With replacement."""
        return self.py.choices(seq, weights=weights, k=k)

    def weighted_choice(self, seq: Sequence[T], weights: Sequence[float]) -> T:
        return self.py.choices(seq, weights=weights, k=1)[0]

    def sample(self, seq: Sequence[T], k: int) -> list[T]:
        """Without replacement. `k` is clamped to `len(seq)`."""
        return self.py.sample(seq, min(k, len(seq)))

    def shuffled(self, seq: Iterable[T]) -> list[T]:
        """Copy-and-shuffle; never shuffles a caller's list in place."""
        items = list(seq)
        self.py.shuffle(items)
        return items

    def subset(self, seq: Sequence[T], probability: float) -> list[T]:
        """Independent Bernoulli filter, preserving input order."""
        return [item for item in seq if self.chance(probability)]

    # ---------------------------------------------------------------- tokens

    def hex_token(self, n_bytes: int = 8) -> str:
        return self.py.getrandbits(n_bytes * 8).to_bytes(n_bytes).hex()

    def uuid(self) -> str:
        """UUID4-shaped identifier. Deterministic, so it is not a real UUID4."""
        raw = self.py.getrandbits(128).to_bytes(16).hex()
        return f"{raw[:8]}-{raw[8:12]}-4{raw[13:16]}-a{raw[17:20]}-{raw[20:32]}"

    def ip_in(self, prefix: str) -> str:
        """Host address inside a /24 given as its first three octets, e.g. `"203.0.113"`."""
        return f"{prefix}.{self.randint(1, 254)}"

    # ---------------------------------------------------------------- batches

    def epoch_jitter(self, size: int, spread_s: float) -> np.ndarray:
        return self.np.uniform(-spread_s, spread_s, size=size)

    def iter_substreams(self, keys: Iterable[str]) -> Iterator[SeededRandom]:
        """Sub-streams in the caller's key order; the order does not affect their contents."""
        for key in keys:
            yield self.substream(key)
