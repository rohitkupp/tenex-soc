"""Deterministic text embedding for `tier2_signatures.embedding`.

These two primitives moved here out of the deleted `app.graph.recurrence`. That module did two
separable things: it embedded an incident's structural signature, and it cosine-searched prior
incidents to link duplicates. The *duplicate checking* is what was removed — `cosine_search`,
`link_recurrence`, the 0.92 threshold, `incidents.embedding`, `incidents.recurrence_of`, and the
triage-skip that let a recurrence inherit its parent's verdict are all gone.

Embedding itself is not duplicate detection, and Tier 2 is a different feature that needs it:
`app.tier2.signature_sync` writes a 1024-d vector per signature so cross-tenant overlap is
computable. It used to borrow `incidents.embedding`; with that column dropped it computes its own
here, from its own canonical text.

CLAUDE.md: "For embeddings use a local deterministic method ... do NOT call an external embedding
API." `HashingVectorizer` is murmurhash3-based feature hashing, seeded identically in every
process (no `PYTHONHASHSEED` dependency, unlike Python's built-in `hash()`), so the same text
always embeds to the same vector on any machine, offline. `alternate_sign=False` keeps every
coordinate non-negative, which is what makes the L2-normalized vectors cosine-comparable the way
pgvector's `vector_cosine_ops` expects.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from sklearn.feature_extraction.text import HashingVectorizer

__all__ = ["EMBEDDING_DIMS", "canonical_text", "embed_text"]

EMBEDDING_DIMS: Final[int] = 1024

_vectorizer: Final[HashingVectorizer] = HashingVectorizer(
    n_features=EMBEDDING_DIMS,
    alternate_sign=False,
    norm="l2",
    token_pattern=r"(?u)\S+",  # noqa: S106 -- a regex token pattern, not a credential
)


def canonical_text(
    *,
    technique_ids: Sequence[str | None],
    detector_keys: Sequence[str],
    entity_types: Sequence[str],
    enrichment_tags: Sequence[str],
) -> str:
    """Sorted, deduplicated, category-prefixed tokens — never a raw entity value (structural
    similarity, not identity). The category prefixes stop a detector key and a tag colliding into
    the same hashed token merely because they share a substring."""
    tokens: set[str] = set()
    tokens.update(f"technique:{t}" for t in technique_ids if t)
    tokens.update(f"detector:{d}" for d in detector_keys if d)
    tokens.update(f"entity:{e}" for e in entity_types if e)
    tokens.update(f"tag:{t}" for t in enrichment_tags if t)
    return " ".join(sorted(tokens))


def embed_text(text: str) -> list[float]:
    """`text` -> a deterministic, L2-normalized `EMBEDDING_DIMS`-d vector. Empty input embeds to
    the zero vector rather than being undefined."""
    return [float(v) for v in _vectorizer.transform([text]).toarray()[0]]
