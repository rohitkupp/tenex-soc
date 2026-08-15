"""Recurrence detection (docs/05 "Recurrence detection"). Replaces the heavyweight
signature/dedup service — cheap, and it directly attacks alert fatigue.

1. Build a canonical text representation of the incident: sorted technique IDs, detector keys,
   entity types, and enrichment tags. **Not** the raw entity values — structural similarity, not
   identity.
2. Embed it. Store in `incidents.embedding`.
3. Cosine search against prior incidents for the same tenant via the HNSW index.
4. If similarity >= 0.92, set `recurrence_of`/`recurrence_similarity`.
5. Recurrences skip agent triage entirely and inherit the parent's verdict (M11 wiring — this
   module only produces the link; the triage-skip itself belongs to whatever calls the agent).

## Embedding, without an external API

CLAUDE.md: "For embeddings use a local deterministic method (e.g. hashing vectorizer / TF-IDF
over the canonical text projected to 1024 dims) — do NOT call an external embedding API." This
uses `sklearn.feature_extraction.text.HashingVectorizer(n_features=1024)` — the murmurhash3-based
feature-hashing trick, seeded identically on every process (no `PYTHONHASHSEED` dependency, unlike
Python's built-in `hash()`), so the same canonical text always embeds to the same 1024-d vector on
any machine, offline, with no network call. `alternate_sign=False` keeps every coordinate
non-negative, which makes the L2-normalized vectors cosine-comparable in the way pgvector's
`vector_cosine_ops` HNSW index expects.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from sklearn.feature_extraction.text import HashingVectorizer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.incident import Incident

__all__ = [
    "EMBEDDING_DIMS",
    "RECURRENCE_SIMILARITY_THRESHOLD",
    "canonical_text",
    "cosine_search",
    "embed_text",
    "link_recurrence",
]

log = get_logger(__name__)

EMBEDDING_DIMS: Final[int] = 1024
# docs/05: "If similarity >= 0.92, set recurrence_of and recurrence_similarity."
RECURRENCE_SIMILARITY_THRESHOLD: Final[float] = 0.92

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
    """Sorted, deduplicated, category-prefixed tokens — never a raw entity value (docs/05:
    "structural similarity, not identity"). Category prefixes (`technique:`, `detector:`, ...)
    keep e.g. a detector key and a tag from colliding into the same hashed token merely because
    they happen to share a substring.
    """
    tokens: set[str] = set()
    tokens.update(f"technique:{t}" for t in technique_ids if t)
    tokens.update(f"detector:{d}" for d in detector_keys if d)
    tokens.update(f"entity:{e}" for e in entity_types if e)
    tokens.update(f"tag:{t}" for t in enrichment_tags if t)
    return " ".join(sorted(tokens))


def embed_text(text: str) -> list[float]:
    """`text` -> a deterministic, L2-normalized `EMBEDDING_DIMS`-d vector. Empty input embeds to
    the zero vector (not undefined) — `incidents.embedding` accepts it, and an all-zero vector's
    cosine similarity to anything (including itself) is a well-defined `0.0` under pgvector's
    `<=>` operator's own convention for a zero-norm operand."""
    matrix = _vectorizer.transform([text])
    return [float(v) for v in matrix.toarray()[0]]


def cosine_search(
    session: Session, embedding: Sequence[float], *, limit: int = 5
) -> list[tuple[Incident, float]]:
    """Nearest prior incidents by cosine similarity, closest first. `session` must already be
    tenant-scoped (`app.models.base.tenant_scope`/`tenant_session`) — `Incident` is
    `TenantScopedMixin`, so the guard ANDs `tenant_id` on automatically, backed by the HNSW index
    (`ix_incidents_embedding_hnsw`, docs/02) via pgvector's `vector_cosine_ops`.
    """
    distance = Incident.embedding.cosine_distance(list(embedding)).label("distance")
    stmt = (
        select(Incident, distance)
        .where(Incident.embedding.is_not(None))
        .order_by(distance)
        .limit(limit)
    )
    return [(incident, 1.0 - float(dist)) for incident, dist in session.execute(stmt).all()]


@dataclass(frozen=True, slots=True)
class RecurrenceLink:
    recurrence_of: uuid.UUID
    recurrence_similarity: float


def link_recurrence(
    session: Session,
    embedding: Sequence[float],
    *,
    exclude_incident_id: uuid.UUID | None = None,
    threshold: float = RECURRENCE_SIMILARITY_THRESHOLD,
) -> RecurrenceLink | None:
    """The closest sufficiently-similar prior incident, or `None` if nothing clears `threshold`.
    `exclude_incident_id` skips an incident's own (already-persisted) row, so re-scoring an
    existing incident never finds itself."""
    for incident, similarity in cosine_search(session, embedding, limit=5):
        if exclude_incident_id is not None and incident.id == exclude_incident_id:
            continue
        if similarity >= threshold:
            log.info(
                "recurrence.linked",
                incident_id=str(incident.id),
                similarity=round(similarity, 4),
            )
            return RecurrenceLink(recurrence_of=incident.id, recurrence_similarity=similarity)
    return None
