"""MITRE ATT&CK RAG over `data/mitre/techniques.json` — docs/07-AGENT.md `search_mitre`.

> `search_mitre` uses local embeddings over the ATT&CK corpus. A few hundred techniques fits in
> memory as a numpy matrix — no vector DB needed for this, and pgvector is already used for
> incident recurrence.

This module must work **fully offline** (CLAUDE.md: "Must work OFFLINE"). Rather than pulling a
neural embedding model at runtime (a network dependency this environment does not want to take —
see the "ZScaler proxy only" constraint noted in this milestone's brief), the "local embeddings"
are TF-IDF vectors built once, in-process, from the corpus text itself with
`sklearn.feature_extraction.text.TfidfVectorizer` (scikit-learn is already a project dependency,
`pyproject.toml`). The result is exactly what docs/07 asks for: a small numpy matrix held in
memory, cosine-similarity search over it, zero external calls, fully deterministic.

**The anti-hallucination guarantee lives here, not just in the prompt.** `search_mitre` can only
ever return technique ids that are literal keys of `_CORPUS_BY_ID` (below), and
`technique_exists`/`get_technique` are the single source of truth every other module in this
package (`tools.py`'s tool schema, `verifier.py`'s post-hoc check) uses to reject a fabricated id.
There is no code path in this package that can echo a technique id that didn't come from this
loader.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Final

import numpy as np
import numpy.typing as npt
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

__all__ = [
    "Technique",
    "all_technique_ids",
    "get_technique",
    "search_mitre",
    "technique_exists",
]

_CORPUS_PATH: Final[Path] = (
    Path(__file__).resolve().parents[2] / "data" / "mitre" / "techniques.json"
)


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    description: str
    detection: str
    score: float | None = None  # similarity score; only populated on search_mitre results


class MitreCorpusError(Exception):
    """The corpus file itself is malformed — a packaging bug, not a runtime condition. Fails
    loudly at load time (mirrors `app.response.catalog.CatalogError`'s reasoning) rather than
    surfacing as a confusing empty-results condition on the first `search_mitre` call."""


def _load_raw(path: Path) -> list[dict[str, object]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MitreCorpusError(f"could not read MITRE corpus at {path}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MitreCorpusError(f"{path} is not valid JSON: {exc}") from exc
    techniques = data.get("techniques") if isinstance(data, dict) else None
    if not isinstance(techniques, list) or not techniques:
        raise MitreCorpusError(f"{path} must contain a non-empty top-level 'techniques' list")
    return techniques


def _to_technique(raw: dict[str, object]) -> Technique:
    try:
        tid = str(raw["id"]).strip()
        name = str(raw["name"]).strip()
        tactics_raw = raw.get("tactics") or []
        if not isinstance(tactics_raw, list):
            raise MitreCorpusError(f"technique {tid!r} has a non-list 'tactics' field: {raw!r}")
        tactics = tuple(str(t) for t in tactics_raw)
        description = str(raw["description"]).strip()
        detection = str(raw["detection"]).strip()
    except KeyError as exc:
        raise MitreCorpusError(f"technique entry missing required field {exc}: {raw!r}") from exc
    if not tid or not name or not description:
        raise MitreCorpusError(f"technique entry has a blank id/name/description: {raw!r}")
    return Technique(
        id=tid, name=name, tactics=tactics, description=description, detection=detection
    )


def _corpus_text(t: Technique) -> str:
    """The text each technique is embedded from — id and name repeated so an exact-id or
    exact-name query still ranks its own technique first even though TF-IDF has no notion of
    "this token is special"."""
    return f"{t.id} {t.name} {t.name} {' '.join(t.tactics)} {t.description} {t.detection}"


@dataclass(frozen=True, slots=True)
class _Index:
    techniques: tuple[Technique, ...]
    by_id: dict[str, Technique]
    vectorizer: TfidfVectorizer
    matrix: npt.NDArray[np.float64]  # (n_techniques, n_features), TF-IDF rows, numpy — docs/07


@lru_cache(maxsize=1)
def _load_index(path: Path = _CORPUS_PATH) -> _Index:
    raw = _load_raw(path)
    techniques: list[Technique] = []
    seen: set[str] = set()
    for entry in raw:
        t = _to_technique(entry)
        if t.id in seen:
            raise MitreCorpusError(f"duplicate technique id in corpus: {t.id!r}")
        seen.add(t.id)
        techniques.append(t)

    vectorizer = TfidfVectorizer(lowercase=True, stop_words="english", ngram_range=(1, 2))
    matrix = vectorizer.fit_transform([_corpus_text(t) for t in techniques]).toarray()

    return _Index(
        techniques=tuple(techniques),
        by_id={t.id: t for t in techniques},
        vectorizer=vectorizer,
        matrix=matrix,
    )


def all_technique_ids() -> tuple[str, ...]:
    """Every technique id in the corpus, in file order. This is the enum `app.agent.tools`
    builds the `mitre_techniques[].id` tool-schema field from — the strongest form of the
    anti-hallucination guarantee: an id outside this set is not merely *invalid*, it is not a
    representable value the model's structured output can produce at all."""
    return tuple(t.id for t in _load_index().techniques)


def technique_exists(technique_id: str) -> bool:
    return technique_id in _load_index().by_id


def get_technique(technique_id: str) -> Technique | None:
    return _load_index().by_id.get(technique_id)


def search_mitre(query: str, top_k: int = 5) -> list[Technique]:
    """docs/07's RAG tool. Cosine similarity of `query`'s TF-IDF vector (using the corpus's
    already-fit vocabulary — `vectorizer.transform`, never `fit_transform`, so the query never
    perturbs the corpus's own embedding space) against every technique's row. Ties broken by
    corpus order (stable sort) so results are 100% deterministic for identical input, which
    recorded-fixture tests rely on.

    An empty or whitespace-only query, or a query that shares no vocabulary with the corpus at
    all (every row scores 0.0), returns `[]` rather than `top_k` arbitrary rows — a zero-relevance
    result set is not useful "top-k" evidence and should not be presented as if it were.
    """
    if top_k <= 0:
        return []
    index = _load_index()
    q = (query or "").strip()
    if not q:
        return []

    query_vec = index.vectorizer.transform([q]).toarray()
    sims = cosine_similarity(query_vec, index.matrix)[0]

    order = np.argsort(-sims, kind="stable")[:top_k]
    results: list[Technique] = []
    for i in order:
        score = float(sims[i])
        if score <= 0.0:
            continue
        t = index.techniques[i]
        results.append(
            Technique(
                id=t.id,
                name=t.name,
                tactics=t.tactics,
                description=t.description,
                detection=t.detection,
                score=round(score, 4),
            )
        )
    return results
