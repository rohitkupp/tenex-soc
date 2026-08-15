"""Consumer 3 — Agent few-shot memory (docs/08 Part 2, §3). No retraining.

docs/08 calls this "the highest value per hour of implementation": on a new incident, retrieve
the `k=3` most similar past incidents *with analyst-confirmed dispositions* via the existing
pgvector HNSW index (`ix_incidents_embedding_hnsw`, `app.models.incident.Incident.embedding`),
and expose them for inclusion in the agent's context as `<prior_analyst_decisions>`. RAG over the
feedback store, reusing infrastructure already built for recurrence detection (`incidents.
embedding`, docs/05) — no training, immediate effect.

## What this module owns, and what it hands off

This builds the retrieval and the rendered context block. The agent worker itself is M11
(`app/agent/`), concurrent with this milestone and not yet built (the package is an empty stub
in this checkout) — it is the one that decides *where* in a prompt this block goes and *when* to
call `retrieve_prior_analyst_decisions`. Two things the agent integration must get right, noted
here because they are easy to get wrong and this module cannot enforce them from the outside:

1. **Never in the system prompt.** CLAUDE.md rule 3: "Log content is untrusted input... Never put
   it in a system prompt. Always delimit and mark as data." An analyst's free-text `note`/
   `dismissal_reason` is lower-risk than a raw log line (it is written by a trusted internal user,
   not attacker-controlled telemetry) but it is still external text reaching the prompt, and the
   XML-ish `<prior_analyst_decisions>` wrapper this module renders exists specifically so the
   agent can delimit it as data in the same way `docs/06` requires for cited evidence.
2. **Pseudonymize before it leaves the tenant boundary** (CLAUDE.md rule 4) if a `note` ever
   contains something identifiable an analyst typed in free text — this module does not run
   `app/privacy`'s redactor over `note`/`dismissal_reason` itself (out of this milestone's
   ownership, and the M11 agent path already has to pseudonymize everything else it sends), so
   the agent integration is the enforcement point, not an assumption this module gets to make
   silently.

## Function signatures (state these exactly — the M11 integration point)

```python
def retrieve_prior_analyst_decisions(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    query_embedding: Sequence[float],
    k: int = 3,
    exclude_incident_id: uuid.UUID | None = None,
) -> list[PriorAnalystDecision]: ...

def get_prior_analyst_decisions_for_incident(
    session: Session, *, tenant_id: uuid.UUID, incident_id: uuid.UUID, k: int = 3
) -> list[PriorAnalystDecision]: ...

def render_prior_analyst_decisions_block(decisions: list[PriorAnalystDecision]) -> str: ...
```

The first is the primitive (any 1024-dim query vector); the second is the convenience form the
agent worker will actually call once per incident (looks up the incident's own `embedding` and
excludes it from its own results). Both only return incidents that have at least one
`analyst_feedback` row — "analyst-confirmed dispositions" per docs/08, not just any embedded
incident.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import exists, select
from sqlalchemy.orm import Session

from app.models.analyst_feedback import AnalystFeedback
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.triage_verdict import TriageVerdict

__all__ = [
    "DEFAULT_K",
    "PriorAnalystDecision",
    "get_prior_analyst_decisions_for_incident",
    "render_prior_analyst_decisions_block",
    "retrieve_prior_analyst_decisions",
]

DEFAULT_K = 3


@dataclass(frozen=True, slots=True)
class PriorAnalystDecision:
    incident_id: uuid.UUID
    title: str
    similarity: float  # cosine similarity in [-1, 1] (typically [0, 1] for these embeddings)
    disposition: str
    reason: str
    mitre_techniques: tuple[str, ...]
    created_at: datetime


def _reason_text(feedback: AnalystFeedback) -> str:
    """docs/08's own worked example uses the dismissal reason
    ('"Sanctioned nightly backup to corporate S3 bucket."'). `note` is the more general free-text
    field (docs/02); prefer it when present, fall back to `dismissal_reason`, and never surface an
    empty string as if it were a real reason."""
    return (feedback.note or feedback.dismissal_reason or "").strip()


def retrieve_prior_analyst_decisions(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    query_embedding: Sequence[float],
    k: int = DEFAULT_K,
    exclude_incident_id: uuid.UUID | None = None,
) -> list[PriorAnalystDecision]:
    """The `k` nearest incidents to `query_embedding` (pgvector HNSW cosine search on
    `incidents.embedding`) that carry at least one `analyst_feedback` row, nearest first.

    An incident can receive more than one feedback event (e.g. a later correction); the most
    recent one is treated as the incident's current disposition/reason, matching how `app.
    learning.feedback_data.labeled_examples` reads the same history for calibration and weight
    tuning.
    """
    with tenant_scope(session, tenant_id):
        distance = Incident.embedding.cosine_distance(list(query_embedding))
        has_feedback = exists().where(AnalystFeedback.verdict_id == TriageVerdict.id)

        stmt = (
            select(Incident, TriageVerdict, distance.label("distance"))
            .join(TriageVerdict, TriageVerdict.incident_id == Incident.id)
            .where(Incident.embedding.is_not(None))
            .where(has_feedback)
        )
        if exclude_incident_id is not None:
            stmt = stmt.where(Incident.id != exclude_incident_id)
        stmt = stmt.order_by(distance.asc()).limit(k)

        rows = session.execute(stmt).all()

        decisions: list[PriorAnalystDecision] = []
        for incident, verdict, distance_value in rows:
            feedback = session.execute(
                select(AnalystFeedback)
                .where(AnalystFeedback.verdict_id == verdict.id)
                .order_by(AnalystFeedback.created_at.desc())
                .limit(1)
            ).scalar_one()

            disposition = feedback.corrected_disposition or verdict.disposition
            techniques = (
                tuple(verdict.mitre_techniques)
                if isinstance(verdict.mitre_techniques, list)
                else ()
            )
            decisions.append(
                PriorAnalystDecision(
                    incident_id=incident.id,
                    title=incident.title,
                    similarity=1.0 - float(distance_value),
                    disposition=disposition,
                    reason=_reason_text(feedback),
                    mitre_techniques=techniques,
                    created_at=feedback.created_at,
                )
            )
    return decisions


def get_prior_analyst_decisions_for_incident(
    session: Session, *, tenant_id: uuid.UUID, incident_id: uuid.UUID, k: int = DEFAULT_K
) -> list[PriorAnalystDecision]:
    """Convenience form for the agent worker: look up `incident_id`'s own embedding, then
    retrieve its `k` nearest analyst-confirmed neighbors (excluding itself). Returns `[]`,
    not an error, if the incident has no embedding yet (correlation/fusion, M10, hasn't run) —
    few-shot memory degrading to "no examples" is the correct behavior for an incident too new
    to have one, not a failure worth raising past the agent."""
    with tenant_scope(session, tenant_id):
        incident = session.get(Incident, incident_id)
    if incident is None or incident.embedding is None:
        return []
    return retrieve_prior_analyst_decisions(
        session,
        tenant_id=tenant_id,
        query_embedding=incident.embedding,
        k=k,
        exclude_incident_id=incident_id,
    )


def render_prior_analyst_decisions_block(decisions: list[PriorAnalystDecision]) -> str:
    """Renders docs/08's exact worked format:

    ```
    <prior_analyst_decisions>
    Similar incident (cosine 0.94), analyst disposition: false_positive
    Reason: "Sanctioned nightly backup to corporate S3 bucket."
    </prior_analyst_decisions>
    ```

    One `Similar incident (...) / Reason: "..."` pair per decision, in the order given (nearest
    first). Returns the wrapper tags even for an empty list, so the agent's prompt template can
    always splice this in unconditionally rather than branching on "were there any."
    """
    lines = ["<prior_analyst_decisions>"]
    for d in decisions:
        lines.append(
            f"Similar incident (cosine {d.similarity:.2f}), analyst disposition: {d.disposition}"
        )
        lines.append(f'Reason: "{d.reason}"' if d.reason else "Reason: (none recorded)")
    lines.append("</prior_analyst_decisions>")
    return "\n".join(lines)
