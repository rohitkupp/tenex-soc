"""Pydantic v2 schemas for the incident *read* surface — docs/09-API-CONTRACT.md.

`app.schemas.agent` owns the `triage_verdicts` row shape and nothing else, by its own
docstring. This module owns everything else docs/09 folds into the case file:

    GET /api/analyses/{id}/incidents   the queue (list items + keyset cursor)
    GET /api/incidents/{id}            "signals with explanations, entities, ..., verdict"
    GET /api/incidents/{id}/graph      `{nodes: [], edges: []}`
    GET /api/incidents/{id}/timeline   docs/05's deterministic phase list

Field names and nullability here are not freshly invented: they match
`frontend/lib/api/types.ts`'s `IncidentListItem` / `IncidentDetail` / `IncidentGraph` /
`TimelinePhaseOut` exactly, which were themselves derived from docs/09 + docs/02 + docs/05.
The frontend was written against a backend that did not exist yet; making the server match the
client (rather than the reverse) keeps docs/09 as the single arbiter and means no already-shipped
component has to change.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.schemas.agent import TriageVerdictResponse


class SignalOut(BaseModel):
    """docs/02's `signals` table. `explanation` is the detector's own payload, passed through
    verbatim — the UI dispatches on `detector_key` to render it (docs/13 M15: "No raw JSON
    rendered anywhere in the UI"), so narrowing it to a union here would only make the server
    the second place that has to learn about every new detector."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    detector_key: str
    detector_layer: str
    raw_score: float
    confidence: float
    entity_type: str
    entity_value: str
    window_start: datetime | None
    window_end: datetime | None
    mitre_technique: str | None
    evidence_event_ids: list[int]
    explanation: dict[str, Any]
    created_at: datetime


class EntityOut(BaseModel):
    """docs/02's `entities` table."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    type: str
    value: str
    first_seen: datetime | None
    last_seen: datetime | None
    event_count: int
    risk_score: float
    attrs: dict[str, Any]


class IncidentListItem(BaseModel):
    """The queue row. Deliberately flat and cheap: docs/09 wants a list endpoint an analyst can
    page through, so the expensive parts of the case file (signal explanations, entity rows, the
    graph) are *not* here — `entity_count`/`signal_count` are array lengths, not joins.

    `disposition`, `citation_valid`, and `mitre_techniques` come from the incident's latest
    verdict and are `null`/`[]` when it has not been triaged (docs/07 triages only the top
    `MAX_TRIAGE_INCIDENTS`, so an untriaged incident is the normal case, not an error).
    """

    id: uuid.UUID
    title: str
    severity: str
    fused_score: float
    disposition: str | None
    citation_valid: bool | None
    mitre_techniques: list[str]
    entity_count: int
    signal_count: int
    recurrence_of: uuid.UUID | None
    created_at: datetime
    needs_attention: bool


class IncidentsListResponse(BaseModel):
    items: list[IncidentListItem]
    next_cursor: str | None


class IncidentDetail(BaseModel):
    """docs/09: "Full detail: signals with explanations, entities, timeline, verdict, plan."

    Timeline and plan are their own routes (`/timeline`; `GET /api/incidents/{id}/plan` already
    exists in `app.api.plans`) — splitting them keeps this response bounded and lets the case
    file's sections stream in independently, which is what `frontend/app/(dashboard)/analyses/
    [id]/incidents/[iid]` already does.

    `verdict` is `null` for an untriaged incident. A recurrence inherits its parent's verdict
    (docs/05), so it can be non-null even for an incident the agent never ran on directly.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    analysis_id: uuid.UUID
    title: str
    severity: str
    fused_score: float
    status: str
    entity_ids: list[int]
    signal_ids: list[int]
    recurrence_of: uuid.UUID | None
    recurrence_similarity: float | None
    created_at: datetime
    entities: list[EntityOut]
    signals: list[SignalOut]
    verdict: TriageVerdictResponse | None


class TimelinePhaseOut(BaseModel):
    """`app.graph.timeline.TimelinePhase`, serialised. `tactic_is_placeholder` is carried through
    rather than hidden: it tells the UI (and a reviewer) which phases carry a deterministic
    lookup-table tactic versus one the agent actually attributed."""

    ts: datetime | None
    tactic: str
    tactic_is_placeholder: bool
    event_ids: list[int]
    summary: str
    detector_key: str
    entity_type: str
    entity_value: str


class TimelineResponse(BaseModel):
    phases: list[TimelinePhaseOut]


class GraphNode(BaseModel):
    """`id` is `"{type}:{value}"`, not the database id — the UI keys edges by it, and a stable
    composite key survives the entity-id churn of a re-ingest."""

    id: str
    type: str
    value: str
    risk_score: float
    event_count: int
    is_seed: bool


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str
    weight: float
    event_count: int


class IncidentGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
