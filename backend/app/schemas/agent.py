"""Pydantic v2 schemas for the verdict endpoints — docs/09-API-CONTRACT.md's `verdict` slice of
`GET /api/incidents/{id}` (full incident detail there is other milestones' concern: signals with
explanations and entities are `app/graph` — this module owns only the `triage_verdicts` row
shape). Snake_case, matching docs/09's conventions.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict


class TriageVerdictResponse(BaseModel):
    """Maps `app.models.triage_verdict.TriageVerdict` directly (docs/02's `triage_verdicts`
    table, matched field for field) — `model_validate(row)` via `from_attributes`."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    disposition: str
    confidence: float
    llm_severity_opinion: str | None
    mitre_techniques: list[dict[str, Any]]
    summary: str
    narrative: list[dict[str, Any]]
    contradicting_evidence: str | None
    # Free-text investigation guidance for a human analyst (docs/v2_migration change 20) — not
    # action IDs from a catalog.
    recommended_actions: list[str]
    tool_trace: list[dict[str, Any]]
    citation_valid: bool
    invalid_citations: list[dict[str, Any]]
    model: str
    tokens_in: int | None
    tokens_out: int | None
    cost_usd: Decimal | None
    latency_ms: int | None
    created_at: datetime


class TriageVerdictListResponse(BaseModel):
    items: list[TriageVerdictResponse]
