"""Pydantic v2 schemas for docs/09-API-CONTRACT.md's "Tier 2" section."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class IncidentTypeBreakdownOut(BaseModel):
    incident_type: str
    signature_count: int
    tenant_count: int
    avg_confidence: float


class Tier2OverviewResponse(BaseModel):
    total_signatures: int
    total_tenants: int
    total_overlapping_indicators: int
    by_incident_type: list[IncidentTypeBreakdownOut]


class IndicatorOverlapEntryOut(BaseModel):
    indicator_hash: str
    signature_count: int
    tenant_count: int
    incident_types: list[str]
    first_observed_at: datetime
    last_observed_at: datetime


class IndicatorOverlapResponse(BaseModel):
    items: list[IndicatorOverlapEntryOut]


class Tier2QueryRequest(BaseModel):
    question: str


class Tier2QueryResponse(BaseModel):
    """docs/09: `POST /api/tier2/query` -> `{sql, explanation, columns, rows, chart_hint}`,
    always including `sql` — rejected or not (docs/09: "especially then")."""

    sql: str
    explanation: str
    columns: list[str]
    rows: list[list[Any]]
    chart_hint: str
    rejected: bool
    rejection_reason: str | None
