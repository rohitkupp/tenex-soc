"""Pydantic v2 schemas for docs/09-API-CONTRACT.md's Events section."""

from __future__ import annotations

import uuid
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _stringify_ip(v: Any) -> Any:
    """psycopg 3 hands `events.src_ip`/`dst_ip` back as `ipaddress.IPv4Address` /
    `IPv6Address` instances (see app.models.event), not `str`. Normalize to `str` here
    so the API always emits plain JSON strings regardless of driver internals."""
    if isinstance(v, IPv4Address | IPv6Address):
        return str(v)
    return v


class EventListItem(BaseModel):
    """One row in `GET /api/analyses/{id}/events` — hot columns only. Deliberately
    flat and without `ocsf`/`enrichment`: docs/09 keeps list shapes light because this
    view can page through 1M+ rows (docs/13 M3 acceptance), and the full payload is a
    click away via `GET /api/events/{event_id}`.

    `signal_count`/`max_confidence`/`detectors` are the take-home brief's "highlight the
    anomalous entries ... with a confidence score" requirement, folded onto the list row
    cheaply: `app.api.events.list_events` computes them with exactly one extra query per
    *page* (never per event, never per row) and attaches them here via `model_copy`, so the
    fields default to the "no signal touched this event" values below rather than being
    required — that keeps `EventListItem.model_validate(event)` on a bare ORM row valid
    before the page-wide stats are folded in.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    analysis_id: uuid.UUID
    ts: datetime
    source_type: str
    raw_line_no: int
    ocsf_class_uid: int
    principal: str | None
    src_ip: str | None
    dst_ip: str | None
    domain: str | None
    url_path: str | None
    action: str | None
    http_method: str | None
    status_code: int | None
    bytes_in: int | None
    bytes_out: int | None
    user_agent: str | None
    event_key: str | None
    signal_count: int = 0
    max_confidence: float | None = None
    detectors: list[str] = Field(default_factory=list)

    _normalize_src_ip = field_validator("src_ip", mode="before")(_stringify_ip)
    _normalize_dst_ip = field_validator("dst_ip", mode="before")(_stringify_ip)


class EventListResponse(BaseModel):
    items: list[EventListItem]
    next_cursor: str | None


class EventSignalOut(BaseModel):
    """One `signals` row (docs/02) cited against this event — the take-home brief's "brief
    explanation of why the entry was flagged" and "confidence score" requirements.

    `explanation` is the detector's own JSONB payload, passed through verbatim — same
    reasoning as `app.schemas.incident.SignalOut`: the UI dispatches on `detector_key` to
    render it, so narrowing/reshaping it here would make the server a second place that has
    to learn about every new detector."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    detector_key: str
    detector_layer: str
    confidence: float
    raw_score: float
    mitre_technique: str | None
    explanation: dict[str, Any]
    window_start: datetime | None
    window_end: datetime | None


class EventOut(EventListItem):
    """`GET /api/events/{event_id}` — full OCSF + enrichment, used by citation
    expansion in the UI (docs/09). `signals` carries every signal that cites this event
    (via `evidence_event_ids`), full explanation included — this is the single-event
    detail view, so unlike the list endpoint a per-event query here is fine."""

    ocsf: dict[str, Any]
    enrichment: dict[str, Any]
    signals: list[EventSignalOut] = Field(default_factory=list)
