"""Pydantic v2 schemas for docs/09-API-CONTRACT.md's Events section."""

from __future__ import annotations

import uuid
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator


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
    click away via `GET /api/events/{event_id}`."""

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

    _normalize_src_ip = field_validator("src_ip", mode="before")(_stringify_ip)
    _normalize_dst_ip = field_validator("dst_ip", mode="before")(_stringify_ip)


class EventListResponse(BaseModel):
    items: list[EventListItem]
    next_cursor: str | None


class EventOut(EventListItem):
    """`GET /api/events/{event_id}` — full OCSF + enrichment, used by citation
    expansion in the UI (docs/09)."""

    ocsf: dict[str, Any]
    enrichment: dict[str, Any]
