"""Bulk COPY writer for `events` — docs/02-DATA-MODEL.md is explicit: "Bulk-load with
COPY, never row-by-row inserts." This module is the only place that should ever write
to `events`.

## The seam with `app/parsers/`

A separate agent owns `app/parsers/` and `app/ocsf/` and is building parsers that emit
`OCSFEvent` objects via an iterator over a file. This module does **not** import from
either package, and does not know how an `OCSFEvent` is shaped internally — it depends
only on the narrow structural contract below (`EventRecord`), which mirrors
docs/02's `events` columns one-for-one (everything except `id`, which Postgres
generates, and `analysis_id`/`tenant_id`, which are supplied once per call, not per
row, since one writer call always loads one file into one analysis for one tenant).

Whoever wires the two halves together writes a small adapter that turns each
`OCSFEvent` (plus whatever hot-column extraction docs/03's mappers do) into something
satisfying `EventRecord` — a `dataclass`, a plain object with matching attributes, or a
generator that yields one. `EventRecord` is a `Protocol`, so nothing needs to inherit
from it; structural typing is the whole point. A plain `dict` with the same keys also
works if you pass `EventRecord.from_mapping` — see below — since COPY-ing from an
iterator of dicts is equally natural coming out of a JSON-shaped parser.

```python
class EventRecord(Protocol):
    ts: datetime                    # tz-aware
    source_type: str
    raw_line_no: int
    ocsf_class_uid: int
    principal: str | None
    src_ip: str | None              # dotted/colon text form; COPY casts to inet
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
    hostname: str | None            # Client Connector device hostname (this task)
    device_name: str | None         # opaque device identifier (this task)
    device_owner: str | None        # the asset's assigned user (this task)
    os_type: str | None             # normalized OS type (this task)
    os_version: str | None          # raw OS version string (this task)
    bypassed_traffic: bool | None   # (this task)
    flow_type: str | None           # (this task)
    ja4_hash: str | None            # JA4 client TLS fingerprint (Phase 2, this task)
    ocsf: dict[str, Any]            # full OCSF-normalized event
    enrichment: dict[str, Any]      # {} until M5's enrichment stage runs
```

## Streaming, not batching

`rows` is consumed as an `Iterable[EventRecord]` and iterated exactly once, row by row,
inside a single `COPY ... FROM STDIN` — nothing calls `list(rows)` or otherwise
materializes the whole sequence. Peak memory is therefore bounded by whatever the
*caller's* iterator holds in flight (ideally O(1) — one parsed line at a time), not by
the total row count. This is what lets `bulk_copy_events` take 1M+ rows without
exhausting memory (docs/13 M3 acceptance) — see `tests/test_events_writer.py` for a
streaming-memory proof and the standalone benchmark referenced in the M3 report for the
1M-row throughput/RSS numbers themselves.

Uses psycopg 3's `cursor.copy()` (binary-adjacent COPY protocol via the driver's own
type adapters — `Jsonb` for the two JSONB columns, everything else passed through
psycopg's native adapters for `uuid`, `datetime`, `int`, `str`, and dotted-string ->
`inet`), not a hand-built CSV/TSV blob — that sidesteps every COPY-format escaping
pitfall (tabs/newlines/backslashes inside `url_path`, `user_agent`, JSON text, etc.)
that a text-mode implementation would have to get right by hand.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

import psycopg
from psycopg.types.json import Jsonb

__all__ = ["EventRecord", "SimpleEventRecord", "bulk_copy_events"]

# Column order COPY writes in. `id` is Postgres-generated (BIGSERIAL); `analysis_id` and
# `tenant_id` are supplied once per `bulk_copy_events` call, not per row — see the
# module docstring for why.
_COPY_COLUMNS: tuple[str, ...] = (
    "analysis_id",
    "tenant_id",
    "ts",
    "source_type",
    "raw_line_no",
    "ocsf_class_uid",
    "principal",
    "src_ip",
    "dst_ip",
    "domain",
    "url_path",
    "action",
    "http_method",
    "status_code",
    "bytes_in",
    "bytes_out",
    "user_agent",
    "event_key",
    "hostname",
    "device_name",
    "device_owner",
    "os_type",
    "os_version",
    "bypassed_traffic",
    "flow_type",
    "ja4_hash",
    "ocsf",
    "enrichment",
)

_COPY_SQL = f"COPY events ({', '.join(_COPY_COLUMNS)}) FROM STDIN"


@runtime_checkable
class EventRecord(Protocol):
    """Structural contract for one row handed to `bulk_copy_events`. Matches
    docs/02-DATA-MODEL.md's `events` columns exactly, minus `id` (DB-generated) and
    `analysis_id`/`tenant_id` (call-level, not row-level — see module docstring).

    Anything with these attributes satisfies this Protocol — a `dataclass`, an
    `OCSFEvent`-derived adapter object, an ORM-unrelated plain class. No inheritance
    required; `isinstance(x, EventRecord)` works too (`runtime_checkable`), but
    `bulk_copy_events` never calls it on the hot path — checking every one of a
    million rows would defeat the point of streaming COPY.
    """

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
    hostname: str | None
    device_name: str | None
    device_owner: str | None
    os_type: str | None
    os_version: str | None
    bypassed_traffic: bool | None
    flow_type: str | None
    ja4_hash: str | None  # Phase 2 (this task) — JA4 client TLS fingerprint, `%s{ja4_str}`
    ocsf: dict[str, Any]
    enrichment: dict[str, Any]


@dataclass(slots=True)
class SimpleEventRecord:
    """Concrete, ready-to-use `EventRecord`. Not required — anything structurally
    matching the Protocol works — but saves the parser side from having to define its
    own dataclass if an `OCSFEvent` adapter is all it needs. Also used directly by this
    module's own tests and by the standalone load-test/benchmark script, since neither
    depends on `app/parsers/`.
    """

    ts: datetime
    source_type: str
    raw_line_no: int
    ocsf_class_uid: int
    ocsf: dict[str, Any]
    principal: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    domain: str | None = None
    url_path: str | None = None
    action: str | None = None
    http_method: str | None = None
    status_code: int | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    user_agent: str | None = None
    event_key: str | None = None
    hostname: str | None = None
    device_name: str | None = None
    device_owner: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    bypassed_traffic: bool | None = None
    flow_type: str | None = None
    ja4_hash: str | None = None
    enrichment: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.enrichment is None:
            self.enrichment = {}

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> SimpleEventRecord:
        """Adapter for callers that produce plain `dict`s (e.g. straight off a JSON
        parser) instead of objects — `bulk_copy_events` itself only needs attribute
        access, but this makes the dict-shaped contract mentioned in the module
        docstring concrete. Required fields raise `KeyError` (with the missing key
        named) if absent; optional fields default to `None`/`{}` like the dataclass
        itself does."""
        kwargs: dict[str, Any] = {field: m[field] for field in _REQUIRED_FIELDS}
        kwargs.update({field: m.get(field) for field in _OPTIONAL_FIELDS})
        return cls(**kwargs)


_REQUIRED_FIELDS = ("ts", "source_type", "raw_line_no", "ocsf_class_uid", "ocsf")
_OPTIONAL_FIELDS = (
    "principal",
    "src_ip",
    "dst_ip",
    "domain",
    "url_path",
    "action",
    "http_method",
    "status_code",
    "bytes_in",
    "bytes_out",
    "user_agent",
    "event_key",
    "hostname",
    "device_name",
    "device_owner",
    "os_type",
    "os_version",
    "bypassed_traffic",
    "flow_type",
    "ja4_hash",
    "enrichment",
)


def _to_copy_row(
    record: EventRecord, *, analysis_id: uuid.UUID, tenant_id: uuid.UUID
) -> tuple[Any, ...]:
    return (
        analysis_id,
        tenant_id,
        record.ts,
        record.source_type,
        record.raw_line_no,
        record.ocsf_class_uid,
        record.principal,
        record.src_ip,
        record.dst_ip,
        record.domain,
        record.url_path,
        record.action,
        record.http_method,
        record.status_code,
        record.bytes_in,
        record.bytes_out,
        record.user_agent,
        record.event_key,
        record.hostname,
        record.device_name,
        record.device_owner,
        record.os_type,
        record.os_version,
        record.bypassed_traffic,
        record.flow_type,
        record.ja4_hash,
        Jsonb(record.ocsf),
        Jsonb(record.enrichment),
    )


def bulk_copy_events(
    conn: psycopg.Connection[Any],
    *,
    analysis_id: uuid.UUID,
    tenant_id: uuid.UUID,
    rows: Iterable[EventRecord],
) -> int:
    """Stream `rows` into `events` via a single `COPY ... FROM STDIN`.

    `conn` is a raw psycopg 3 connection (not a SQLAlchemy `Session`/`Connection`) —
    COPY is a driver-level protocol, not ORM-mediated SQL, and going through the ORM
    for a million-row bulk load would reintroduce exactly the row-by-row overhead
    docs/02 says to avoid. Does not commit; the caller controls the transaction
    boundary (pass an `autocommit=True` connection, or `conn.commit()` after this
    returns — see `tests/test_events_writer.py` for both patterns).

    `rows` is iterated exactly once and never materialized as a list — see the module
    docstring's "Streaming, not batching" section. Returns the number of rows written.
    """
    written = 0
    with conn.cursor() as cur, cur.copy(_COPY_SQL) as copy:
        for record in rows:
            copy.write_row(_to_copy_row(record, analysis_id=analysis_id, tenant_id=tenant_id))
            written += 1
    return written
