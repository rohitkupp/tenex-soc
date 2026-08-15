"""`analyses` (and `uploads`, read-only) bookkeeping for the pipeline.

Every function here takes a raw `psycopg`-backed SQLAlchemy Core `Connection` (from
`app.core.db.get_engine()`), not an ORM `Session` — deliberately. Two reasons:

1. **Atomicity.** `decrement_pending_parsers` and `increment_counters` must be single
   `UPDATE ... RETURNING` statements, not a read-then-write pair, or concurrent parser
   workers racing to finish last would corrupt (or double-fire) the fan-in gate — see
   `decrement_pending_parsers`'s docstring for the argument that a single statement is
   what makes this correct under concurrency, which docs/13/this milestone's brief
   calls out by name as "a race if done naively".
2. **Workers are async.** They run on `asyncio`'s event loop (the AMQP consumer needs
   it responsive for heartbeats); the ORM `Session`/`get_db` machinery in `app.core.db`
   and `app.models.base` is synchronous and request-scoped, built for FastAPI's
   thread-pooled sync routes, not a long-lived async consumer loop. Call sites in
   `app.pipeline.base_worker` wrap every function here in `asyncio.to_thread` so the
   blocking `psycopg` round trip never stalls the event loop.

Every statement below hand-writes `WHERE tenant_id = :tenant_id` — the documented
exception `app.models.base`'s module docstring calls out ("Hand-written text() SQL ...
bypass it ... must add its own tenant_id predicate by hand and say so in a comment").
This *is* that comment: these are internal pipeline-bookkeeping statements, always
called with a `tenant_id` taken from the `StageMessage` that authenticated the caller
(the worker that published it already resolved it from a tenant-scoped upload/analysis
row), never from unauthenticated input.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Connection, text

from app.pipeline.contracts import DEFAULT_COUNTERS
from app.pipeline.errors import PermanentStageError


class AnalysisNotFoundError(PermanentStageError):
    """The `analysis_id`/`tenant_id` pair in a `StageMessage` no longer resolves to a
    row — e.g. the analysis was deleted (`DELETE /api/analyses/{id}` cascades) while a
    message for it was in flight. Treated as a permanent (non-retryable) failure by
    `app.pipeline.base_worker`."""


def fetch_upload_for_analysis(
    conn: Connection, *, analysis_id: uuid.UUID, tenant_id: uuid.UUID
) -> dict[str, Any]:
    row = (
        conn.execute(
            text(
                """
            SELECT u.id AS upload_id, u.storage_ref, u.detected_sources, u.filename
            FROM analyses a
            JOIN uploads u ON u.id = a.upload_id
            WHERE a.id = :analysis_id AND a.tenant_id = :tenant_id AND u.tenant_id = :tenant_id
            """
            ),
            {"analysis_id": analysis_id, "tenant_id": tenant_id},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise AnalysisNotFoundError(f"analysis={analysis_id} tenant={tenant_id} not found")
    return dict(row)


def fetch_analysis(
    conn: Connection, *, analysis_id: uuid.UUID, tenant_id: uuid.UUID
) -> dict[str, Any]:
    row = (
        conn.execute(
            text(
                """
            SELECT id, tenant_id, upload_id, status, stage, progress, pending_parsers,
                   counters, parse_failure_rate, error, started_at, finished_at
            FROM analyses
            WHERE id = :analysis_id AND tenant_id = :tenant_id
            """
            ),
            {"analysis_id": analysis_id, "tenant_id": tenant_id},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise AnalysisNotFoundError(f"analysis={analysis_id} tenant={tenant_id} not found")
    return dict(row)


def start_ingest(
    conn: Connection,
    *,
    analysis_id: uuid.UUID,
    tenant_id: uuid.UUID,
    pending_parsers: int,
    progress: float,
) -> None:
    """Orchestrator's postcondition: `analyses` row exists already (M1 upload path
    created it as `status='queued'`); this sets `status='running'`, `stage='ingest'`,
    `pending_parsers`, `started_at`, and seeds `counters` to the full four-key shape
    (docs/01/02/09) so every later stage can `jsonb_set` a key that is always present."""
    conn.execute(
        text(
            """
            UPDATE analyses
            SET status = 'running',
                stage = 'ingest',
                progress = :progress,
                pending_parsers = :pending_parsers,
                counters = CAST(:counters AS jsonb),
                started_at = COALESCE(started_at, now())
            WHERE id = :analysis_id AND tenant_id = :tenant_id
            """
        ),
        {
            "analysis_id": analysis_id,
            "tenant_id": tenant_id,
            "pending_parsers": pending_parsers,
            "progress": progress,
            "counters": json.dumps(DEFAULT_COUNTERS),
        },
    )


def mark_stage(
    conn: Connection, *, analysis_id: uuid.UUID, tenant_id: uuid.UUID, stage: str, progress: float
) -> None:
    conn.execute(
        text(
            """
            UPDATE analyses
            SET stage = :stage, progress = :progress
            WHERE id = :analysis_id AND tenant_id = :tenant_id
            """
        ),
        {"analysis_id": analysis_id, "tenant_id": tenant_id, "stage": stage, "progress": progress},
    )


def decrement_pending_parsers(
    conn: Connection, *, analysis_id: uuid.UUID, tenant_id: uuid.UUID
) -> int:
    """Atomically decrement `pending_parsers` by 1 and return the post-decrement value,
    in one `UPDATE ... RETURNING` statement.

    **Why this is race-free.** Postgres takes a row-level lock for the duration of an
    `UPDATE` on the matched row. If two parser workers finish within microseconds of
    each other and both run this statement concurrently, the second transaction blocks
    until the first commits, then reads the *already-decremented* value as its own
    starting point — there is no window where both read the same pre-decrement value
    and both compute (say) `1 -> 0`. Exactly one of the two concurrent decrements can
    ever observe the return value hit `0`, which is what lets the caller
    (`app.pipeline.stages.parse`) use `== 0` as a single-fire gate to publish the one
    `q.enrich` message for the analysis, with no separate lock, no `SELECT ... FOR
    UPDATE`, and no distributed coordination — the `UPDATE` statement itself is the
    lock. A naive read-modify-write (`SELECT pending_parsers` then `UPDATE ... SET
    pending_parsers = :n - 1`) does not have this property: both transactions can read
    the same `1`, both compute `0`, and the gate fires twice.
    """
    row = conn.execute(
        text(
            """
            UPDATE analyses
            SET pending_parsers = GREATEST(pending_parsers - 1, 0)
            WHERE id = :analysis_id AND tenant_id = :tenant_id
            RETURNING pending_parsers
            """
        ),
        {"analysis_id": analysis_id, "tenant_id": tenant_id},
    ).one_or_none()
    if row is None:
        raise AnalysisNotFoundError(f"analysis={analysis_id} tenant={tenant_id} not found")
    return int(row[0])


def increment_counter(
    conn: Connection, *, analysis_id: uuid.UUID, tenant_id: uuid.UUID, key: str, delta: int
) -> dict[str, Any]:
    """Atomically add `delta` to `counters[key]` (single `UPDATE ... RETURNING`, same
    race-free reasoning as `decrement_pending_parsers`) and return the full, current
    `counters` object — what `app.pipeline.progress.publish_progress` sends straight to
    Redis/SSE without a second round trip."""
    row = conn.execute(
        text(
            """
            UPDATE analyses
            SET counters = jsonb_set(
                COALESCE(counters, '{}'::jsonb),
                ARRAY[:key],
                to_jsonb(COALESCE((counters ->> :key)::bigint, 0) + :delta)
            )
            WHERE id = :analysis_id AND tenant_id = :tenant_id
            RETURNING counters
            """
        ),
        {"analysis_id": analysis_id, "tenant_id": tenant_id, "key": key, "delta": delta},
    ).one_or_none()
    if row is None:
        raise AnalysisNotFoundError(f"analysis={analysis_id} tenant={tenant_id} not found")
    return dict(row[0])


def set_parse_failure_rate(
    conn: Connection, *, analysis_id: uuid.UUID, tenant_id: uuid.UUID, failure_rate: float
) -> None:
    conn.execute(
        text(
            """
            UPDATE analyses
            SET parse_failure_rate = :rate
            WHERE id = :analysis_id AND tenant_id = :tenant_id
            """
        ),
        {"analysis_id": analysis_id, "tenant_id": tenant_id, "rate": failure_rate},
    )


def mark_complete(conn: Connection, *, analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
    conn.execute(
        text(
            """
            UPDATE analyses
            SET status = 'complete', stage = 'tier2', progress = 1.0, finished_at = now()
            WHERE id = :analysis_id AND tenant_id = :tenant_id AND status NOT IN ('complete', 'failed')
            """
        ),
        {"analysis_id": analysis_id, "tenant_id": tenant_id},
    )


def reopen_for_retry(conn: Connection, *, analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
    """`POST /api/ops/dead-letters/{id}/retry` republishes a permanently-failed
    message with a fresh attempt budget — if it now succeeds, the analysis should be
    able to reach `complete` again, so this flips a `failed` analysis back to
    `running` (only if it is currently `failed`; a no-op otherwise, e.g. if the
    analysis was already deleted or reached a different state some other way)."""
    conn.execute(
        text(
            """
            UPDATE analyses
            SET status = 'running', error = NULL, finished_at = NULL
            WHERE id = :analysis_id AND tenant_id = :tenant_id AND status = 'failed'
            """
        ),
        {"analysis_id": analysis_id, "tenant_id": tenant_id},
    )


def mark_failed(
    conn: Connection, *, analysis_id: uuid.UUID, tenant_id: uuid.UUID, error: str
) -> None:
    """Idempotent: only the first permanent failure sets `status`/`error`/`finished_at`
    (the `WHERE status NOT IN (...)` guard) — a second stage failing after the analysis
    is already terminal does not clobber the first error or `finished_at`."""
    conn.execute(
        text(
            """
            UPDATE analyses
            SET status = 'failed', error = :error, finished_at = now()
            WHERE id = :analysis_id AND tenant_id = :tenant_id AND status NOT IN ('complete', 'failed')
            """
        ),
        {"analysis_id": analysis_id, "tenant_id": tenant_id, "error": error[:2000]},
    )


def fetch_status(conn: Connection, *, analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> str | None:
    row = conn.execute(
        text("SELECT status FROM analyses WHERE id = :analysis_id AND tenant_id = :tenant_id"),
        {"analysis_id": analysis_id, "tenant_id": tenant_id},
    ).one_or_none()
    return str(row[0]) if row is not None else None


def get_counters(
    conn: Connection, *, analysis_id: uuid.UUID, tenant_id: uuid.UUID
) -> dict[str, Any]:
    row = conn.execute(
        text("SELECT counters FROM analyses WHERE id = :analysis_id AND tenant_id = :tenant_id"),
        {"analysis_id": analysis_id, "tenant_id": tenant_id},
    ).one_or_none()
    if row is None:
        raise AnalysisNotFoundError(f"analysis={analysis_id} tenant={tenant_id} not found")
    return dict(row[0]) if row[0] else dict(DEFAULT_COUNTERS)


def utcnow() -> datetime:
    return datetime.now(UTC)
