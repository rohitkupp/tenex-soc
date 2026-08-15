"""Parse — docs/01's `parse` stage contract:

* Precondition: raw artifact exists (in MinIO — `storage_ref` on the `StageMessage`).
* Postcondition: `events` rows written, `parse_failure_rate` recorded.

This is the one stage this milestone makes **real**, per the assignment brief: stream
the object out of MinIO, parse with M3's registry (`app.parsers.registry.iter_events`),
`COPY` into `events` (`app.storage.event_writer.bulk_copy_events`), record
`analyses.parse_failure_rate`. One `StageWorker` instance runs per source type
(`app/workers/parser_zscaler.py` today — Okta and CloudTrail's sibling worker modules
were removed along with those sources), each bound to its own `q.parse.<source>` queue
— matching docs/01's services table, where each `parser-<source>` is its own
container/queue, not one worker branching on `source_type`. Trivially one worker with
one source registered, but nothing here is hardcoded to that count: adding a source
back means adding its own `app/workers/parser_<source>.py` and a `PARSER_QUEUES` entry
(`app.pipeline.contracts`), not restructuring this module.

## The fan-in

`app.pipeline.stages.orchestrator` fans a single analysis out to N parser queues in
parallel (docs/01: "Parser fan-out is parallel"). Exactly one of those N parsers must
be the one that publishes the single `q.enrich` message once all of them are done —
`app.pipeline.state.decrement_pending_parsers`'s docstring is the correctness argument
for why an atomic `UPDATE ... RETURNING` makes "the parser whose decrement observes the
counter hit zero" a safe, race-free gate under real concurrency (proved live in
`tests/test_pipeline_fanout.py`, N=1 today).

## Aggregating `parse_failure_rate` across concurrent parsers

`analyses.parse_failure_rate` is one column, but potentially several parsers write to
it. A naive "each parser sets its own local failure rate" is a last-write-wins race
that throws away whichever parsers finished first. Instead every parser atomically
accumulates its *line counts* into two `analyses.counters` keys — the public `events`
key (lines successfully written) and an internal `_parse_failed_lines` key (lines that
failed to parse) — using the same race-free `UPDATE ... RETURNING` pattern as the
fan-in gate itself. Only the parser that wins the fan-in gate computes and writes the
final `parse_failure_rate`, from the now-fully-aggregated totals, in the same
transaction as its winning decrement. `_parse_failed_lines` never reaches the wire —
`app.pipeline.contracts.public_counters` filters `analyses.counters` down to the four
documented keys before anything is published to Redis/SSE.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from typing import Any, cast

from botocore.exceptions import ClientError
from psycopg.errors import ForeignKeyViolation

from app.core.config import get_settings
from app.core.db import get_engine
from app.core.logging import get_logger
from app.parsers.base import ParseFailure
from app.parsers.registry import ParseStats, iter_events, make_parser
from app.pipeline import state
from app.pipeline.contracts import STAGE_PROGRESS, public_counters
from app.pipeline.errors import PermanentStageError
from app.pipeline.messages import StageMessage
from app.pipeline.progress import publish_progress
from app.pipeline.redis_client import get_redis
from app.storage.client import get_s3_client
from app.storage.event_writer import EventRecord, SimpleEventRecord, bulk_copy_events

log = get_logger(__name__)

_FAILED_LINES_KEY = "_parse_failed_lines"


def _decoded_lines(body: Any) -> Iterator[str]:
    """Streams the MinIO object line by line — `iter_lines()` reads off the socket in
    chunks (botocore's default `StreamingBody` behavior), never materializing the whole
    object in memory, matching the "stream the object out of MinIO" instruction."""
    for raw_line in body.iter_lines():
        yield raw_line.decode("utf-8", errors="replace")


def _raw_connection() -> Any:
    """A bare psycopg3 connection for `bulk_copy_events`'s `COPY` protocol — that
    module takes `psycopg.Connection`, not a SQLAlchemy handle. Same pattern
    `tests/test_events_writer.py` (M3) already uses."""
    import psycopg

    dsn = get_settings().database_url.replace("postgresql+psycopg://", "postgresql://")
    return psycopg.connect(dsn, autocommit=True)


def _fetch_and_parse(message: StageMessage) -> dict[str, Any]:
    if not message.storage_ref or not message.source_type:
        raise PermanentStageError("parse message missing storage_ref/source_type")
    # Narrowed to `str` here (mypy doesn't retain the guard above inside a nested
    # function defined afterwards, since it can't prove `message` is unmodified by the
    # time `rows()` actually runs) — captured once as plain locals instead.
    storage_ref: str = message.storage_ref
    source_type: str = message.source_type

    settings = get_settings()
    s3 = get_s3_client()
    try:
        obj = s3.get_object(Bucket=settings.s3_bucket, Key=storage_ref)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"NoSuchKey", "404", "NoSuchBucket"}:
            raise PermanentStageError(
                f"object {storage_ref!r} not found in bucket {settings.s3_bucket!r}"
            ) from exc
        raise  # transient S3/MinIO error — let the normal retry policy handle it

    parser = make_parser(source_type)
    stats = ParseStats()

    def rows() -> Iterator[SimpleEventRecord]:
        for result in iter_events(source_type, _decoded_lines(obj["Body"]), parser=parser):
            stats.record(result)
            if isinstance(result, ParseFailure):
                continue
            yield SimpleEventRecord(**result.hot_columns(), ocsf=result.model_dump(mode="json"))

    raw_conn = _raw_connection()
    try:
        # `SimpleEventRecord.enrichment` is declared `dict[str, Any] | None` (event_writer.py,
        # out of this milestone's scope to edit) so its runtime __post_init__ can default it
        # to `{}` — that Optional annotation makes it structurally narrower than
        # `EventRecord.enrichment: dict[str, Any]` for mypy's (invariant) Protocol attribute
        # check, even though every actual instance's `.enrichment` is always a dict, never
        # None, by the time `__post_init__` runs. The cast documents that runtime guarantee.
        try:
            written = bulk_copy_events(
                raw_conn,
                analysis_id=message.analysis_id,
                tenant_id=message.tenant_id,
                rows=cast(Iterable[EventRecord], rows()),
            )
        except ForeignKeyViolation as exc:
            # `events.analysis_id` FKs to `analyses.id` — this means the analysis was
            # deleted (`DELETE /api/analyses/{id}` cascades, docs/09) while this
            # message was in flight. Deterministic: retrying the exact same message
            # will fail identically every time, so this skips the backoff ladder
            # rather than spending ~21s re-learning it 3 more times (same reasoning as
            # `app.pipeline.state.AnalysisNotFoundError`, which this is the COPY-path
            # equivalent of — that guard only covers `state`'s own UPDATE statements,
            # not the raw-connection `COPY` this module drives directly).
            raise PermanentStageError(
                f"analysis {message.analysis_id} no longer exists (deleted mid-parse): {exc}"
            ) from exc
    finally:
        raw_conn.close()

    with get_engine().begin() as conn:
        counters = state.increment_counter(
            conn,
            analysis_id=message.analysis_id,
            tenant_id=message.tenant_id,
            key="events",
            delta=written,
        )
        failed_total = state.increment_counter(
            conn,
            analysis_id=message.analysis_id,
            tenant_id=message.tenant_id,
            key=_FAILED_LINES_KEY,
            delta=stats.failed,
        )[_FAILED_LINES_KEY]
        remaining = state.decrement_pending_parsers(
            conn, analysis_id=message.analysis_id, tenant_id=message.tenant_id
        )

        is_last = remaining == 0
        failure_rate = None
        if is_last:
            total_lines = int(counters.get("events", 0)) + int(failed_total)
            failure_rate = (failed_total / total_lines) if total_lines else 0.0
            state.set_parse_failure_rate(
                conn,
                analysis_id=message.analysis_id,
                tenant_id=message.tenant_id,
                failure_rate=failure_rate,
            )
            state.mark_stage(
                conn,
                analysis_id=message.analysis_id,
                tenant_id=message.tenant_id,
                stage="parse",
                progress=STAGE_PROGRESS["parse"],
            )

    return {
        "written": written,
        "source_total": stats.total,
        "source_failed": stats.failed,
        "remaining_parsers": remaining,
        "is_last": is_last,
        "failure_rate": failure_rate,
        "counters": counters,
    }


async def handle(message: StageMessage) -> list[tuple[str, StageMessage]]:
    result = await asyncio.to_thread(_fetch_and_parse, message)

    if result["is_last"]:
        progress_message = (
            f"Parsed {message.source_type} ({result['written']} events, "
            f"{result['source_failed']}/{result['source_total']} lines failed). "
            f"All parsers done — overall parse_failure_rate={result['failure_rate']:.4f}."
        )
    else:
        progress_message = (
            f"Parsed {message.source_type} ({result['written']} events, "
            f"{result['source_failed']}/{result['source_total']} lines failed). "
            f"{result['remaining_parsers']} parser(s) still running."
        )

    await publish_progress(
        get_redis(),
        analysis_id=message.analysis_id,
        stage="parse",
        progress=STAGE_PROGRESS["parse"],
        status="running",
        message=progress_message,
        counters=public_counters(result["counters"]),
    )

    if not result["is_last"]:
        return []

    return [
        (
            "enrich",
            message.model_copy(
                update={
                    "stage": "enrich",
                    "source_type": None,
                    "attempt": 0,
                    "emitted_at": datetime.now(UTC),
                },
            ),
        )
    ]
