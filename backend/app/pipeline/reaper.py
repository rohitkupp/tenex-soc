"""Mark abandoned analyses as failed instead of leaving them 'running' forever.

Nothing in this pipeline ever noticed an analysis that stopped making progress. An analysis is
set to `running` when its first stage message is published and only leaves that state when a
stage marks it `complete` or `failed`. If the message driving it is lost — a worker killed
mid-stage by a deploy, a broker redelivery limit reached, a queue purged — there is no message
left to fail and no timer watching, so the row sits at `running` indefinitely and the UI shows a
spinner that will never resolve.

That is exactly what happened to two production analyses: `q.triage` held no message for either,
`dead_letters` had no row, and one had been "running" for two hours with 3 of 15 incidents
triaged. From the outside it is indistinguishable from slow progress, which is why it needs an
explicit answer rather than a longer wait.

## Why a timeout and not a heartbeat

A heartbeat would be more precise — a stage that is genuinely working could refresh it — but it
needs every stage to remember to emit one, which is the kind of second bookkeeping obligation
this codebase has repeatedly gotten wrong (a hand-maintained list nobody updates). `analyses`
already records `started_at` and every stage already updates `stage`/`progress` through
`app.pipeline.state`, so "no forward movement for N minutes" is answerable from data that is
already maintained, by code that stages cannot forget to call.

## Why the threshold is generous

Triage runs the four-stage agent pipeline over `MAX_TRIAGE_INCIDENTS` incidents at roughly a
minute each, so a legitimately busy run genuinely occupies half an hour. The threshold has to sit
well past that: reaping a run that was about to finish destroys real, paid-for work. Being late
to declare a stuck run is cheap; being early is not.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy import text

from app.core.db import get_engine
from app.core.logging import get_logger

log = get_logger(__name__)

# See "Why the threshold is generous". A 20-incident triage at ~1 min/incident plus narration is
# ~30 min of legitimate work; this leaves better than 2x headroom on top of that.
STALE_AFTER: Final[timedelta] = timedelta(minutes=75)

_STALE_ERROR: Final[str] = (
    "Analysis stopped making progress and was marked failed by the reaper. Its pipeline message "
    "was lost — most often a worker restarted mid-stage — so no stage remained to advance or "
    "fail it. Any work already committed (events, signals, incidents, verdicts) is intact; use "
    "retry to resume from the stage it stopped at."
)


def reap_stale_analyses(now: datetime | None = None) -> list[dict[str, Any]]:
    """Flip every `queued`/`running` analysis older than `STALE_AFTER` to `failed`.

    Returns one dict per reaped analysis so a caller can log what it did. Idempotent: a second
    call reaps nothing, because the first left no eligible rows.

    Deliberately does **not** delete anything. A reaped analysis keeps its events, signals,
    incidents and verdicts — `POST /api/analyses/{id}/retry` republishes from the failing stage
    and the per-incident verdict skip means already-triaged incidents are not paid for twice.
    Marking it failed is a statement about the *pipeline run*, not a verdict on its data.
    """
    now = now or datetime.now(UTC)
    cutoff = now - STALE_AFTER

    with get_engine().begin() as conn:
        rows = (
            conn.execute(
                text(
                    """
                UPDATE analyses
                SET status = 'failed', error = COALESCE(error, :err), finished_at = :now
                WHERE status IN ('queued', 'running')
                  AND started_at IS NOT NULL
                  AND started_at < :cutoff
                RETURNING id, tenant_id, stage, started_at
                """
                ),
                {"err": _STALE_ERROR, "now": now, "cutoff": cutoff},
            )
            .mappings()
            .all()
        )

    reaped = [dict(r) for r in rows]
    for r in reaped:
        log.warning(
            "pipeline.analysis_reaped",
            analysis_id=str(r["id"]),
            stage=r["stage"],
            started_at=str(r["started_at"]),
            stale_after_minutes=STALE_AFTER.total_seconds() / 60,
        )
    return reaped
