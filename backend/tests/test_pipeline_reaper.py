"""`app.pipeline.reaper` — the thing that notices an analysis nobody is driving any more.

Two production analyses sat at `running` indefinitely: their triage messages were gone from
`q.triage`, `dead_letters` held no row for either, and one had been running two hours with 3 of
15 incidents triaged. Nothing in the system was watching, so nothing ever said so.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from app.core.db import get_engine
from app.pipeline.reaper import STALE_AFTER, reap_stale_analyses
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.response import response_tenant_cleanup  # noqa: F401


def _set_started(analysis_id: uuid.UUID, started_at: datetime, status: str = "running") -> None:
    with get_engine().begin() as conn:
        conn.execute(
            text("UPDATE analyses SET started_at = :s, status = :st WHERE id = :a"),
            {"s": started_at, "st": status, "a": analysis_id},
        )


def _row(analysis_id: uuid.UUID) -> dict:
    with get_engine().connect() as conn:
        return dict(
            conn.execute(
                text("SELECT status, error, finished_at FROM analyses WHERE id = :a"),
                {"a": analysis_id},
            ).mappings().one()
        )


def _ctx(cleanup: list[uuid.UUID]):
    tenant = make_tenant()
    cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"r-{uuid.uuid4().hex[:8]}@corp.example")
    return make_analysis(tenant_id=tenant.id, user_id=user.id)


def test_an_analysis_running_past_the_threshold_is_marked_failed(
    response_tenant_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    analysis = _ctx(response_tenant_cleanup)
    _set_started(analysis.id, datetime.now(UTC) - STALE_AFTER - timedelta(minutes=5))

    reaped = reap_stale_analyses()

    assert analysis.id in {r["id"] for r in reaped}
    row = _row(analysis.id)
    assert row["status"] == "failed"
    assert row["finished_at"] is not None
    # The message must say what happened and what to do, not just "failed" — this row is the
    # only trace an analyst will ever see of a lost pipeline message.
    assert "retry" in row["error"]


def test_an_analysis_still_inside_the_threshold_is_left_alone(
    response_tenant_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """The expensive mistake is reaping a run that was about to finish — a 20-incident triage
    legitimately occupies half an hour."""
    analysis = _ctx(response_tenant_cleanup)
    _set_started(analysis.id, datetime.now(UTC) - STALE_AFTER + timedelta(minutes=10))

    reap_stale_analyses()

    assert _row(analysis.id)["status"] == "running"


def test_a_finished_analysis_is_never_touched(
    response_tenant_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """Age alone must not be grounds for reaping — only age *while still claiming to run*."""
    analysis = _ctx(response_tenant_cleanup)
    _set_started(
        analysis.id, datetime.now(UTC) - STALE_AFTER - timedelta(hours=5), status="complete"
    )

    reap_stale_analyses()

    assert _row(analysis.id)["status"] == "complete"


def test_reaping_is_idempotent(response_tenant_cleanup: list[uuid.UUID]) -> None:  # noqa: F811
    """It runs on a timer, so a second pass over the same stuck row must be a no-op rather than
    rewriting `finished_at` or re-logging every five minutes."""
    analysis = _ctx(response_tenant_cleanup)
    _set_started(analysis.id, datetime.now(UTC) - STALE_AFTER - timedelta(minutes=5))

    first = reap_stale_analyses()
    finished_at = _row(analysis.id)["finished_at"]
    second = reap_stale_analyses()

    assert analysis.id in {r["id"] for r in first}
    assert analysis.id not in {r["id"] for r in second}
    assert _row(analysis.id)["finished_at"] == finished_at
