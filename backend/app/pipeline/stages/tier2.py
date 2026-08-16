"""Tier 2 sync — docs/01's `tier2` stage contract, made real. Terminal stage.

* Precondition: verdicts exist (`triage` already ran).
* Postcondition: `tier2_signatures` rows.

`app.tier2.signature_sync` is a self-contained, fully tested package that already names this
exact wiring point in its own module docstring: "The live pipeline hook is `app.pipeline`'s
`tier2` stage ... wiring `sync_incident_to_tier2` into that worker as its real handler is that
stage's owner's job." This module is that wiring: every incident in the analysis that has a
verdict gets one `sync_incident_to_tier2` call; `should_sync_to_tier2` (inside that function)
decides whether a signature is actually written (`true_positive`/`needs_review` only —
`benign`/`false_positive` are not threat intelligence, see that package's own docstring).

Also the one stage that flips `analyses.status` to `complete` — `app.pipeline.state.mark_complete`,
the same call the old skeleton's `next_queue is None` branch made, now made from real, non-skeleton
code for the same reason: this is genuinely the last stage in the chain
(`app.pipeline.contracts.NEXT_QUEUE["tier2"] is None`).
"""

from __future__ import annotations

import asyncio
from typing import Any

from sqlalchemy import select

from app.core.db import get_engine, get_session_factory
from app.core.logging import get_logger
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.tenant import Tenant
from app.models.triage_verdict import TriageVerdict
from app.pipeline import state
from app.pipeline.contracts import STAGE_PROGRESS, public_counters
from app.pipeline.errors import PermanentStageError
from app.pipeline.messages import StageMessage
from app.pipeline.progress import publish_progress
from app.pipeline.redis_client import get_redis
from app.tier2.signature_sync import sync_incident_to_tier2

log = get_logger(__name__)


def _latest_verdict(session: Any, incident_id: Any) -> TriageVerdict | None:
    return session.execute(
        select(TriageVerdict)
        .where(TriageVerdict.incident_id == incident_id)
        .order_by(TriageVerdict.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def _run_tier2(message: StageMessage) -> dict[str, Any]:
    session = get_session_factory()()
    try:
        tenant = session.get(Tenant, message.tenant_id)
        if tenant is None:
            raise PermanentStageError(f"tenant {message.tenant_id} not found")

        with tenant_scope(session, message.tenant_id):
            incident_rows = (
                session.execute(select(Incident).where(Incident.analysis_id == message.analysis_id))
                .scalars()
                .all()
            )

            n_synced = 0
            n_no_verdict = 0
            n_not_syncable = 0
            for incident in incident_rows:
                verdict = _latest_verdict(session, incident.id)
                if verdict is None:
                    n_no_verdict += 1
                    continue
                signature = sync_incident_to_tier2(
                    session, incident=incident, verdict=verdict, tenant=tenant
                )
                if signature is not None:
                    n_synced += 1
                else:
                    n_not_syncable += 1

            session.commit()
    finally:
        session.close()

    with get_engine().begin() as conn:
        state.mark_stage(
            conn,
            analysis_id=message.analysis_id,
            tenant_id=message.tenant_id,
            stage="tier2",
            progress=STAGE_PROGRESS["tier2"],
        )
        state.mark_complete(conn, analysis_id=message.analysis_id, tenant_id=message.tenant_id)
        counters = state.get_counters(
            conn, analysis_id=message.analysis_id, tenant_id=message.tenant_id
        )

    log.info(
        "tier2.done",
        analysis_id=str(message.analysis_id),
        n_incidents=len(incident_rows),
        n_synced=n_synced,
        n_no_verdict=n_no_verdict,
        n_not_syncable=n_not_syncable,
    )
    return {
        "n_incidents": len(incident_rows),
        "n_synced": n_synced,
        "n_no_verdict": n_no_verdict,
        "n_not_syncable": n_not_syncable,
        "counters": counters,
    }


async def handle(message: StageMessage) -> list[tuple[str, StageMessage]]:
    result = await asyncio.to_thread(_run_tier2, message)

    await publish_progress(
        get_redis(),
        analysis_id=message.analysis_id,
        stage="tier2",
        progress=STAGE_PROGRESS["tier2"],
        status="complete",
        message=(
            f"Tier 2 sync complete: {result['n_synced']}/{result['n_incidents']} incident(s) "
            "synced as cross-tenant signatures "
            f"({result['n_no_verdict']} never triaged, {result['n_not_syncable']} not "
            "syncable — benign/false-positive). Analysis complete."
        ),
        counters=public_counters(result["counters"]),
    )

    return []  # terminal — no next queue
