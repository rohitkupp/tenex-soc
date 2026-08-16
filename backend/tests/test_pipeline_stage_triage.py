"""`app.pipeline.stages.triage` — real work: drives the real Path B four-stage flow
(`app.agent.orchestrator.triage_top_incidents_for_analysis`) and Path A
(`narrate_analysis`), respects `MAX_TRIAGE_INCIDENTS`, and accumulates real cost into
`analyses.llm_cost_usd`. Uses `tests.fixtures.agent.SafeFallbackCaller` so this never needs a
live `ANTHROPIC_API_KEY` (CLAUDE.md: recorded/scripted fixtures, no live calls in CI)."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from sqlalchemy import text

from app.core.config import get_settings
from app.core.db import get_engine
from app.pipeline.messages import StageMessage
from app.pipeline.stages import triage
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.agent import SafeFallbackCaller
from tests.fixtures.response import make_incident, make_signal


def _message(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> StageMessage:
    return StageMessage(
        analysis_id=analysis_id,
        tenant_id=tenant_id,
        stage="triage",
        storage_ref=None,
        source_type=None,
        attempt=0,
        emitted_at=datetime.now(UTC),
    )


def test_triage_respects_max_triage_incidents_and_accumulates_cost(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"triage-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    settings = get_settings()
    n_incidents = settings.max_triage_incidents + 3
    for i in range(n_incidents):
        signal = make_signal(
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            entity_type="user",
            entity_value=f"user{i}@corp.example",
        )
        make_incident(
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            signal_ids=[signal.id],
            title=f"incident {i}",
            fused_score=0.5 + i * 0.01,
        )

    caller = SafeFallbackCaller()
    handler = triage.make_handler(caller=caller)
    forwarded = asyncio.run(handler(_message(analysis.id, tenant.id)))

    assert len(forwarded) == 1
    assert forwarded[0][0] == "tier2"

    with get_engine().begin() as conn:
        n_verdicts = conn.execute(
            text(
                "SELECT count(*) FROM triage_verdicts tv "
                "JOIN incidents i ON i.id = tv.incident_id WHERE i.analysis_id = :aid"
            ),
            {"aid": analysis.id},
        ).scalar_one()
        analysis_row = conn.execute(
            text("SELECT llm_cost_usd, counters FROM analyses WHERE id = :aid"),
            {"aid": analysis.id},
        ).one()

    # The cap is enforced -- not every incident got triaged.
    assert n_verdicts == settings.max_triage_incidents
    assert n_verdicts < n_incidents

    # Every SafeFallbackCaller verdict is a `needs_review` fallback, and every incident beyond
    # the cap has no verdict at all -- both count as needs_attention (app.api.incident_detail's
    # own predicate: "verdict is None, or the agent asked for review, or citations failed").
    assert analysis_row.counters["needs_attention"] == n_incidents

    # Path B's Analyst calls (one per triaged incident) plus Path A's single Narrator call all
    # accumulate real, non-zero token cost.
    assert analysis_row.llm_cost_usd is not None
    assert analysis_row.llm_cost_usd > 0

    # Path A ran exactly once regardless of incident count -- one narrate_analysis tool call.
    narrate_calls = [
        c for c in caller.calls if (c.get("tool_choice") or {}).get("name") == "narrate_analysis"
    ]
    assert len(narrate_calls) == 1


def test_triage_needs_review_verdicts_are_disposition_needs_review(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"triage2-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    signal = make_signal(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        entity_type="user",
        entity_value="only-user@corp.example",
    )
    make_incident(tenant_id=tenant.id, analysis_id=analysis.id, signal_ids=[signal.id])

    caller = SafeFallbackCaller()
    handler = triage.make_handler(caller=caller)
    asyncio.run(handler(_message(analysis.id, tenant.id)))

    with get_engine().begin() as conn:
        disposition = conn.execute(
            text(
                "SELECT tv.disposition FROM triage_verdicts tv "
                "JOIN incidents i ON i.id = tv.incident_id WHERE i.analysis_id = :aid"
            ),
            {"aid": analysis.id},
        ).scalar_one()
    assert disposition == "needs_review"
