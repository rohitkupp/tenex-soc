"""`app.pipeline.stages.anonymize` — real work: runs the real `app.privacy` pseudonymization and
redaction functions over this analysis's events and records genuine counts. See that module's own
docstring for why it does not rewrite `events` rows in place."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from sqlalchemy import text

from app.core.db import get_engine
from app.pipeline.messages import StageMessage
from app.pipeline.stages import anonymize
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.agent import make_event


def _message(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> StageMessage:
    return StageMessage(
        analysis_id=analysis_id,
        tenant_id=tenant_id,
        stage="anonymize",
        storage_ref=None,
        source_type=None,
        attempt=0,
        emitted_at=datetime.now(UTC),
    )


def test_anonymize_reports_real_pseudonymization_and_redaction_counts(
    tenant_cleanup: list[uuid.UUID],
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"anon-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    now = datetime.now(UTC)
    make_event(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        ts=now,
        raw_line_no=1,
        principal="bob@corp.example",
        src_ip="10.1.2.3",
        dst_ip="93.184.216.34",
        url_path="/checkout?card=4111-1111-1111-1111",
    )
    make_event(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        ts=now,
        raw_line_no=2,
        principal="bob@corp.example",
        src_ip="10.1.2.3",
        dst_ip="93.184.216.34",
        url_path="/dashboard",
    )

    forwarded = asyncio.run(anonymize.handle(_message(analysis.id, tenant.id)))

    assert len(forwarded) == 1
    queue_name, next_message = forwarded[0]
    assert queue_name == "detect"
    assert next_message.stage == "detect"

    with get_engine().begin() as conn:
        counters = conn.execute(
            text("SELECT counters FROM analyses WHERE id = :aid"), {"aid": analysis.id}
        ).scalar_one()

    # Two events, each with principal/src_ip/dst_ip pseudonymizable (3 identifiers x 2 events).
    assert counters["_privacy_identifiers_pseudonymized"] == 6
    # The Luhn-valid card number on line 1's url_path is a real, detectable secret.
    assert counters["_privacy_secrets_redacted"] >= 1
    # Real events/signals/incidents/needs_attention are untouched by this stage. `.get(..., 0)`,
    # not `[...]` — a bare `make_analysis()` in a stage-isolation test never went through
    # `ingest`'s `start_ingest` (which is what seeds all four public counter keys in
    # production), so a key this stage never wrote is simply absent from the raw JSONB here,
    # not present-and-zero the way `app.pipeline.state.get_counters`'s own documented
    # empty-JSONB fallback would report it.
    assert counters.get("signals", 0) == 0
    assert counters.get("incidents", 0) == 0


def test_anonymize_does_not_rewrite_events_in_place(tenant_cleanup: list[uuid.UUID]) -> None:
    """Real values stay in Postgres for detection to use — see the module's own docstring on why
    a redacted-copy-at-rest would be actively wrong here."""
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"anon2-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    make_event(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        ts=datetime.now(UTC),
        raw_line_no=1,
        principal="carol@corp.example",
    )

    asyncio.run(anonymize.handle(_message(analysis.id, tenant.id)))

    with get_engine().begin() as conn:
        principal = conn.execute(
            text("SELECT principal FROM events WHERE analysis_id = :aid"), {"aid": analysis.id}
        ).scalar_one()
    assert principal == "carol@corp.example"
