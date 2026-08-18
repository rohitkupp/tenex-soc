"""Anonymize — the tenant boundary, made real.

This stage used to sit between `enrich` and `detect`, where it could not anonymise anything.
Every stage downstream of it needs the plaintext: a detector cannot match `u_8f3a91c204de`
against a baseline built from `alice@corp.example`, correlation cannot group entities it can no
longer recognise, and the agent's citations would point at pseudonyms it has no way to resolve.
So the stage degraded into an audit — it counted how many identifiers *would* have been
pseudonymised and wrote the number to a counter, while its own docstring conceded it "does not
rewrite any row".

It now runs after `triage` and immediately before `tier2`, which is the boundary CLAUDE.md rule 4
actually names: `tier2` is the one cross-tenant surface in the system, the only place one
tenant's data is compared against another's. Here the stage does the thing it is named for.

## What it does

1. Pseudonymises every identity field of every event in the analysis
   (`app.privacy.event_privacy.anonymize_event`, HMAC-SHA256 under the tenant's own salt).
2. Redacts secrets and PII out of the free-text fields (`app.privacy.redact`).
3. Writes the result into the **Tier 2 database** (`app.core.db.Tier2Base`) — a physically
   separate Postgres. The primary database keeps the real values; nothing identifiable is
   copied across.
4. Publishes the true counts, which are now a report of what it did rather than a projection of
   what it would have done.

`domain` is deliberately *not* pseudonymised. docs/06 exempts it: a domain is threat
intelligence, not an identity, and hashing it under a per-tenant salt would make the
cross-tenant overlap Tier 2 exists to compute impossible — the same reasoning
`app.privacy.pseudonymize.indicator_hash` documents for its shared-salt path.

## Re-runs replace, they do not accumulate

An analysis re-run deletes its own `tier2_events` rows first. Tier 2 holds a derived projection,
so the correct state after a re-run is "what this run produced", not "everything every run ever
produced". Without the delete a retried analysis would double-count every event in Tier 2's
aggregates.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, text

from app.core.db import get_engine, get_tier2_session_factory, init_tier2_schema
from app.core.logging import get_logger
from app.models.tier2_event import Tier2Event
from app.pipeline import state
from app.pipeline.contracts import NEXT_QUEUE, STAGE_PROGRESS, public_counters
from app.pipeline.errors import PermanentStageError
from app.pipeline.messages import StageMessage
from app.pipeline.progress import publish_progress
from app.pipeline.redis_client import get_redis
from app.privacy.event_privacy import anonymize_event
from app.privacy.redact import redact_text
from app.tier2.hashing import tenant_hash

log = get_logger(__name__)

_IDENTIFIERS_COUNTER_KEY = "_privacy_identifiers_pseudonymized"
_SECRETS_COUNTER_KEY = "_privacy_secrets_redacted"

# Rows per INSERT into the Tier 2 database. Large enough that a 500-event analysis is one or two
# round trips, small enough that a very large upload does not build one enormous statement.
_COPY_BATCH = 500


def _anonymize_to_tier2(message: StageMessage) -> dict[str, Any]:
    with get_engine().begin() as conn:
        tenant_row = conn.execute(
            text("SELECT pseudonym_salt FROM tenants WHERE id = :tenant_id"),
            {"tenant_id": message.tenant_id},
        ).one_or_none()
        if tenant_row is None:
            raise PermanentStageError(f"tenant {message.tenant_id} not found")
        salt = bytes(tenant_row[0])

        rows = (
            conn.execute(
                text(
                    """
                SELECT id, ts, principal, src_ip, dst_ip, domain, action, http_method,
                       status_code, bytes_in, bytes_out, url_path, user_agent,
                       hostname, device_name, device_owner, enrichment
                FROM events
                WHERE analysis_id = :analysis_id AND tenant_id = :tenant_id
                ORDER BY id
                """
                ),
                {"analysis_id": message.analysis_id, "tenant_id": message.tenant_id},
            )
            .mappings()
            .all()
        )

    # The tenant identifier Tier 2 sees is the same salted hash `tier2_signatures` uses, so the
    # two tables join on equal terms and neither carries a real tenant id.
    hashed_tenant = tenant_hash(message.tenant_id, salt)

    init_tier2_schema()
    n_events = 0
    n_identifiers = 0
    redaction_counts: dict[str, int] = {}
    pending: list[dict[str, Any]] = []

    session_factory = get_tier2_session_factory()
    with session_factory() as tier2:
        # Replace this analysis's own projection — see module docstring.
        tier2.execute(delete(Tier2Event).where(Tier2Event.analysis_id == message.analysis_id))

        for row in rows:
            n_events += 1
            anonymized = anonymize_event(
                {
                    "principal": row["principal"],
                    "src_ip": str(row["src_ip"]) if row["src_ip"] is not None else None,
                    "dst_ip": str(row["dst_ip"]) if row["dst_ip"] is not None else None,
                    "hostname": row["hostname"],
                    "device_name": row["device_name"],
                    "device_owner": row["device_owner"],
                },
                tenant_id=message.tenant_id,
                salt=salt,
            )
            n_identifiers += len(anonymized.reverse_entries)

            redacted: dict[str, str | None] = {}
            for field in ("url_path", "user_agent"):
                value = row[field]
                if not value:
                    redacted[field] = value
                    continue
                result = redact_text(value)
                redacted[field] = result.text
                for name, count in result.counts.items():
                    redaction_counts[name] = redaction_counts.get(name, 0) + count

            pending.append(
                {
                    "tenant_hash": hashed_tenant,
                    "analysis_id": message.analysis_id,
                    "source_event_id": row["id"],
                    "ts": row["ts"],
                    # Pseudonyms only, never the originals.
                    "principal": anonymized.event.get("principal"),
                    "src_ip": anonymized.event.get("src_ip"),
                    "dst_ip": anonymized.event.get("dst_ip"),
                    "hostname": anonymized.event.get("hostname"),
                    "device_name": anonymized.event.get("device_name"),
                    "device_owner": anonymized.event.get("device_owner"),
                    # docs/06's do-NOT list — threat intelligence, not identity.
                    "domain": row["domain"],
                    "action": row["action"],
                    "http_method": row["http_method"],
                    "status_code": row["status_code"],
                    "bytes_in": row["bytes_in"],
                    "bytes_out": row["bytes_out"],
                    "url_path": redacted["url_path"],
                    "user_agent": redacted["user_agent"],
                    "enrichment": row["enrichment"] or {},
                }
            )
            if len(pending) >= _COPY_BATCH:
                tier2.execute(Tier2Event.__table__.insert(), pending)
                pending.clear()

        if pending:
            tier2.execute(Tier2Event.__table__.insert(), pending)
        tier2.commit()

    n_secrets = sum(redaction_counts.values())

    with get_engine().begin() as conn:
        state.mark_stage(
            conn,
            analysis_id=message.analysis_id,
            tenant_id=message.tenant_id,
            stage="anonymize",
            progress=STAGE_PROGRESS["anonymize"],
        )
        state.increment_counter(
            conn,
            analysis_id=message.analysis_id,
            tenant_id=message.tenant_id,
            key=_IDENTIFIERS_COUNTER_KEY,
            delta=n_identifiers,
        )
        state.increment_counter(
            conn,
            analysis_id=message.analysis_id,
            tenant_id=message.tenant_id,
            key=_SECRETS_COUNTER_KEY,
            delta=n_secrets,
        )
        counters = state.get_counters(
            conn, analysis_id=message.analysis_id, tenant_id=message.tenant_id
        )

    return {
        "n_events": n_events,
        "n_identifiers": n_identifiers,
        "n_secrets": n_secrets,
        "redaction_counts": redaction_counts,
        "counters": counters,
    }


async def handle(message: StageMessage) -> list[tuple[str, StageMessage]]:
    result = await asyncio.to_thread(_anonymize_to_tier2, message)

    await publish_progress(
        get_redis(),
        analysis_id=message.analysis_id,
        stage="anonymize",
        progress=STAGE_PROGRESS["anonymize"],
        status="running",
        message=(
            f"Copied {result['n_events']} event(s) into the Tier 2 database with "
            f"{result['n_identifiers']} identifier(s) pseudonymized and {result['n_secrets']} "
            "secret(s)/PII pattern(s) redacted. The primary database keeps the real values; "
            "nothing identifiable crosses the tenant boundary (CLAUDE.md rule 4)."
        ),
        counters=public_counters(result["counters"]),
    )

    next_queue = NEXT_QUEUE["anonymize"]
    assert next_queue is not None
    now = datetime.now(UTC)
    return [
        (
            next_queue,
            message.model_copy(update={"stage": next_queue, "attempt": 0, "emitted_at": now}),
        )
    ]
