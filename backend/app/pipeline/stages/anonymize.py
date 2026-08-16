"""Anonymize — docs/01's `anonymize` stage contract, made real.

docs/01's literal postcondition ("`pseudonym_map` written, `events.redacted` populated") names
two persisted structures that were never added to the real schema: `docs/02-DATA-MODEL.md` has no
`pseudonym_map` table and `events` has no `redacted` column (grepped — zero hits in
`alembic/versions/`, confirmed against the live migrations before writing this module). This is
not a gap this stage should paper over with a new table invented on the spot — CLAUDE.md is
explicit that a schema change gets reported before it lands, and the design question ("what does
a durable reverse map look like, what does it cost to maintain") deserves an actual decision, not
one made silently mid-wiring-task.

More importantly, **this checkout already has a working, tested answer to "pseudonymize before
data leaves the tenant boundary" that does not depend on either structure**: `app.agent.context`'s
own module docstring states it plainly — "every tool in this package pseudonymizes and redacts
defensively, every time, using `app.privacy`'s public API directly" (CLAUDE.md rule 4). The
boundary CLAUDE.md rule 4 actually cares about is the LLM call, not the Postgres row, and that
boundary is already enforced, independently of whether this stage ran at all. Rewriting a
pseudonymized/redacted *copy* of every event at rest would be a second, redundant enforcement
point for the same rule — and one that is actively wrong to rely on, since every downstream
detector (`app.detection.*`) and the graph (`app.graph.*`) need the *real* `principal`/`src_ip`/
`domain` values to correlate correctly; only the LLM-facing edge should ever see a pseudonym.

So this stage's real, honest job is the *audit* half of docs/06's own talking point ("1,204
secrets redacted before LLM submission"): run the same `app.privacy.pseudonymize`/`app.privacy.
redact` functions this analysis's raw events would actually go through at the LLM boundary, once,
for real, over every event, and publish the true counts. It does not rewrite any row — there is
nothing downstream that reads a rewritten one — but the numbers it reports are genuine
per-analysis measurements, not fabricated, and they are stored as internal `analyses.counters`
bookkeeping (`_privacy_identifiers_pseudonymized` / `_privacy_secrets_redacted`, the same
underscore-prefixed-internal-key convention `app.pipeline.stages.parse`'s `_parse_failed_lines`
already established) so the number survives past the SSE message.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text

from app.core.db import get_engine
from app.core.logging import get_logger
from app.pipeline import state
from app.pipeline.contracts import NEXT_QUEUE, STAGE_PROGRESS, public_counters
from app.pipeline.errors import PermanentStageError
from app.pipeline.messages import StageMessage
from app.pipeline.progress import publish_progress
from app.pipeline.redis_client import get_redis
from app.privacy.event_privacy import anonymize_event
from app.privacy.redact import redact_text

log = get_logger(__name__)

_IDENTIFIERS_COUNTER_KEY = "_privacy_identifiers_pseudonymized"
_SECRETS_COUNTER_KEY = "_privacy_secrets_redacted"

# The two free-text hot columns this stage can reach directly (`events.url_path`,
# `events.user_agent`) — matches `app.agent.context.TRUNCATE_FIELDS`'s hot-column subset (that
# tuple also includes `referrer`, which is OCSF-JSONB-only, not a hot column here; the live
# per-call redaction at the LLM boundary still covers it when a prompt actually needs it).
_FREE_TEXT_FIELDS = ("url_path", "user_agent")


def _privacy_audit(message: StageMessage) -> dict[str, Any]:
    with get_engine().begin() as conn:
        tenant_row = conn.execute(
            text("SELECT pseudonym_salt FROM tenants WHERE id = :tenant_id"),
            {"tenant_id": message.tenant_id},
        ).one_or_none()
        if tenant_row is None:
            raise PermanentStageError(f"tenant {message.tenant_id} not found")
        salt = bytes(tenant_row[0])

        # Hand-written text() SQL against a tenant-scoped table — same documented convention
        # `app.pipeline.stages.enrich` follows; see that module's matching comment.
        rows = conn.execute(
            text(
                """
                SELECT principal, src_ip, dst_ip, url_path, user_agent
                FROM events
                WHERE analysis_id = :analysis_id AND tenant_id = :tenant_id
                """
            ),
            {"analysis_id": message.analysis_id, "tenant_id": message.tenant_id},
        ).all()

        n_events = 0
        n_identifiers = 0
        redaction_counts: dict[str, int] = {}
        for principal, src_ip, dst_ip, url_path, user_agent in rows:
            n_events += 1
            anonymized = anonymize_event(
                {
                    "principal": principal,
                    "src_ip": str(src_ip) if src_ip is not None else None,
                    "dst_ip": str(dst_ip) if dst_ip is not None else None,
                },
                tenant_id=message.tenant_id,
                salt=salt,
            )
            n_identifiers += len(anonymized.reverse_entries)

            # The field names are carried in the tuple for readability at the call site — which
            # field a redaction came from is not needed here, only the aggregate counts.
            for value in (url_path, user_agent):
                if not value:
                    continue
                result = redact_text(value)
                for pattern_name, count in result.counts.items():
                    redaction_counts[pattern_name] = redaction_counts.get(pattern_name, 0) + count

        n_secrets = sum(redaction_counts.values())

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
    result = await asyncio.to_thread(_privacy_audit, message)

    await publish_progress(
        get_redis(),
        analysis_id=message.analysis_id,
        stage="anonymize",
        progress=STAGE_PROGRESS["anonymize"],
        status="running",
        message=(
            f"Privacy pass over {result['n_events']} event(s): {result['n_identifiers']} "
            f"identifier(s) pseudonymizable, {result['n_secrets']} secret(s)/PII pattern(s) "
            "redactable. Real values stay in Postgres for detection; every field is "
            "pseudonymized/redacted again at the point it actually reaches an LLM prompt "
            "(app.agent.context, CLAUDE.md rule 4)."
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
