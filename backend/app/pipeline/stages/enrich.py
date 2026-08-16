"""Enrich — docs/01's `enrich` stage contract, made real:

* Precondition: events exist (`parse` already ran).
* Postcondition: `events.enrichment` populated, `entities` seeded.

Wired to `app/enrichment/` exactly as that package's own `__init__.py` docstring says the
enricher worker is expected to: one `enrich_event({...})` call per event, keyed on the same four
hot-column names (`src_ip`, `dst_ip`, `domain`, `user_agent`) `Event`/`OCSFEventBase.hot_columns()`
already use, writing the result straight into `events.enrichment` (JSONB, already exists on the
table — M3 defaulted it to `{}` for exactly this stage to fill in).

## Entity seeding

`app.graph.builder.persist_entity_graph` (M10, correlate stage) is the *complete*, graph-aware
writer for `entities` — it needs Louvain's induced subgraph, so it cannot run until correlate has
the full entity graph built. This stage's own "entities seeded" postcondition is therefore a
narrower, graph-independent pass: one row per distinct `(type, value)` this analysis's raw event
columns carry (`user` from `principal`, `src_ip`, `domain` — preferring the just-computed
registrable domain over the raw hostname — `dst_ip`), first_seen/last_seen/event_count only, no
edges. `entities`' own `UNIQUE (analysis_id, type, value)` constraint (docs/02) makes this an
idempotent upsert; correlate's later, more complete write (which also knows about `asn`/`country`
nodes and every edge) upserts the exact same rows again without conflict.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text

from app.core.db import get_engine
from app.core.logging import get_logger
from app.enrichment import enrich_event
from app.pipeline import state
from app.pipeline.contracts import NEXT_QUEUE, STAGE_PROGRESS, public_counters
from app.pipeline.messages import StageMessage
from app.pipeline.progress import publish_progress
from app.pipeline.redis_client import get_redis

log = get_logger(__name__)

# Batched UPDATE size — one round trip per this many events rather than one per row (a real
# analysis is easily tens of thousands of events) or one giant statement (unbounded parameter
# list). Matches the "chunked, not row-by-row, not everything-at-once" shape the rest of this
# package already uses (`app.pipeline.stages.parse`'s COPY is the bulk-load equivalent).
_ENRICH_BATCH_SIZE = 2000

_EntityKey = tuple[str, str]


class _EntityAccumulator:
    __slots__ = ("event_count", "first_seen", "last_seen")

    def __init__(self, ts: datetime) -> None:
        self.first_seen = ts
        self.last_seen = ts
        self.event_count = 0

    def observe(self, ts: datetime) -> None:
        self.event_count += 1
        if ts < self.first_seen:
            self.first_seen = ts
        if ts > self.last_seen:
            self.last_seen = ts


def _enrich_and_seed(message: StageMessage) -> dict[str, Any]:
    with get_engine().begin() as conn:
        # Hand-written text() SQL against a tenant-scoped table (`events`) bypasses the ORM
        # guard in `app.models.base` — this predicate is that guard, written by hand, exactly
        # as that module's own docstring requires. `analysis_id` alone would already be
        # sufficient (an analysis belongs to exactly one tenant), but `tenant_id` travels on
        # every `StageMessage` for free, so there is no reason not to add the same defense in
        # depth `app.pipeline.state`'s own hand-written statements use throughout.
        rows = conn.execute(
            text(
                """
                SELECT id, ts, principal, src_ip, dst_ip, domain, user_agent
                FROM events
                WHERE analysis_id = :analysis_id AND tenant_id = :tenant_id
                ORDER BY id
                """
            ),
            {"analysis_id": message.analysis_id, "tenant_id": message.tenant_id},
        ).all()

        entities: dict[_EntityKey, _EntityAccumulator] = {}

        def _touch(entity_type: str, value: str | None, ts: datetime) -> None:
            if not value:
                return
            key = (entity_type, value)
            accum = entities.get(key)
            if accum is None:
                entities[key] = accum = _EntityAccumulator(ts)
            accum.observe(ts)

        batch: list[dict[str, Any]] = []
        n_events = 0
        for event_id, ts, principal, src_ip, dst_ip, domain, user_agent in rows:
            src_ip_str = str(src_ip) if src_ip is not None else None
            dst_ip_str = str(dst_ip) if dst_ip is not None else None
            enrichment = enrich_event(
                {
                    "src_ip": src_ip_str,
                    "dst_ip": dst_ip_str,
                    "domain": domain,
                    "user_agent": user_agent,
                }
            )
            batch.append({"id": event_id, "enrichment": json.dumps(enrichment)})
            n_events += 1

            registrable = (enrichment.get("domain") or {}).get("registrable_domain") or domain
            _touch("user", principal, ts)
            _touch("src_ip", src_ip_str, ts)
            _touch("domain", registrable, ts)
            _touch("dst_ip", dst_ip_str, ts)

            if len(batch) >= _ENRICH_BATCH_SIZE:
                conn.execute(
                    text(
                        "UPDATE events SET enrichment = CAST(:enrichment AS jsonb) WHERE id = :id"
                    ),
                    batch,
                )
                batch = []
        if batch:
            conn.execute(
                text("UPDATE events SET enrichment = CAST(:enrichment AS jsonb) WHERE id = :id"),
                batch,
            )

        for (entity_type, value), accum in entities.items():
            conn.execute(
                text(
                    """
                    INSERT INTO entities (analysis_id, type, value, first_seen, last_seen, event_count)
                    VALUES (:analysis_id, :type, :value, :first_seen, :last_seen, :event_count)
                    ON CONFLICT (analysis_id, type, value) DO UPDATE SET
                        first_seen = LEAST(entities.first_seen, EXCLUDED.first_seen),
                        last_seen = GREATEST(entities.last_seen, EXCLUDED.last_seen),
                        event_count = EXCLUDED.event_count
                    """
                ),
                {
                    "analysis_id": message.analysis_id,
                    "type": entity_type,
                    "value": value,
                    "first_seen": accum.first_seen,
                    "last_seen": accum.last_seen,
                    "event_count": accum.event_count,
                },
            )

        state.mark_stage(
            conn,
            analysis_id=message.analysis_id,
            tenant_id=message.tenant_id,
            stage="enrich",
            progress=STAGE_PROGRESS["enrich"],
        )
        counters = state.get_counters(
            conn, analysis_id=message.analysis_id, tenant_id=message.tenant_id
        )

    return {"n_events": n_events, "n_entities": len(entities), "counters": counters}


async def handle(message: StageMessage) -> list[tuple[str, StageMessage]]:
    result = await asyncio.to_thread(_enrich_and_seed, message)

    await publish_progress(
        get_redis(),
        analysis_id=message.analysis_id,
        stage="enrich",
        progress=STAGE_PROGRESS["enrich"],
        status="running",
        message=(
            f"Enriched {result['n_events']} event(s) — domain/IP/user-agent/tag lookups — "
            f"and seeded {result['n_entities']} entities."
        ),
        counters=public_counters(result["counters"]),
    )

    next_queue = NEXT_QUEUE["enrich"]
    assert next_queue is not None  # enrich always forwards to anonymize
    now = datetime.now(UTC)
    return [
        (
            next_queue,
            message.model_copy(update={"stage": next_queue, "attempt": 0, "emitted_at": now}),
        )
    ]
