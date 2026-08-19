"""Delete every "M10 verification" tenant and all rows under it, WAL-gently, then vacuum.

## What these tenants are

`app.graph.ingest.ingest_log_file` creates a brand-new tenant named `M10 verification` on every
call — the pipeline-demo and calibrator-fitting harnesses use it so repeated runs never collide.
By construction the data under these tenants is disposable: it is regenerated synthetic input,
never referenced by the live tenant, never shown in any UI.

## Why this script exists

A `fit-calibrators` run was executed on the production VM, whose `DATABASE_URL` is the deployed
Supabase instance. It ingested multiple 50,000-event scenario files into production before dying
on the pooler's COPY incompatibility — several hundred thousand `events` rows plus their WAL,
on a small disk. Postgres hit `No space left on device` mid-WAL-write and crash-looped. This is
the cleanup; `app.core.db.assert_local_database` (added alongside) is the prevention.

## Why the deletes are batched

The disk is the constraint. A single `DELETE ... WHERE tenant_id = ANY(...)` over ~400k rows
writes all of its WAL before commit — on a volume that just crash-looped for lack of WAL space,
that could re-kill the database mid-cleanup. Batches of `_BATCH` rows commit and pause, letting
checkpoints recycle WAL segments between rounds. Slow is the point.

`VACUUM` (plain) afterwards marks the space reusable; `VACUUM FULL events` additionally returns
it to the OS, and is safe *after* the deletes because the rewrite only needs space for the rows
that survive — run it with `--full` once the plain pass has succeeded.

    python -m app.scripts.purge_m10_tenants [--dry-run] [--full]
"""

from __future__ import annotations

import argparse
import json
import time

from sqlalchemy import text

from app.core.db import get_engine
from app.core.logging import get_logger

log = get_logger(__name__)

_TENANT_NAME = "M10 verification"
_BATCH = 20_000
_PAUSE_SECONDS = 2.0

# Children before parents. Every tenant-scoped table that the ingest/detect path writes;
# `analyses`' FK cascade does not reach events/signals (they carry their own tenant_id).
_TABLES = (
    "signals",
    "entity_edges",
    "entities",
    "incidents",
    "events",
    "analyses",
    "uploads",
    "users",
)


def purge(*, dry_run: bool = False, vacuum_full: bool = False) -> dict[str, int]:
    engine = get_engine()
    deleted: dict[str, int] = {}

    with engine.connect() as conn:
        tenant_ids = [
            r[0]
            for r in conn.execute(
                text("SELECT id FROM tenants WHERE name = :n"), {"n": _TENANT_NAME}
            )
        ]
    log.info("purge.tenants_found", n=len(tenant_ids))
    if not tenant_ids:
        return {"tenants": 0}

    for table in _TABLES:
        total = 0
        while True:
            with engine.begin() as conn:
                n = conn.execute(
                    text(
                        f"DELETE FROM {table} WHERE ctid IN ("  # noqa: S608 - fixed table list
                        f"SELECT ctid FROM {table} WHERE tenant_id = ANY(:ids) LIMIT :lim)"
                    ),
                    {"ids": tenant_ids, "lim": _BATCH},
                ).rowcount
            total += n
            if n:
                log.info("purge.batch", table=table, deleted=n, total=total)
            if dry_run or n < _BATCH:
                break
            time.sleep(_PAUSE_SECONDS)  # let a checkpoint recycle WAL before the next round
        deleted[table] = total

    if not dry_run:
        with engine.begin() as conn:
            deleted["tenants"] = conn.execute(
                text("DELETE FROM tenants WHERE id = ANY(:ids)"), {"ids": tenant_ids}
            ).rowcount

        # autocommit connection: VACUUM cannot run inside a transaction block.
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            for table in ("events", "signals", "entities", "entity_edges"):
                conn.execute(text(f"VACUUM {table}"))  # noqa: S608
                log.info("purge.vacuum", table=table)
            if vacuum_full:
                conn.execute(text("VACUUM FULL events"))
                log.info("purge.vacuum_full", table="events")

    log.info("purge.done", dry_run=dry_run, **deleted)
    return deleted


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="count one batch per table only")
    parser.add_argument(
        "--full", action="store_true", dest="vacuum_full",
        help="also VACUUM FULL events (returns disk to the OS; needs the plain pass done first)",
    )
    args = parser.parse_args()
    print(json.dumps(purge(dry_run=args.dry_run, vacuum_full=args.vacuum_full)))


if __name__ == "__main__":
    main()
