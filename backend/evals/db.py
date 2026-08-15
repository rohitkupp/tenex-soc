"""Small Postgres helpers shared by the harness's pipeline glue.

The eval harness runs the real L1-L5 pipeline against a live Postgres (`app.graph.pipeline_demo`,
`app.graph.ingest.ingest_log_file` — both require one; there is no DB-free code path for L1's
Sigma rules or L2's `events_dao`, see those packages' own module docstrings). Every scenario run
creates a **fresh, throwaway tenant** (`ingest_log_file`'s own design). Left alone across repeated
`make eval` runs (every PR, per docs/12) those would accumulate forever, so this module's
`cleanup_tenants` sweeps them at the end of every harness run — the exact same delete order
`tests/conftest.py`'s `tenant_cleanup` fixture already uses (analyses -> uploads -> users ->
tenants; `events`/`signals`/`incidents`/`entities`/`entity_edges` all cascade from `analyses`).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import text

from app.core.db import get_engine
from app.core.logging import get_logger

log = get_logger(__name__)


def cleanup_tenants(tenant_ids: Sequence[uuid.UUID]) -> None:
    """Delete every row created under `tenant_ids` (eval-harness scratch tenants only — never
    called with a real tenant id). No-op on an empty sequence."""
    ids = list(tenant_ids)
    if not ids:
        return
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM analyses WHERE tenant_id = ANY(:ids)"), {"ids": ids})
        conn.execute(text("DELETE FROM uploads WHERE tenant_id = ANY(:ids)"), {"ids": ids})
        conn.execute(text("DELETE FROM users WHERE tenant_id = ANY(:ids)"), {"ids": ids})
        conn.execute(text("DELETE FROM tenants WHERE id = ANY(:ids)"), {"ids": ids})
    log.info("db.cleanup_tenants", n_tenants=len(ids))
