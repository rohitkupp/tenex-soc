"""Load a plain log file into a real `tenant`/`upload`/`analysis`/`events` row set in Postgres.

Why this lives here rather than in `app/pipeline`/`app/storage`: this milestone's own ownership
list excludes `app/pipeline/**` and `app/workers/**` (the real ingestion orchestrator), but M10's
verification bar ("load a real generated scenario end to end ... run detectors ... correlate")
needs events sitting in the live `events` table before L1 (`app.detection.sigma.runner`, SQL
predicates over `events`) or L2 (`app.detection.signal.events_dao.fetch_event_rows`) can run
against them at all — both of those packages are read-only, real, already-built code this
milestone reuses rather than reimplements. This module is the small, honest adapter that makes a
plain log file usable by them, built once here and shared by `app.detection.calibration`'s
recalibration harness and `app.graph.pipeline_demo`'s end-to-end demo, rather than duplicated in
both.

Reuses `app.parsers.registry` (parsing) and `app.enrichment.enrich_event` (the same offline
enrichment the real pipeline would run at M5) — read-only usage of both, no changes to either
package. Writes via `app.storage.event_writer.bulk_copy_events`, the same bulk-COPY writer the
real ingestion path uses, so a row landing in `events` here is byte-for-byte what a live upload
would produce.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import psycopg
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.enrichment import enrich_event
from app.models.analysis import Analysis
from app.models.base import tenant_scope
from app.models.tenant import Tenant
from app.models.upload import Upload
from app.models.user import User
from app.parsers.base import ParseFailure
from app.parsers.registry import iter_events, make_parser
from app.storage.event_writer import EventRecord, SimpleEventRecord, bulk_copy_events

__all__ = ["IngestResult", "ingest_log_file"]

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class IngestResult:
    tenant_id: uuid.UUID
    user_id: uuid.UUID
    analysis_id: uuid.UUID
    n_events: int
    n_parse_failures: int


def _records(path: Path, source_type: str) -> tuple[list[SimpleEventRecord], int]:
    parser = make_parser(source_type)
    records: list[SimpleEventRecord] = []
    n_failures = 0
    with path.open("r", encoding="utf-8") as fh:
        for result in iter_events(source_type, fh, parser=parser):
            if isinstance(result, ParseFailure):
                n_failures += 1
                continue
            hot = result.hot_columns()
            enrichment = enrich_event(hot)
            records.append(
                SimpleEventRecord(
                    ts=hot["ts"],
                    source_type=hot["source_type"],
                    raw_line_no=hot["raw_line_no"],
                    ocsf_class_uid=hot["ocsf_class_uid"],
                    ocsf=result.model_dump(mode="json"),
                    principal=hot["principal"],
                    src_ip=hot["src_ip"],
                    dst_ip=hot["dst_ip"],
                    domain=hot["domain"],
                    url_path=hot["url_path"],
                    action=hot["action"],
                    http_method=hot["http_method"],
                    status_code=hot["status_code"],
                    bytes_in=hot["bytes_in"],
                    bytes_out=hot["bytes_out"],
                    user_agent=hot["user_agent"],
                    event_key=hot["event_key"],
                    enrichment=enrichment,
                )
            )
    log.info("ingest.parsed", path=str(path), n_events=len(records), n_failures=n_failures)
    return records, n_failures


def ingest_log_file(
    session: Session,
    *,
    path: Path,
    source_type: str = "zscaler",
    tenant_name: str = "M10 verification",
    filename: str | None = None,
) -> IngestResult:
    """Create a fresh tenant/user/upload/analysis and bulk-load `path` into `events`.

    One call = one brand-new tenant, so repeated calls (e.g. running the same scenario twice for
    the recurrence-detection check) never collide on uniqueness constraints and each gets its own
    clean `analysis_id` to build a graph over.
    """
    tenant = Tenant(name=tenant_name, pseudonym_salt=secrets.token_bytes(16))
    session.add(tenant)
    session.flush()

    with tenant_scope(session, tenant.id):
        user = User(
            tenant_id=tenant.id,
            email=f"verifier+{uuid.uuid4().hex[:8]}@corp.example",
            password_hash="!",  # noqa: S106 -- not a credential, never authenticated against
        )
        session.add(user)
        session.flush()

        upload = Upload(
            tenant_id=tenant.id,
            user_id=user.id,
            filename=filename or path.name,
            size_bytes=path.stat().st_size,
            sha256="0" * 64,
            storage_ref=f"{tenant.id}/{path.name}",
            detected_sources=[source_type],
        )
        session.add(upload)
        session.flush()

        analysis = Analysis(tenant_id=tenant.id, upload_id=upload.id, status="running")
        session.add(analysis)
        session.flush()
        session.commit()

    records, n_failures = _records(path, source_type)

    dsn = get_settings().database_url.replace("postgresql+psycopg://", "postgresql://")
    with psycopg.connect(dsn, autocommit=True) as raw_conn:
        # `SimpleEventRecord.enrichment` is typed `dict[str, Any] | None` (its own `__post_init__`
        # guarantees it is never actually `None` after construction) while the `EventRecord`
        # Protocol declares a bare `dict[str, Any]` -- a real, harmless structural mismatch, not a
        # runtime one; every record built by `_records` above always sets a real dict.
        bulk_copy_events(
            raw_conn,
            analysis_id=analysis.id,
            tenant_id=tenant.id,
            rows=cast(Iterable[EventRecord], records),
        )

    log.info(
        "ingest.done",
        tenant_id=str(tenant.id),
        analysis_id=str(analysis.id),
        n_events=len(records),
    )
    return IngestResult(
        tenant_id=tenant.id,
        user_id=user.id,
        analysis_id=analysis.id,
        n_events=len(records),
        n_parse_failures=n_failures,
    )
