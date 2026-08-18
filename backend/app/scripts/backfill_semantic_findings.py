"""Recompute `analyses.domain_semantic_findings` for analyses that are missing it.

Calls exactly the function `app.pipeline.stages.triage` calls — `_compute_domain_semantic_
findings` over `_compute_notable_destinations` — so a backfilled analysis is indistinguishable
from one the pipeline produced. Nothing is reimplemented here; this module only chooses *which*
analyses to run it for.

**Why this exists rather than re-running triage.** The obvious way to restore this column is to
put every analysis back through the triage stage. That re-triages every incident as well, which
is the expensive part of the pipeline by a wide margin — roughly $3 per analysis against a few
cents for this one call — and rewrites verdicts that are already correct, including their
`evidence_confidence`. The semantic findings are a self-contained product of one LLM call over
deterministic inputs, so recomputing just that is both far cheaper and much less destructive.

Only analyses whose findings are empty are touched, so this is safe to re-run and will not spend
a second time on work that already succeeded. `--all` overrides that for a deliberate refresh.

    python -m app.scripts.backfill_semantic_findings [--all] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import text, update

from app.api.analyses import _compute_domain_semantic_findings, _compute_notable_destinations
from app.core.config import get_settings
from app.core.db import get_session_factory
from app.core.logging import get_logger
from app.models.analysis import Analysis
from app.models.base import tenant_scope

log = get_logger(__name__)


def _target_analyses(session, *, refresh_all: bool) -> list[tuple[uuid.UUID, uuid.UUID]]:
    """Completed analyses, optionally only those with nothing stored yet.

    Restricted to `status='complete'`: a failed or still-running analysis may have no events to
    compute over, and spending an LLM call to confirm that is waste.
    """
    where = "status = 'complete'"
    if not refresh_all:
        where += " AND jsonb_array_length(domain_semantic_findings) = 0"
    rows = session.execute(text(f"SELECT id, tenant_id FROM analyses WHERE {where}")).all()  # noqa: S608
    return [(r[0], r[1]) for r in rows]


def backfill(*, refresh_all: bool = False, dry_run: bool = False) -> dict[str, int]:
    settings = get_settings()
    if not settings.llm_enabled:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not configured, so every finding would degrade to [] and this "
            "run would silently do nothing. Configure a key or do not run this."
        )

    session_factory = get_session_factory()
    filled = empty = 0
    with session_factory() as session:
        targets = _target_analyses(session, refresh_all=refresh_all)
        log.info("backfill.start", analyses=len(targets), refresh_all=refresh_all)

        for analysis_id, tenant_id in targets:
            with tenant_scope(session, tenant_id):
                destinations = _compute_notable_destinations(session, tenant_id, analysis_id)
                findings = _compute_domain_semantic_findings(
                    session, tenant_id, analysis_id, destinations
                )
                if not findings:
                    # A correct, reportable answer: an analysis with no rare or first-seen
                    # destinations genuinely has nothing to say. Counted separately from a
                    # success so a run of all-empties is visible rather than looking like work.
                    empty += 1
                    log.info(
                        "backfill.no_findings",
                        analysis_id=str(analysis_id),
                        destinations=len(destinations),
                    )
                    continue

                filled += 1
                log.info(
                    "backfill.computed", analysis_id=str(analysis_id), findings=len(findings)
                )
                if dry_run:
                    continue

                session.execute(
                    update(Analysis)
                    .where(Analysis.id == analysis_id)
                    .values(
                        domain_semantic_findings=[f.model_dump(mode="json") for f in findings],
                        domain_semantics_generated_at=datetime.now(UTC),
                    )
                )
                session.commit()

    summary = {"analyses": len(targets), "filled": filled, "no_findings": empty}
    log.info("backfill.done", dry_run=dry_run, **summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--all",
        action="store_true",
        dest="refresh_all",
        help="recompute even for analyses that already have findings",
    )
    parser.add_argument("--dry-run", action="store_true", help="compute and report, do not write")
    args = parser.parse_args()
    print(json.dumps(backfill(refresh_all=args.refresh_all, dry_run=args.dry_run)))


if __name__ == "__main__":
    main()

