"""Recompute `triage_verdicts.evidence_confidence` from each verdict's stored rubric grades.

`app.agent.confidence` is a pure function of the Judge's `rubric_assessment`, and every
judgement is already persisted verbatim in `triage_verdicts.tool_trace` as the
`submit_judgement` tool input. So a change to the weights or caps does not require re-running
triage against a live model — the inputs are on disk, and the score can simply be recomputed.
That property is worth keeping: it is what makes the number auditable rather than merely
reproducible, and it is why the scorer takes `(item, satisfied)` pairs instead of reaching into
the orchestrator's state.

Only rows whose trace actually carries a judgement are touched. A verdict from a `needs_review`
fallback never reached the Judge, has no grades, and must keep `NULL` — the column's whole
distinction between "not assessed" and "assessed and low" depends on this script not inventing
a score for it.

    python -m app.scripts.recompute_evidence_confidence [--dry-run]
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from sqlalchemy import select

from app.agent.confidence import RubricGrade, aggregate_evidence_confidence, evidence_confidence
from app.core.db import get_session_factory
from app.core.logging import get_logger
from app.models.triage_verdict import TriageVerdict

log = get_logger(__name__)

_SURVIVING = ("PASS", "REVISE")


class _Grade:
    """Structural stand-in for `JudgeRubricItem` — the trace holds plain JSON, not models."""

    __slots__ = ("item", "satisfied")

    def __init__(self, item: Any, satisfied: Any) -> None:
        self.item = item
        self.satisfied = satisfied


def _judgement_from_trace(trace: Any) -> list[dict[str, Any]] | None:
    if not isinstance(trace, list):
        return None
    for entry in trace:
        if not isinstance(entry, dict) or entry.get("tool_name") != "submit_judgement":
            continue
        payload = entry.get("tool_input")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                return None
        if isinstance(payload, dict) and isinstance(payload.get("verdicts"), list):
            return payload["verdicts"]
    return None


def recompute(*, dry_run: bool = False) -> dict[str, int]:
    session_factory = get_session_factory()
    changed = skipped = unchanged = 0
    with session_factory() as session:
        rows = session.execute(select(TriageVerdict)).scalars().all()
        for row in rows:
            verdicts = _judgement_from_trace(row.tool_trace)
            if not verdicts:
                skipped += 1
                continue

            # Mirrors the orchestrator exactly: score only the findings the Judge let through,
            # then take the mean. Reproducing the survival rule here rather than the score alone
            # is the point — a divergence would silently produce numbers the live path never would.
            per_finding = [
                evidence_confidence(
                    RubricGrade.from_items(
                        [
                            _Grade(g.get("item"), g.get("satisfied"))
                            for g in (v.get("rubric_assessment") or [])
                            if isinstance(g, dict)
                        ]
                    )
                )
                for v in verdicts
                if isinstance(v, dict) and v.get("decision") in _SURVIVING
            ]
            result = aggregate_evidence_confidence(per_finding)
            if result is None:
                skipped += 1
                continue

            if row.evidence_confidence == result.score and row.evidence_confidence_band == result.band:
                unchanged += 1
                continue

            log.info(
                "recompute.updated",
                verdict_id=str(row.id),
                before=row.evidence_confidence,
                after=result.score,
                band=result.band,
            )
            if not dry_run:
                row.evidence_confidence = result.score
                row.evidence_confidence_band = result.band
                row.evidence_confidence_basis = result.as_basis()
            changed += 1

        if not dry_run:
            session.commit()

    summary = {"changed": changed, "unchanged": unchanged, "skipped_no_judgement": skipped}
    log.info("recompute.done", dry_run=dry_run, **summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="report without writing")
    args = parser.parse_args()
    print(json.dumps(recompute(dry_run=args.dry_run)))


if __name__ == "__main__":
    main()
