"""DB-touching middle stage of the evidence pipeline (`app.detection.evidence.payload`'s module
docstring, "why three stages, not one dataclass"): turns each extractor's DB-free `RawEvidence`
into an `EvidenceDraft` by actually running its declared baseline lookups against
`app.baseline.resolve` -- the only module in the *new* half of this package that imports
`app.baseline`/needs a `Session`, mirroring `events_dao.py`'s role for the old `SignalDraft`
half.

Nomination *eligibility* (not the final `nominates_candidate` -- that needs cross-extractor
de-duplication, `payload.finalize_evidence`'s job) is decided here, per `RawEvidence`, the moment
its baseline lookups are in hand: docs/v2_migration change 2's rule is "historical percentile
exceeds 99.5", so a query only counts if `BaselineQuery.counts_toward_nomination` is set (the
default) and its resolved percentile actually exceeds `NOMINATION_PERCENTILE_THRESHOLD` --
`None` (cold start) never counts, by construction (`None > 99.5` is simply never true).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy.orm import Session

from app.baseline.resolve import contact_counts, percentile_for
from app.detection.evidence.payload import (
    NOMINATION_PERCENTILE_THRESHOLD,
    EvidenceDraft,
    RawEvidence,
    historical_from_percentile,
)

__all__ = ["resolve_evidence"]


class _Resolved:
    """`(extra_measurements, historical, nomination_eligible, nomination_score)` -- the four
    things a baseline lookup can contribute to an `EvidenceDraft`. `extra_measurements` is merged
    into `raw.measurements` (not just `historical`) because rarity's contact *counts* are
    themselves the migration's own `measurements` column for that extractor (docs/v2_migration
    change 2's table: "rarity | contact counts at user, dept, org scope | first-seen flags per
    scope, percentile") -- and those counts are only known once `contact_counts` has actually run,
    which no `RawEvidence` (DB-free by construction) can do for itself."""

    __slots__ = ("extra_measurements", "historical", "nomination_eligible", "nomination_score")

    def __init__(
        self,
        extra_measurements: dict[str, Any],
        historical: dict[str, Any],
        nomination_eligible: bool,
        nomination_score: float | None,
    ) -> None:
        self.extra_measurements = extra_measurements
        self.historical = historical
        self.nomination_eligible = nomination_eligible
        self.nomination_score = nomination_score


def _resolve_baseline_queries(
    session: Session, tenant_id: uuid.UUID, raw: RawEvidence
) -> _Resolved:
    """`nomination_score` is the *value's own percentile / 100*, clamped, for whichever query
    first crosses the nomination threshold (there is at most one candidate percentile per
    extractor in this milestone; the first eligible query wins deterministically since
    `raw.baseline_queries` is a fixed tuple in extractor-authored order, not a set)."""
    historical: dict[str, Any] = {}
    eligible = False
    nomination_score: float | None = None
    for query in raw.baseline_queries:
        result = percentile_for(
            session, tenant_id, query.entity_type, query.entity_value, query.metric, query.value
        )
        historical.update(
            historical_from_percentile(query.historical_prefix, result, value=query.value)
        )
        if (
            query.counts_toward_nomination
            and result.percentile is not None
            and result.percentile > NOMINATION_PERCENTILE_THRESHOLD
        ):
            eligible = True
            if nomination_score is None:
                nomination_score = min(1.0, result.percentile / 100.0)
    return _Resolved({}, historical, eligible, nomination_score)


def _resolve_contact_query(session: Session, tenant_id: uuid.UUID, raw: RawEvidence) -> _Resolved:
    """Rarity's own baseline lookup (`ContactQuery`, resolved via `contact_counts` rather than
    `percentile_for` -- `payload.ContactQuery`'s own docstring for why). Nomination-eligible
    exactly when the domain has never been contacted **org-wide** in the baseline period
    (`org.is_first_contact`) -- `rarity.py`'s own docstring justifies treating that as this
    extractor's analogue of "exceeds the 99.5th percentile": a domain nobody in the org has
    contacted in six months of history is about as rare as `contact_counts` can report."""
    assert raw.contact_query is not None
    counts = contact_counts(session, tenant_id, raw.contact_query.user, raw.contact_query.domain)
    extra_measurements: dict[str, Any] = {
        "user_contact_count": counts.user.contact_count,
        "department_contact_count": counts.department.contact_count,
        "org_contact_count": counts.org.contact_count,
    }
    historical: dict[str, Any] = {
        "user_first_seen": counts.user.is_first_contact,
        "department_first_seen": counts.department.is_first_contact,
        "org_first_seen": counts.org.is_first_contact,
        "department_scope_value": counts.department.scope_value,
        # Baseline-relative rarity, deliberately distinct from `SignalDraft.explanation[
        # "domain_rarity"]` (file-relative -- `rarity.py`'s own docstring): computed from
        # `counts.org.contact_count`, the six-month history, never the uploaded file.
        "baseline_domain_rarity": 1.0 / (1.0 + counts.org.contact_count),
    }
    eligible = counts.org.is_first_contact
    nomination_score = 1.0 if eligible else None
    return _Resolved(extra_measurements, historical, eligible, nomination_score)


def resolve_evidence(
    session: Session, tenant_id: uuid.UUID, raw_evidence: Sequence[RawEvidence]
) -> list[EvidenceDraft]:
    """`RawEvidence` -> `EvidenceDraft` for every extractor's findings, in the order given --
    ordering is not this function's concern (`payload.finalize_evidence` re-sorts deterministically
    before assigning `evidence_id`s), so this simply resolves each entry independently.
    """
    drafts: list[EvidenceDraft] = []
    for raw in raw_evidence:
        if raw.contact_query is not None:
            resolved = _resolve_contact_query(session, tenant_id, raw)
        elif raw.baseline_queries:
            resolved = _resolve_baseline_queries(session, tenant_id, raw)
        else:
            # dga: "— (probability is already the answer)" (docs/v2_migration change 2's own
            # table) -- no baseline lookup, empty historical, never nomination-eligible.
            resolved = _Resolved({}, {}, False, None)

        drafts.append(
            EvidenceDraft(
                extractor=raw.extractor,
                entity=raw.entity,
                window=raw.window,
                measurements={**raw.measurements, **resolved.extra_measurements},
                historical=resolved.historical,
                contributing_line_numbers=raw.contributing_line_numbers,
                nomination_eligible=resolved.nomination_eligible,
                nomination_score=resolved.nomination_score,
            )
        )
    return drafts
