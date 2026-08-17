"""Query helper behind `GET /api/tier2/detector-reliability` (Tier 2 chart 3) — per-detector
confirm/dismiss counts pooled across **every tenant's** analyst feedback. This is the highest-
value cross-tenant learning signal Tier 2 has: it is what lets an MDR say "this detector is
noisy everywhere," a claim no single tenant's data can support on its own.

## This is a deliberate, reviewed exception to tenant scoping — read before touching this file

`app.models.base`'s module docstring ("Known boundary") documents two real tenant-isolation
bugs found and fixed elsewhere in this codebase, both the same shape this query uses on
purpose: an aggregate/JOIN-only `SELECT` where the only tenant-scoped table
(`app.models.incident.Incident`) never appears in the statement's *top-level selected
columns*, only in a `.join()`. SQLAlchemy's `with_loader_criteria` hook
(`_touches_tenant_scoped_table`, walking `ORMExecuteState.all_mappers`) is derived from
selected-column ownership, not from everything a query's `FROM`/`JOIN` clause touches, so
that shape is invisible to the automatic tenant filter — `app.learning.feedback.
_tenant_feedback_count` was fixed by adding an explicit `.where(Incident.tenant_id ==
tenant_id)` once this was found in production.

This function is the mirror image of that fix, on purpose: it uses hand-written `text()` SQL
(itself outside the ORM hook's reach, per the same "Known boundary" docstring) against
`analyst_feedback` / `triage_verdicts` / `incidents` / `signals` directly, and **deliberately
does not add a `tenant_id` predicate at all**. Detector reliability pooled across every
customer is the literal point of this chart — an explicit tenant filter here would not close a
leak, it would delete the feature. `GET /api/tier2/*` is already documented (see
`app.api.tier2`'s module docstring) as the one route family in this application that is
intentionally not tenant-scoped, for the same reason `tier2_signatures` carries no `tenant_id`
column at all: cross-tenant comparison only exists if more than one tenant's data is in the
query. This module is that same design decision applied to real operational tables instead of
the anonymized `tier2_signatures` table, which is exactly why it needs to be *this* explicit
about it rather than inheriting the exemption implicitly.

## Detector attribution and the confirm/dismiss label

`analyst_feedback` records a verdict on a whole *incident*, not on an individual detector --
same fan-out `app.learning.feedback_data.labeled_examples` already uses for the (single-
tenant) weight-tuning consumer: every `detector_key` among `incidents.signal_ids`'s
contributing signals inherits that incident's outcome label. "Confirmed" / "dismissed" reuse
the identical `effective_label` rule that module documents (`corrected_disposition` overrides
the verdict's own `disposition` when present; `disposition == 'true_positive'` is a confirm,
anything else is a dismiss) so this chart's numbers are the same precision signal
`app.learning.weights.retune_detector_weights` already computes per tenant, just pooled
instead of scoped -- not a second, differently-defined notion of "confirm" invented here.
"""

from __future__ import annotations

from typing import NamedTuple

from sqlalchemy import text
from sqlalchemy.orm import Session


class DetectorReliabilityRow(NamedTuple):
    detector_key: str
    detector_layer: str
    confirmed: int
    dismissed: int


class DetectorReliabilityResult(NamedTuple):
    total_tenants: int
    items: list[DetectorReliabilityRow]


# No request-supplied values anywhere in this query -- nothing to bind, nothing to interpolate.
# See module docstring for why this deliberately carries no tenant_id predicate.
_DETECTOR_RELIABILITY_QUERY = """
    SELECT
        s.detector_key,
        s.detector_layer,
        COUNT(*) FILTER (
            WHERE COALESCE(af.corrected_disposition, tv.disposition) = 'true_positive'
        ) AS confirmed,
        COUNT(*) FILTER (
            WHERE COALESCE(af.corrected_disposition, tv.disposition) != 'true_positive'
        ) AS dismissed
    FROM analyst_feedback af
    JOIN triage_verdicts tv ON af.verdict_id = tv.id
    JOIN incidents i ON tv.incident_id = i.id
    JOIN signals s ON s.id = ANY(i.signal_ids)
    GROUP BY s.detector_key, s.detector_layer
    ORDER BY (COUNT(*)) DESC, s.detector_key
"""

_TOTAL_TENANTS_QUERY = """
    SELECT COUNT(DISTINCT i.tenant_id)
    FROM analyst_feedback af
    JOIN triage_verdicts tv ON af.verdict_id = tv.id
    JOIN incidents i ON tv.incident_id = i.id
"""


def list_detector_reliability(session: Session) -> DetectorReliabilityResult:
    rows = session.execute(text(_DETECTOR_RELIABILITY_QUERY)).all()
    total_tenants = session.execute(text(_TOTAL_TENANTS_QUERY)).scalar_one()
    return DetectorReliabilityResult(
        total_tenants=total_tenants,
        items=[
            DetectorReliabilityRow(
                detector_key=row.detector_key,
                detector_layer=row.detector_layer,
                confirmed=row.confirmed,
                dismissed=row.dismissed,
            )
            for row in rows
        ],
    )
