"""`EvidencePayload` -- the output contract every extractor in this package produces
(docs/v2_migration/MIGRATION-01-evidence-first.md, change 2, "L2 -> deterministic evidence
extractors").

## Old contract vs. new contract

A detector used to emit a `signals` row with a calibrated score (`app.detection.evidence.drafts.
SignalDraft`, unchanged, still produced alongside this new contract -- see each detector
module's own docstring). An extractor now *also* emits an `EvidencePayload`: raw measurements
plus historical context, which travels to the LLM intact rather than being collapsed into one
score. Both outputs exist side by side; this module owns only the new one.

## Why three stages, not one dataclass

Building an `EvidencePayload` needs two things a single detector function cannot supply on its
own:

1. **A baseline lookup** (`app.baseline.resolve.percentile_for` / `contact_counts`), which needs
   a `Session` and `tenant_id` -- exactly the reason `events_dao.py` is the only DB-touching
   module in this package's *old* half. Keeping every `detect_*`/`raw_evidence_*` function pure
   and DB-free is what makes `tests/test_evidence_*.py` fast unit tests instead of integration
   tests (module docstring of `drafts.py` states the same rationale for `SignalDraft`).
2. **Visibility across every extractor's output for this analysis**, for two things a single
   extractor cannot decide about its own findings alone: a deterministic `evidence_id` sequence
   (needs the full ordered set) and nomination de-duplication (needs to know what every *other*
   extractor already nominated).

So there are three stages, mirroring `SignalDraft`'s own draft/finalize split one level further:

```
detect_*(rows) -> RawEvidence            (pure, no DB -- this module's extractor functions)
resolve_evidence(session, ...) -> EvidenceDraft   (DB: baseline lookups, per RawEvidence)
finalize_evidence(drafts) -> EvidencePayload       (pure: id assignment + nomination dedup)
```

`RawEvidence.baseline_queries` describes *what* baseline lookup each measurement needs
(entity/metric/value) without performing it -- `resolve_evidence.py` is the only module here that
calls `app.baseline.resolve`, the same separation `events_dao.py` already draws for the
`signals` path.

## `evidence_id` scheme: `"EVIDENCE-{n}"`, sequential in a fixed, deterministic order

Stable and citable **within one analysis run**: the LLM cites `[EVIDENCE-14]` and a later phase
resolves that back to this payload (docs/v2_migration change 2 and change 7's `[EVIDENCE-14]`
citation namespace). Determinism comes from two ordering rules applied by `finalize_evidence`,
neither of which depends on wall-clock time, dict iteration order, or any other incidental
ordering:

1. **Extractor order** -- `EXTRACTOR_ORDER` below, the same fixed sequence
   `app.detection.evidence.run.run_evidence_layer` already runs detectors in (beaconing, dga,
   burst, rarity, stl, url_entropy).
2. **Within one extractor**, drafts are sorted by `(entity["type"], entity["value"],
   window[0], window[1])` -- every field already on the draft, so no extractor has to hand back
   pre-sorted output itself.

`n` starts at 1 and increases by exactly one per payload in that order, so re-running
`finalize_evidence` on an identical set of `RawEvidence`/`EvidenceDraft` inputs (same rows, same
baseline state) always assigns the same ids to the same findings -- `tests/test_evidence_
payload.py::test_evidence_id_is_stable_and_deterministic_across_two_runs` proves this directly.

## Cold start propagates, never coerced to a number

`app.baseline.resolve.PercentileResult.baseline_status` is `"insufficient_history"` whenever
`n_windows < MIN_WINDOWS_FOR_BASELINE`, and `.percentile` is `None` in that case -- never a
number computed from a handful of windows (that module's own docstring). `historical_from_
percentile` below is the *only* place a percentile-based extractor writes into `historical`, and
it passes `result.percentile` through unchanged (`None` stays `None`) alongside
`{prefix}_baseline_status` and `{prefix}_n_windows` -- so a cold-start entity's `EvidencePayload`
carries `"beaconing_percentile": None, "beaconing_baseline_status": "insufficient_history",
"beaconing_n_windows": 3` rather than silently dropping the field or fabricating a plausible-
looking value. The migration is explicit that the LLM must be told to weight deviations
accordingly given that signal -- it can only do that if the signal survives the trip.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from pydantic import BaseModel, ConfigDict

from app.baseline.resolve import PercentileResult
from app.detection.evidence.constants import (
    EXTRACTOR_BEACONING,
    EXTRACTOR_BURST,
    EXTRACTOR_DGA,
    EXTRACTOR_RARITY,
    EXTRACTOR_STL,
    EXTRACTOR_URL_ENTROPY,
)

__all__ = [
    "EXTRACTOR_ORDER",
    "NOMINATION_PERCENTILE_THRESHOLD",
    "BaselineQuery",
    "ContactQuery",
    "EvidenceDraft",
    "EvidencePayload",
    "RawEvidence",
    "historical_from_percentile",
]

# docs/v2_migration change 2: "an extractor sets nominates_candidate = true when its historical
# percentile exceeds 99.5" -- same bar `URL_PATH_PERCENTILE_THRESHOLD` (constants.py) already
# uses for a different purpose (whether url_path fires as a *signal* at all); declared
# independently here since the two thresholds gate different contracts and a future change to
# one must not silently move the other.
NOMINATION_PERCENTILE_THRESHOLD: Final[float] = 99.5

# Fixed extractor order for deterministic `evidence_id` assignment (module docstring) --
# matches `run.py`'s own detector-run order.
EXTRACTOR_ORDER: Final[tuple[str, ...]] = (
    EXTRACTOR_BEACONING,
    EXTRACTOR_DGA,
    EXTRACTOR_BURST,
    EXTRACTOR_RARITY,
    EXTRACTOR_STL,
    EXTRACTOR_URL_ENTROPY,
)


class EvidencePayload(BaseModel):
    """docs/v2_migration change 2's output contract, verbatim in field name and intent -- two
    types are widened from the migration doc's own illustrative `dict[str, float]`, deliberately:
    `measurements`/`historical` carry `Any`, not just `float`, because the doc's own follow-up
    text requires non-float entries in the same dicts it types as `dict[str, float]` (url_entropy
    "must include the literal path string" in `measurements`; a cold-start `historical` entry is
    `None`/a status string, never a fabricated float, per this module's own docstring). The doc's
    class sketch is illustrative, not a literal schema to satisfy at the cost of losing exactly
    the data the surrounding prose demands.
    """

    model_config = ConfigDict(frozen=True)

    evidence_id: str
    extractor: str
    entity: dict[str, str]
    window: tuple[datetime, datetime]
    measurements: dict[str, Any]
    historical: dict[str, Any]
    contributing_line_numbers: list[int]
    nominates_candidate: bool
    nomination_score: float | None = None


@dataclass(frozen=True, slots=True)
class BaselineQuery:
    """One `app.baseline.resolve.percentile_for` call a `RawEvidence` needs before it can become
    an `EvidenceDraft`. `historical_prefix` namespaces the resulting `{prefix}_percentile` /
    `{prefix}_baseline_status` / `{prefix}_n_windows` keys in `historical` so one `RawEvidence`
    can request more than one scope (burst's user/department/org three-scope lookup) without the
    keys colliding. `counts_toward_nomination=False` lets a query contribute historical context
    without being eligible to trigger `nominates_candidate` on its own (not used by any extractor
    in this milestone, but a query-level rather than draft-level flag since a future extractor
    requesting several scopes may only want one of them nomination-eligible)."""

    entity_type: str
    entity_value: str
    metric: str
    value: float
    historical_prefix: str
    counts_toward_nomination: bool = True


@dataclass(frozen=True, slots=True)
class ContactQuery:
    """`app.baseline.resolve.contact_counts` needs `(user, domain)`, not a metric/value pair --
    rarity's own baseline lookup, kept as a distinct type from `BaselineQuery` rather than forced
    into the same shape (`contact_counts` has no `PercentileResult`-style cold start; see
    `rarity.py`'s own docstring for why a missing `baseline_contacts` row is informative --
    "zero contacts" -- rather than "insufficient history")."""

    user: str
    domain: str


@dataclass(slots=True)
class RawEvidence:
    """Everything one extractor can compute about one finding *without* a database -- the
    DB-free half of the three-stage pipeline (module docstring). `baseline_queries` and
    `contact_query` describe what `resolve_evidence.py` still needs to look up; exactly one of
    them is populated for a given extractor (dga: neither -- see that module's docstring)."""

    extractor: str
    entity: dict[str, str]
    window: tuple[datetime, datetime]
    measurements: dict[str, Any]
    contributing_line_numbers: list[int]
    baseline_queries: tuple[BaselineQuery, ...] = ()
    contact_query: ContactQuery | None = None


@dataclass(slots=True)
class EvidenceDraft:
    """`RawEvidence` plus resolved `historical` context and nomination *eligibility* -- still
    missing `evidence_id` (needs the full per-analysis ordering) and the *final*
    `nominates_candidate` (needs cross-extractor de-duplication against every other draft's
    entity-window). `finalize_evidence` is what turns this into an `EvidencePayload`.
    """

    extractor: str
    entity: dict[str, str]
    window: tuple[datetime, datetime]
    measurements: dict[str, Any]
    historical: dict[str, Any]
    contributing_line_numbers: list[int]
    nomination_eligible: bool
    nomination_score: float | None = None


def historical_from_percentile(
    prefix: str, result: PercentileResult, *, value: float | None = None
) -> dict[str, Any]:
    """`{prefix}_percentile` / `{prefix}_baseline_status` / `{prefix}_n_windows` from a resolved
    `PercentileResult` -- the one place a percentile-based extractor writes into `historical`, so
    cold start propagates identically everywhere (module docstring, "Cold start propagates").
    `prefix=""` collapses to bare `percentile`/`baseline_status`/`n_windows` for a single-scope
    extractor; a non-empty prefix (burst's `"user"`/`"department"`/`"org"`) namespaces multiple
    scopes in the same `historical` dict.

    `value`, when given, also adds `{prefix}_ratio_vs_baseline = value / p50` (docs/v2_migration
    change 2's burst row: "ratio vs. user / dept / org baseline, percentile") -- `None` when the
    baseline has no usable `p50` to divide by (cold start, or a degenerate zero median), same
    non-coercion rule as `percentile` itself.
    """
    p = f"{prefix}_" if prefix else ""
    out: dict[str, Any] = {
        f"{p}percentile": result.percentile,
        f"{p}baseline_status": result.baseline_status,
        f"{p}n_windows": result.n_windows,
    }
    if value is not None:
        ratio = value / result.p50 if result.p50 else None
        out[f"{p}ratio_vs_baseline"] = ratio
    return out


def _sort_key(draft: EvidenceDraft) -> tuple[str, str, datetime, datetime]:
    return (
        draft.entity.get("type", ""),
        draft.entity.get("value", ""),
        draft.window[0],
        draft.window[1],
    )


def _windows_overlap(a: tuple[datetime, datetime], b: tuple[datetime, datetime]) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


def finalize_evidence(
    drafts: Sequence[EvidenceDraft],
    *,
    existing_candidate_windows: Sequence[tuple[str, str, datetime, datetime]] = (),
) -> list[EvidencePayload]:
    """The pure, final stage (module docstring): deterministic `evidence_id` assignment plus
    nomination de-duplication, across every extractor's drafts for one analysis at once.

    ## Ordering (the `evidence_id` scheme)

    Drafts are grouped by `extractor` in `EXTRACTOR_ORDER`, then sorted within each extractor by
    `_sort_key` (entity type, entity value, window start, window end) -- both fixed, neither
    dependent on input order or dict iteration, so two calls on an identical `drafts` sequence
    (in any order) always assign the same `EVIDENCE-{n}` to the same finding.

    ## Nomination de-duplication

    docs/v2_migration change 2: "an extractor sets `nominates_candidate = true` when its
    historical percentile exceeds 99.5 **and** no existing candidate already covers its
    entity-window." A draft is nomination-*eligible* the moment its own percentile crosses the
    threshold (each extractor decides that for itself, in `resolve_evidence.py`); this function
    resolves the *"no existing candidate already covers it"* half, which is inherently a
    cross-extractor, cross-analysis concern no single extractor can answer alone:

    - **Within this run**: processed in the same deterministic order as `evidence_id`
      assignment, so the *first* eligible draft for a given entity-window becomes the nomination
      and every later eligible draft whose window overlaps an already-claimed one for the *same*
      entity is suppressed (`nominates_candidate=False`, `nomination_score=None` -- the migration
      is explicit `nomination_score` is populated "only when `nominates_candidate`").
    - **Against the rest of the pipeline**: `existing_candidate_windows` lets a caller that
      already knows about non-evidence candidates (an L3 entity-window model's own findings, once
      a pipeline orchestrator wires that in -- out of this package's ownership, see `run.py`'s own
      module docstring on scope) suppress a nomination that would duplicate one of those too.
      Defaults to empty, which is the correct behaviour today: nothing outside this package's own
      evidence run is visible to it yet.
    """
    ordered: list[EvidenceDraft] = []
    by_extractor: dict[str, list[EvidenceDraft]] = {}
    for d in drafts:
        by_extractor.setdefault(d.extractor, []).append(d)
    for extractor in EXTRACTOR_ORDER:
        ordered.extend(sorted(by_extractor.get(extractor, ()), key=_sort_key))
    # Any extractor not in EXTRACTOR_ORDER (shouldn't happen; defensive) sorts last, grouped by
    # its own name, rather than being silently dropped.
    leftover_extractors = sorted(k for k in by_extractor if k not in EXTRACTOR_ORDER)
    for extractor in leftover_extractors:
        ordered.extend(sorted(by_extractor[extractor], key=_sort_key))

    claimed: list[tuple[str, str, tuple[datetime, datetime]]] = [
        (etype, evalue, (start, end)) for etype, evalue, start, end in existing_candidate_windows
    ]

    payloads: list[EvidencePayload] = []
    for i, draft in enumerate(ordered, start=1):
        evidence_id = f"EVIDENCE-{i}"
        entity_type = draft.entity.get("type", "")
        entity_value = draft.entity.get("value", "")

        nominates = False
        nomination_score = None
        if draft.nomination_eligible:
            covered = any(
                etype == entity_type
                and evalue == entity_value
                and _windows_overlap(window, draft.window)
                for etype, evalue, window in claimed
            )
            if not covered:
                nominates = True
                nomination_score = draft.nomination_score
                claimed.append((entity_type, entity_value, draft.window))

        payloads.append(
            EvidencePayload(
                evidence_id=evidence_id,
                extractor=draft.extractor,
                entity=draft.entity,
                window=draft.window,
                measurements=draft.measurements,
                historical=draft.historical,
                contributing_line_numbers=draft.contributing_line_numbers,
                nominates_candidate=nominates,
                nomination_score=nomination_score,
            )
        )
    return payloads
