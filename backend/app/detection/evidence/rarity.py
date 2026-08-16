"""Rarity / first-seen (docs/04 §L2 "Rarity / first-seen").

```
domain_rarity = 1 / (1 + org_wide_event_count(domain))
user_novelty  = 1 if (principal, domain) unseen in baseline window else 0
```

`org_wide_event_count(domain)` is counted within one analysis -- each `analyses` row is one
uploaded log file (docs/02); there is no persisted cross-analysis history to count against yet
(`analyst_feedback.mark_benign_baseline`, docs/02, is the seam a future milestone would use to
build one). "Org-wide" therefore means "across every principal's traffic in this file," which
is the only population actually available.

## `user_novelty` is honestly close to a tautology today, and this module says so rather than
## hiding it

"Unseen in baseline window" presupposes a baseline period distinct from a "now" being scored.
A single static uploaded file has no such split -- there is no live "current moment," only
"everything in the file." The only baseline available for a `(principal, domain)` pair's first
occurrence is *the same file's own history strictly before that occurrence* -- which makes
every pair's first-ever appearance novel by construction, every time, for every pair. That is
not a bug in this module; it is what "baseline" can mean for a batch analysis with no persisted
prior state. `user_novelty` is still computed and written into `explanation` (so the field is
in place, unchanged, the day a real cross-analysis baseline exists upstream), but it is
`domain_rarity` -- not `user_novelty` -- that actually decides whether a signal gets written
here, exactly because novelty alone does not discriminate "an employee tried a new SaaS tool"
from "a beacon called a domain nobody in the org has ever heard of." Pairing the two, per
docs/04's own framing, is what makes a first-time visit to a *rare* domain worth a human's
attention and a first-time visit to a popular one not.

`RARITY_MAX_ORG_EVENT_COUNT` (`constants.py`) is the absolute-count threshold this module uses
to decide "rare enough to write a signal over" -- see that module's docstring for why an
absolute count, not a percentile of this analysis's own domain distribution, was chosen, and
the honestly-reported consequence: a high-volume beacon can out-count its way past this
threshold and `signal.rarity` will not fire for it, even while `signal.beaconing`/`signal.dga`
do.

## Evidence extraction is where change 1's baseline store actually pays off

Everything above (`domain_rarity`, `org_wide_event_count`, `user_novelty`) is file-relative --
"rare within this upload" -- and stays exactly as it is for the `SignalDraft`/`signals` path,
unchanged by this module's own design. `raw_evidence_rarity` is the *new* half: it asks
`app.baseline.resolve.contact_counts` (docs/v2_migration change 1) for the same `(principal,
domain)` pair's contact counts at **user, department, and org scope**, across the tenant's
six-month history -- "zero for Alice, one for Finance, four org-wide," the migration's own
example, rather than "three hits in this one file." `measurements` carries the three raw counts;
`historical` carries the first-seen flag per scope plus a baseline-relative rarity score --
deliberately named `baseline_domain_rarity`, never `domain_rarity`, so the two are never
confused for the same number computed two ways.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence
from typing import Any

from app.detection.evidence.constants import (
    ENTITY_USER,
    EXTRACTOR_RARITY,
    RARITY_MAX_ORG_EVENT_COUNT,
    SIGNAL_RARITY,
)
from app.detection.evidence.drafts import SignalDraft, cap_evidence, cap_evidence_rows
from app.detection.evidence.events_dao import EventRow, rows_with_domain
from app.detection.evidence.payload import ContactQuery, RawEvidence

__all__ = ["detect_rarity", "raw_evidence_rarity"]


def _fired_pairs(rows: Sequence[EventRow]) -> list[tuple[str, str, list[EventRow], int]]:
    """`(principal, domain, ordered_rows, org_wide_event_count_this_file)` for every pair that
    clears `RARITY_MAX_ORG_EVENT_COUNT` -- shared by `detect_rarity` and `raw_evidence_rarity` so
    evidence generation rides the same file-relative gate the `signals` row does (CLAUDE.md rule
    1; same rationale as `beaconing.raw_evidence_beaconing`'s own docstring)."""
    domain_rows = list(rows_with_domain(rows))
    org_wide_count: Counter[str] = Counter(r.domain for r in domain_rows if r.domain)

    pairs: dict[tuple[str, str], list[EventRow]] = defaultdict(list)
    for row in domain_rows:
        if row.principal is None or row.domain is None:
            continue
        pairs[(row.principal, row.domain)].append(row)

    fired: list[tuple[str, str, list[EventRow], int]] = []
    for (principal, domain), pair_rows in pairs.items():
        count = org_wide_count[domain]
        if count > RARITY_MAX_ORG_EVENT_COUNT:
            continue
        fired.append((principal, domain, sorted(pair_rows, key=lambda r: r.ts), count))
    return fired


def detect_rarity(rows: Sequence[EventRow]) -> list[SignalDraft]:
    drafts: list[SignalDraft] = []
    for principal, domain, ordered, count in _fired_pairs(rows):
        domain_rarity = 1.0 / (1.0 + count)
        first_seen, last_seen = ordered[0].ts, ordered[-1].ts

        evidence_ids, truncated = cap_evidence([(r.ts, r.id) for r in ordered])
        explanation: dict[str, Any] = {
            "principal": principal,
            "domain": domain,
            "domain_rarity": domain_rarity,
            "org_wide_event_count": count,
            "user_novelty": True,  # see module docstring -- true by construction today
            "first_seen": first_seen.isoformat(),
            "n_events_by_principal": len(ordered),
            "rare_count_threshold": RARITY_MAX_ORG_EVENT_COUNT,
            "evidence_truncated": truncated,
        }
        drafts.append(
            SignalDraft(
                detector_key=SIGNAL_RARITY,
                entity_type=ENTITY_USER,
                entity_value=principal,
                raw_score=domain_rarity,
                confidence_raw=domain_rarity,
                window_start=first_seen,
                window_end=last_seen,
                evidence_event_ids=evidence_ids,
                explanation=explanation,
            )
        )
    return drafts


def raw_evidence_rarity(rows: Sequence[EventRow]) -> list[RawEvidence]:
    """`EvidencePayload` measurements for every pair `detect_rarity` also fires a `signals` row
    for. `measurements` carries only the counts (baseline-resolved in `resolve_evidence.py`, this
    function's own docstring) -- deliberately empty of `domain_rarity`/`org_wide_event_count`
    (the file-relative versions, which stay on the `SignalDraft` explanation only)."""
    raw: list[RawEvidence] = []
    for principal, domain, ordered, _count in _fired_pairs(rows):
        first_seen, last_seen = ordered[0].ts, ordered[-1].ts
        _event_ids, line_numbers, truncated = cap_evidence_rows(ordered)
        raw.append(
            RawEvidence(
                extractor=EXTRACTOR_RARITY,
                entity={"type": ENTITY_USER, "value": principal, "domain": domain},
                window=(first_seen, last_seen),
                measurements={
                    "n_events_by_principal": len(ordered),
                    "evidence_truncated": truncated,
                },
                contributing_line_numbers=line_numbers,
                contact_query=ContactQuery(user=principal, domain=domain),
            )
        )
    return raw
