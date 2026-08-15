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
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence
from typing import Any

from app.detection.signal.constants import ENTITY_USER, RARITY_MAX_ORG_EVENT_COUNT, SIGNAL_RARITY
from app.detection.signal.drafts import SignalDraft, cap_evidence
from app.detection.signal.events_dao import EventRow, rows_with_domain

__all__ = ["detect_rarity"]


def detect_rarity(rows: Sequence[EventRow]) -> list[SignalDraft]:
    domain_rows = list(rows_with_domain(rows))

    org_wide_count: Counter[str] = Counter(r.domain for r in domain_rows if r.domain)

    pairs: dict[tuple[str, str], list[EventRow]] = defaultdict(list)
    for row in domain_rows:
        if row.principal is None or row.domain is None:
            continue
        pairs[(row.principal, row.domain)].append(row)

    drafts: list[SignalDraft] = []
    for (principal, domain), pair_rows in pairs.items():
        count = org_wide_count[domain]
        if count > RARITY_MAX_ORG_EVENT_COUNT:
            continue

        domain_rarity = 1.0 / (1.0 + count)
        ordered = sorted(pair_rows, key=lambda r: r.ts)
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
