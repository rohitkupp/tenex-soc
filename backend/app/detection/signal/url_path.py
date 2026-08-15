"""URL path analysis (docs/04 §L2 "URL path analysis", REWRITTEN section — new detector).

```
path_entropy   = Shannon entropy of the path string
segment_random = fraction of path segments matching a high-entropy token pattern
                 (base64-ish or hex-ish, length >= 12)
Flag (entity, domain) pairs whose mean path_entropy or segment_random sits above the 99.5th
percentile of the org-wide distribution for that domain's category.
```

## Why this exists (restated from docs/04)

C2 frameworks commonly encode a beacon ID or exfiltrated data in the URL path rather than the
query string — the L1 Sigma rule for credentials already covers the query string
(`app/detection/rules/*.yml`), but a path like `/api/v2/c7f3a9e1b2a4.../checkin` reads as ordinary
REST while carrying near-maximal path entropy for its length. This scores request *structure*
(entropy, token randomness), not content, so it needs no domain-category or threat-intel lookup to
work — it works the same on a domain nobody has ever seen before as on one seen every day.

## Grouped by `(src_ip, domain)`, matching `beaconing.py`

docs/04 says "(entity, domain) pairs" without naming the entity dimension. `beaconing.py` already
groups by `(src_ip, domain)`, and docs/04's own "§Fusion" note for this detector — "a domain
flagged by both beaconing and URL path analysis is materially stronger evidence than either
alone" — only means something if the two detectors are scoring the *same* pairs to begin with;
grouping by `(principal, domain)` instead would make that fusion claim compare two different
population definitions. This module therefore reuses beaconing's own entity dimension.

## Scored against the domain's own org-wide population, not its "category"

docs/04 says "org-wide distribution for that domain's category." `EventRow` (`events_dao.py`) is
deliberately narrow — five/six hot columns shared by every L2 detector — and carries no
URL-category field (ZScaler's `urlcategory` lives in `events.ocsf` JSONB, not a hot column,
docs/02); widening every detector's row type for one detector's category lookup was judged not
worth the coupling. This module instead scores each `(src_ip, domain)` pair against the org-wide
population of *every other pair on that same domain* — a strictly finer-grained, more specific
population than "domain's category" (no cross-domain noise from other sites that merely share a
threat-intel category), at the cost of needing enough traffic on a single domain to form a
population, which `URL_PATH_MIN_PAIRS_FOR_PERCENTILE` gates explicitly rather than silently
scoring against too few points to mean anything.

`explanation`: `{mean_path_entropy, segment_random_ratio, sample_paths}` — `sample_paths`
truncated to `docs/06`'s 256-character field-truncation rule before this ever reaches a prompt.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Sequence
from typing import Any

import numpy as np

from app.detection.features import shannon_entropy
from app.detection.signal.constants import (
    ENTITY_SRC_IP,
    SIGNAL_URL_PATH,
    URL_PATH_MIN_PAIRS_FOR_PERCENTILE,
    URL_PATH_MIN_REQUESTS,
    URL_PATH_PERCENTILE_THRESHOLD,
    URL_PATH_SAMPLE_COUNT,
    URL_PATH_SEGMENT_MIN_LEN,
    URL_PATH_TOKEN_MIN_DISTINCT_CHARS,
    URL_PATH_TRUNCATE_CHARS,
)
from app.detection.signal.drafts import SignalDraft, cap_evidence
from app.detection.signal.events_dao import EventRow, rows_with_domain

__all__ = ["detect_url_path"]

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_BASE64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")


def _is_high_entropy_token(segment: str) -> bool:
    """`length >= 12`, enough distinct characters to rule out a degenerate repeat, and either a
    pure hex charset or a mixed-case base64 charset -- see `constants.py`'s
    `URL_PATH_TOKEN_MIN_DISTINCT_CHARS` docstring for why charset membership alone is too
    permissive (a hyphenated English phrase is entirely within the base64url charset) and why
    mixed-case is the base64 branch's own guard against exactly that.
    """
    if len(segment) < URL_PATH_SEGMENT_MIN_LEN:
        return False
    if len(set(segment)) < URL_PATH_TOKEN_MIN_DISTINCT_CHARS:
        return False
    if all(c in _HEX_CHARS for c in segment):
        return True
    if all(c in _BASE64_CHARS for c in segment):
        return any(c.isupper() for c in segment) and any(c.islower() for c in segment)
    return False


def _segment_random_ratio(path: str) -> float:
    segments = [seg for seg in path.split("/") if seg]
    if not segments:
        return 0.0
    return sum(1 for seg in segments if _is_high_entropy_token(seg)) / len(segments)


def _pair_stats(rows: Sequence[EventRow]) -> tuple[float, float, list[str]]:
    """`(mean_path_entropy, mean_segment_random_ratio, sample_paths)` for one `(src_ip, domain)`
    pair's rows -- rows with no `url_path` are excluded from the means (nothing to score), not
    treated as `0.0` (which would silently dilute a pair with genuinely random paths by however
    many of its requests happened to log no path)."""
    entropies: list[float] = []
    ratios: list[float] = []
    samples: list[str] = []
    for row in rows:
        if not row.url_path:
            continue
        entropies.append(shannon_entropy(list(row.url_path)))
        ratios.append(_segment_random_ratio(row.url_path))
        if len(samples) < URL_PATH_SAMPLE_COUNT:
            samples.append(row.url_path[:URL_PATH_TRUNCATE_CHARS])
    mean_entropy = statistics.fmean(entropies) if entropies else 0.0
    mean_ratio = statistics.fmean(ratios) if ratios else 0.0
    return mean_entropy, mean_ratio, samples


def detect_url_path(rows: Sequence[EventRow]) -> list[SignalDraft]:
    pairs: dict[tuple[str, str], list[EventRow]] = defaultdict(list)
    for row in rows_with_domain(rows):
        if row.src_ip is None:
            continue
        pairs[(row.src_ip, row.domain or "")].append(row)

    # Per-pair stats, keyed by domain so each domain's own org-wide population (module docstring)
    # can be assembled in a second pass.
    pair_entries: dict[str, list[tuple[str, float, float, list[str], list[EventRow]]]] = (
        defaultdict(list)
    )
    for (src_ip, domain), pair_rows in pairs.items():
        if len(pair_rows) < URL_PATH_MIN_REQUESTS:
            continue
        mean_entropy, mean_ratio, samples = _pair_stats(pair_rows)
        pair_entries[domain].append((src_ip, mean_entropy, mean_ratio, samples, pair_rows))

    drafts: list[SignalDraft] = []
    for domain, entries in pair_entries.items():
        if len(entries) < URL_PATH_MIN_PAIRS_FOR_PERCENTILE:
            continue
        entropy_population = [e[1] for e in entries]
        ratio_population = [e[2] for e in entries]
        entropy_cutoff = float(np.percentile(entropy_population, URL_PATH_PERCENTILE_THRESHOLD))
        ratio_cutoff = float(np.percentile(ratio_population, URL_PATH_PERCENTILE_THRESHOLD))

        for src_ip, mean_entropy, mean_ratio, samples, pair_rows in entries:
            if mean_entropy <= entropy_cutoff and mean_ratio <= ratio_cutoff:
                continue

            ordered = sorted(pair_rows, key=lambda r: r.ts)
            evidence_ids, truncated = cap_evidence([(r.ts, r.id) for r in ordered])
            # A score in [0, 1]: how far each statistic sits past its own cutoff, relative to the
            # remaining headroom to the population max -- symmetric treatment of both triggers,
            # neither privileged over the other (docs/04: "whose mean path_entropy *or*
            # segment_random" -- either alone is sufficient).
            entropy_max = max(entropy_population)
            ratio_max = max(ratio_population)
            entropy_over = (
                (mean_entropy - entropy_cutoff) / max(entropy_max - entropy_cutoff, 1e-9)
                if mean_entropy > entropy_cutoff
                else 0.0
            )
            ratio_over = (
                (mean_ratio - ratio_cutoff) / max(ratio_max - ratio_cutoff, 1e-9)
                if mean_ratio > ratio_cutoff
                else 0.0
            )
            score = max(0.0, min(1.0, max(entropy_over, ratio_over)))

            explanation: dict[str, Any] = {
                # docs/04's exact explanation shape:
                "mean_path_entropy": mean_entropy,
                "segment_random_ratio": mean_ratio,
                "sample_paths": samples,
                # additional context for the UI / a human triaging this signal:
                "src_ip": src_ip,
                "domain": domain,
                "entropy_cutoff_p995": entropy_cutoff,
                "segment_random_cutoff_p995": ratio_cutoff,
                "flagged_on_entropy": mean_entropy > entropy_cutoff,
                "flagged_on_segment_random": mean_ratio > ratio_cutoff,
                "n_requests": len(pair_rows),
                "n_pairs_in_domain_population": len(entries),
                "evidence_truncated": truncated,
            }
            drafts.append(
                SignalDraft(
                    detector_key=SIGNAL_URL_PATH,
                    entity_type=ENTITY_SRC_IP,
                    entity_value=src_ip,
                    raw_score=score,
                    confidence_raw=score,
                    window_start=ordered[0].ts,
                    window_end=ordered[-1].ts,
                    evidence_event_ids=evidence_ids,
                    explanation=explanation,
                )
            )
    return drafts
