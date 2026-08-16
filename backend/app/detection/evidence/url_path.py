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

## Evidence extraction (docs/v2_migration change 2)

`raw_evidence_url_entropy` reuses `_url_path_findings` (shared with `detect_url_path`) and adds
exactly what the migration's own table asks for beyond the aggregate stats above: "Shannon
entropy, path depth, encoded-param flags, **the literal path string**." The literal path is the
single highest-entropy path actually observed on the fired pair (`_pair_stats`'s `top_path`) --
"the LLM does the semantic half [...] and it cannot do that without the actual path" (change 2's
own text) means picking *one* representative path, not a truncated sample list, so the LLM has a
concrete string to reason about rather than an aggregate number. `path_depth` (segment count) and
`encoded_param_flag` (a literal `%`/`?`/`=` in the path -- percent-encoding or an embedded query
fragment) are new per-path structural features `EventRow`'s existing columns already support
without a schema change.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from app.detection.evidence.constants import (
    ENTITY_SRC_IP,
    EXTRACTOR_URL_ENTROPY,
    SIGNAL_URL_PATH,
    URL_PATH_MIN_PAIRS_FOR_PERCENTILE,
    URL_PATH_MIN_REQUESTS,
    URL_PATH_PERCENTILE_THRESHOLD,
    URL_PATH_SAMPLE_COUNT,
    URL_PATH_SEGMENT_MIN_LEN,
    URL_PATH_TOKEN_MIN_DISTINCT_CHARS,
    URL_PATH_TRUNCATE_CHARS,
)
from app.detection.evidence.drafts import SignalDraft, cap_evidence, cap_evidence_rows
from app.detection.evidence.events_dao import EventRow, rows_with_domain
from app.detection.evidence.payload import BaselineQuery, RawEvidence
from app.detection.features import shannon_entropy

__all__ = ["detect_url_path", "raw_evidence_url_entropy"]

# Same reasoning as `burst.py`/`stl.py`'s own `_BASELINE_METRIC`: no `url_path_entropy`-named
# metric exists in `baseline_profiles` (the generator only populates `n_events`/`bytes_out`/
# `bytes_in`/`n_unique_domains`), and this detector's `src_ip` entity dimension has no
# `entity_type="user"` profile rows to fall back on either -- so this always cold-starts against
# today's seeded baseline. Named for what it actually measures rather than reused from a
# different detector's metric, since (unlike burst/stl) there is no partial overlap to exploit.
_BASELINE_METRIC = "url_path_entropy"

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


def _pair_stats(rows: Sequence[EventRow]) -> tuple[float, float, list[str], str, float]:
    """`(mean_path_entropy, mean_segment_random_ratio, sample_paths, top_path, top_path_entropy)`
    for one `(src_ip, domain)` pair's rows -- rows with no `url_path` are excluded from the means
    (nothing to score), not treated as `0.0` (which would silently dilute a pair with genuinely
    random paths by however many of its requests happened to log no path). `top_path` is the
    single *highest-entropy* path actually observed (untruncated selection pool, unlike
    `sample_paths`, which only ever keeps the first `URL_PATH_SAMPLE_COUNT`) -- module docstring,
    "Evidence extraction": the one literal path the evidence payload names."""
    entropies: list[float] = []
    ratios: list[float] = []
    samples: list[str] = []
    top_path = ""
    top_path_entropy = -1.0
    for row in rows:
        if not row.url_path:
            continue
        entropy = shannon_entropy(list(row.url_path))
        entropies.append(entropy)
        ratios.append(_segment_random_ratio(row.url_path))
        if len(samples) < URL_PATH_SAMPLE_COUNT:
            samples.append(row.url_path[:URL_PATH_TRUNCATE_CHARS])
        if entropy > top_path_entropy:
            top_path_entropy = entropy
            top_path = row.url_path[:URL_PATH_TRUNCATE_CHARS]
    mean_entropy = statistics.fmean(entropies) if entropies else 0.0
    mean_ratio = statistics.fmean(ratios) if ratios else 0.0
    return mean_entropy, mean_ratio, samples, top_path, max(top_path_entropy, 0.0)


def _path_depth(path: str) -> int:
    return len([seg for seg in path.split("/") if seg])


def _encoded_param_flag(path: str) -> bool:
    """A literal `%` (percent-encoding), `?`, or `=` in the path itself -- ZScaler's `url_path`
    field can carry a query fragment inline depending on log format, and a percent-encoded
    sequence is itself evidence of an encoded payload riding in the path rather than plain
    navigation."""
    return any(c in path for c in "%?=")


@dataclass(frozen=True, slots=True)
class _URLPathFinding:
    """One fired `(src_ip, domain)` pair -- shared by `detect_url_path` (`SignalDraft`) and
    `raw_evidence_url_entropy` (`EvidencePayload`), computed once (`_url_path_findings`)."""

    src_ip: str
    domain: str
    ordered_rows: list[EventRow]
    mean_entropy: float
    mean_ratio: float
    samples: list[str]
    top_path: str
    top_path_entropy: float
    entropy_cutoff: float
    ratio_cutoff: float
    score: float
    n_requests: int
    n_pairs_in_domain_population: int


def _url_path_findings(rows: Sequence[EventRow]) -> list[_URLPathFinding]:
    pairs: dict[tuple[str, str], list[EventRow]] = defaultdict(list)
    for row in rows_with_domain(rows):
        if row.src_ip is None:
            continue
        pairs[(row.src_ip, row.domain or "")].append(row)

    # Per-pair stats, keyed by domain so each domain's own org-wide population (module docstring)
    # can be assembled in a second pass.
    pair_entries: dict[
        str, list[tuple[str, float, float, list[str], str, float, list[EventRow]]]
    ] = defaultdict(list)
    for (src_ip, domain), pair_rows in pairs.items():
        if len(pair_rows) < URL_PATH_MIN_REQUESTS:
            continue
        mean_entropy, mean_ratio, samples, top_path, top_path_entropy = _pair_stats(pair_rows)
        pair_entries[domain].append(
            (src_ip, mean_entropy, mean_ratio, samples, top_path, top_path_entropy, pair_rows)
        )

    findings: list[_URLPathFinding] = []
    for _domain, entries in pair_entries.items():
        if len(entries) < URL_PATH_MIN_PAIRS_FOR_PERCENTILE:
            continue
        entropy_population = [e[1] for e in entries]
        ratio_population = [e[2] for e in entries]
        entropy_cutoff = float(np.percentile(entropy_population, URL_PATH_PERCENTILE_THRESHOLD))
        ratio_cutoff = float(np.percentile(ratio_population, URL_PATH_PERCENTILE_THRESHOLD))
        entropy_max = max(entropy_population)
        ratio_max = max(ratio_population)

        for (
            src_ip,
            mean_entropy,
            mean_ratio,
            samples,
            top_path,
            top_path_entropy,
            pair_rows,
        ) in entries:
            if mean_entropy <= entropy_cutoff and mean_ratio <= ratio_cutoff:
                continue

            # A score in [0, 1]: how far each statistic sits past its own cutoff, relative to the
            # remaining headroom to the population max -- symmetric treatment of both triggers,
            # neither privileged over the other (docs/04: "whose mean path_entropy *or*
            # segment_random" -- either alone is sufficient).
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

            findings.append(
                _URLPathFinding(
                    src_ip=src_ip,
                    domain=_domain,
                    ordered_rows=sorted(pair_rows, key=lambda r: r.ts),
                    mean_entropy=mean_entropy,
                    mean_ratio=mean_ratio,
                    samples=samples,
                    top_path=top_path,
                    top_path_entropy=top_path_entropy,
                    entropy_cutoff=entropy_cutoff,
                    ratio_cutoff=ratio_cutoff,
                    score=score,
                    n_requests=len(pair_rows),
                    n_pairs_in_domain_population=len(entries),
                )
            )
    return findings


def detect_url_path(rows: Sequence[EventRow]) -> list[SignalDraft]:
    drafts: list[SignalDraft] = []
    for f in _url_path_findings(rows):
        evidence_ids, truncated = cap_evidence([(r.ts, r.id) for r in f.ordered_rows])
        explanation: dict[str, Any] = {
            # docs/04's exact explanation shape:
            "mean_path_entropy": f.mean_entropy,
            "segment_random_ratio": f.mean_ratio,
            "sample_paths": f.samples,
            # additional context for the UI / a human triaging this signal:
            "src_ip": f.src_ip,
            "domain": f.domain,
            "entropy_cutoff_p995": f.entropy_cutoff,
            "segment_random_cutoff_p995": f.ratio_cutoff,
            "flagged_on_entropy": f.mean_entropy > f.entropy_cutoff,
            "flagged_on_segment_random": f.mean_ratio > f.ratio_cutoff,
            "n_requests": f.n_requests,
            "n_pairs_in_domain_population": f.n_pairs_in_domain_population,
            "evidence_truncated": truncated,
        }
        drafts.append(
            SignalDraft(
                detector_key=SIGNAL_URL_PATH,
                entity_type=ENTITY_SRC_IP,
                entity_value=f.src_ip,
                raw_score=f.score,
                confidence_raw=f.score,
                window_start=f.ordered_rows[0].ts,
                window_end=f.ordered_rows[-1].ts,
                evidence_event_ids=evidence_ids,
                explanation=explanation,
            )
        )
    return drafts


def raw_evidence_url_entropy(rows: Sequence[EventRow]) -> list[RawEvidence]:
    """`EvidencePayload` measurements for every pair `detect_url_path` also fires a `signals` row
    for (module docstring; same "ride the signal gate" rationale as `beaconing.raw_evidence_
    beaconing`, CLAUDE.md rule 1). `measurements["path"]` is `top_path` -- change 2's own text:
    "the LLM does the semantic half [...] and it cannot do that without the actual path.\""""
    raw: list[RawEvidence] = []
    for f in _url_path_findings(rows):
        _event_ids, line_numbers, truncated = cap_evidence_rows(f.ordered_rows)
        measurements: dict[str, Any] = {
            "path": f.top_path,
            "shannon_entropy": f.top_path_entropy,
            "path_depth": _path_depth(f.top_path),
            "encoded_param_flag": _encoded_param_flag(f.top_path),
            "mean_path_entropy": f.mean_entropy,
            "segment_random_ratio": f.mean_ratio,
            "evidence_truncated": truncated,
        }
        raw.append(
            RawEvidence(
                extractor=EXTRACTOR_URL_ENTROPY,
                entity={"type": ENTITY_SRC_IP, "value": f.src_ip, "domain": f.domain},
                window=(f.ordered_rows[0].ts, f.ordered_rows[-1].ts),
                measurements=measurements,
                contributing_line_numbers=line_numbers,
                baseline_queries=(
                    BaselineQuery(
                        entity_type=ENTITY_SRC_IP,
                        entity_value=f.src_ip,
                        metric=_BASELINE_METRIC,
                        value=f.mean_entropy,
                        historical_prefix="entropy",
                    ),
                ),
            )
        )
    return raw
