"""Shared per-line JSON classification for the Okta and CloudTrail sniffers.

Why this needs to exist at all: a naive "fraction of sample lines whose required keys are
present" ratio is wrong the moment a sample mixes more than one source (docs/03's own "mixed
export" case) — every format's denominator counts *every* line in the sample, including the
other format's lines, which it was never going to match. Split evenly between two sources, each
one's ratio tops out at 0.5 and never clears `SNIFF_THRESHOLD`, so the registry reports neither
present. That is a real, reproducible instance of the "sniffer returns `[]` on real input" failure
mode this milestone exists to fix — caught by testing an interleaved sample of the M2 corpus, not
by inspection.

The fix: exclude a line from a parser's denominator when it is *confidently* some other known
JSON source's line (matches that source's own required-key set), rather than counting it as a
miss. A line that is valid JSON but matches no known signature still counts as an (unmatched)
candidate — that is what keeps the ratio low for arbitrary unrelated JSON. Only cross-matches
between the sources this module knows about are excluded.
"""

from __future__ import annotations

import json

# Every JSON-line source's required-key signature, keyed by `LogParser.source_type`. Both
# `okta.py` and `cloudtrail.py` register themselves here so each one's ratio can exclude the
# other's confidently-matched lines. Disjoint by construction — Okta and CloudTrail share no
# required key names — so a line can match at most one entry.
_SIGNATURES: dict[str, frozenset[str]] = {}


def register_signature(source_type: str, required_keys: tuple[str, ...]) -> frozenset[str]:
    sig = frozenset(required_keys)
    _SIGNATURES[source_type] = sig
    return sig


def json_line_ratio(sample: str, source_type: str) -> float:
    """Fraction of this source's *own* JSON-object candidates that match its required keys.

    A line only enters the denominator if it is a JSON object and is not confidently some other
    registered source's line, so one source's presence in a mixed sample cannot dilute another's
    score down to zero.
    """
    own = _SIGNATURES[source_type]
    others = tuple(sig for name, sig in _SIGNATURES.items() if name != source_type)

    hits = 0
    total = 0
    for line in sample.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except (json.JSONDecodeError, TypeError, RecursionError):
            continue
        if not isinstance(obj, dict):
            continue
        keys = obj.keys()
        if own <= keys:
            hits += 1
            total += 1
        elif any(sig <= keys for sig in others):
            continue  # confidently a different known source; not a candidate for this one
        else:
            total += 1  # unrecognized JSON object; still a legitimate (non-matching) candidate
    return hits / total if total else 0.0
