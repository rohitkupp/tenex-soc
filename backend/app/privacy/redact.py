"""Secret & PII redaction (docs/06-PRIVACY-SECURITY.md "Secret & PII redaction",
normative). Patterns in `redaction_patterns.yml` -- see that file's header for the full
table and the reasoning behind each pattern.

Redaction is lossy and irreversible by design -- unlike pseudonymization there is no reverse
map here and none is wanted; these are secrets, not entities that need to stay
correlatable across an analysis.

Applied to free-text fields before storage and before any prompt (docs/06). This module only
knows how to redact a single string; `app/workers`' callers decide *which* fields of an
event are free text (`url_path`, `user_agent`, `referrer`, ...) and run each one through
`redact_text` (or the batch form, `redact_many`), then sum the per-field counts into the
analysis-level "N secrets redacted" counter docs/06 asks the UI to show.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

PATTERNS_YML = Path(__file__).resolve().parent / "redaction_patterns.yml"


@dataclass(frozen=True, slots=True)
class RedactionResult:
    text: str
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())


@dataclass(frozen=True, slots=True)
class _Pattern:
    name: str
    regex: re.Pattern[str]
    luhn_check: bool


@lru_cache(maxsize=1)
def _patterns() -> tuple[_Pattern, ...]:
    if not PATTERNS_YML.exists():
        return ()
    data: dict[str, Any] = yaml.safe_load(PATTERNS_YML.read_text(encoding="utf-8")) or {}
    out: list[_Pattern] = []
    for raw in data.get("patterns") or []:
        out.append(
            _Pattern(
                name=raw["name"],
                regex=re.compile(raw["regex"]),
                luhn_check=bool(raw.get("luhn_check", False)),
            )
        )
    return tuple(out)


def _luhn_ok(digits: str) -> bool:
    """Standard Luhn/mod-10 checksum. `digits` must already have separators stripped."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _redact_pan(text: str, pattern: _Pattern) -> tuple[str, int]:
    count = 0

    def _sub(m: re.Match[str]) -> str:
        nonlocal count
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            count += 1
            return "<REDACTED:pan>"
        return m.group(0)

    return pattern.regex.sub(_sub, text), count


def redact_text(text: str) -> RedactionResult:
    """Run every pattern over `text` once, in `redaction_patterns.yml`'s declared order
    (see that file's header for why order matters here)."""
    if not text:
        return RedactionResult(text=text, counts={})

    counts: dict[str, int] = {}
    result = text
    for pattern in _patterns():
        if pattern.luhn_check:
            result, n = _redact_pan(result, pattern)
        else:
            result, n = pattern.regex.subn(f"<REDACTED:{pattern.name}>", result)
        if n:
            counts[pattern.name] = counts.get(pattern.name, 0) + n
    return RedactionResult(text=result, counts=counts)


def redact_many(texts: Iterable[str | None]) -> tuple[list[str | None], dict[str, int]]:
    """Batch convenience: redact several free-text fields (e.g. one event's `url_path`,
    `user_agent`, `referrer`) and return the redacted values (`None` passed through as
    `None`, same positions preserved) plus the *combined* counts, ready to be summed into
    an analysis-level total by the caller."""
    out: list[str | None] = []
    totals: dict[str, int] = {}
    for text in texts:
        if text is None:
            out.append(None)
            continue
        result = redact_text(text)
        out.append(result.text)
        for key, value in result.counts.items():
            totals[key] = totals.get(key, 0) + value
    return out, totals
