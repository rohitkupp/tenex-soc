"""Lightweight source-type sniffer for uploads.

`docs/03-PARSERS-OCSF.md` defines the real parser contract for M3:

```python
class LogParser(Protocol):
    source_type: str
    ocsf_class_uid: int
    def sniff(self, sample: str) -> float: ...
    def parse_line(self, line: str, line_no: int) -> OCSFEvent | ParseFailure: ...
```

a registry that runs every `sniff()` against the first 50 lines and keeps every source
scoring above 0.6 (a single upload may be a mixed export). M1 only needs to *detect*
source types, not parse them, so this module implements that same shape — a name plus
a `sniff(lines) -> float` callable, scored the same way — without the parsing half.
Replacing this with `app/parsers/registry.py` at M3 means registering real parsers
here; the call site (`app/storage/streaming_upload.py`) does not change.
"""

from __future__ import annotations

import json
from collections.abc import Callable

SNIFF_LINE_LIMIT = 50
SNIFF_THRESHOLD = 0.6

SourceSniffer = Callable[[list[str]], float]

_OKTA_FIELDS = {"eventType", "outcome"}
_CLOUDTRAIL_FIELDS = {"eventSource", "eventName", "eventTime"}
_ZSCALER_HEADER_FIELDS = {"datetime", "user", "clientip", "host", "action", "url", "requestmethod"}
_ZSCALER_JSON_FIELDS = {"clientip", "host"}


def _json_line_ratio(lines: list[str], required_fields: set[str]) -> float:
    hits, total = 0, 0
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        total += 1
        try:
            obj = json.loads(stripped)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(obj, dict) and required_fields <= obj.keys():
            hits += 1
    return hits / total if total else 0.0


def _sniff_okta(lines: list[str]) -> float:
    return _json_line_ratio(lines, _OKTA_FIELDS)


def _sniff_cloudtrail(lines: list[str]) -> float:
    # The standard export is one JSON object ({"Records": [...]}) rather than JSON
    # Lines, so a per-line ratio would score 0 on a well-formed export. Check the
    # sniff block as a whole for the outer shape first, then fall back to a
    # JSON-lines ratio for exports already split one-record-per-line.
    blob = "\n".join(lines)
    if '"Records"' in blob and '"eventSource"' in blob and '"eventName"' in blob:
        return 0.9
    return _json_line_ratio(lines, _CLOUDTRAIL_FIELDS)


def _sniff_zscaler(lines: list[str]) -> float:
    if not lines:
        return 0.0
    delimiter = "\t" if "\t" in lines[0] else ","
    header_columns = {c.strip().strip('"').lower() for c in lines[0].split(delimiter)}
    if len(header_columns & _ZSCALER_HEADER_FIELDS) >= 3:
        return 0.85
    return _json_line_ratio(lines, _ZSCALER_JSON_FIELDS)


_SNIFFERS: tuple[tuple[str, SourceSniffer], ...] = (
    ("okta", _sniff_okta),
    ("cloudtrail", _sniff_cloudtrail),
    ("zscaler", _sniff_zscaler),
)


def detect_source_types(sample_text: str) -> list[str]:
    """Score every registered sniffer against the first `SNIFF_LINE_LIMIT` lines of
    `sample_text` and return every source type scoring at or above `SNIFF_THRESHOLD`."""
    lines = sample_text.splitlines()[:SNIFF_LINE_LIMIT]
    return [name for name, sniff in _SNIFFERS if sniff(lines) >= SNIFF_THRESHOLD]
