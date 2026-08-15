"""The parser contract, docs/03 verbatim.

```python
class LogParser(Protocol):
    source_type: str
    ocsf_class_uid: int

    def sniff(self, sample: str) -> float:
        \"\"\"Confidence 0..1 that this parser handles the sample. Called on first 50 lines.\"\"\"

    def parse_line(self, line: str, line_no: int) -> OCSFEvent | ParseFailure:
        ...
```

`app/parsers/zscaler.py` implements this structurally — `LogParser` is `@runtime_checkable` so
`isinstance(parser, LogParser)` works, but nothing here requires subclassing it. ZScaler is the
only registered parser today (Okta and CloudTrail were removed); the Protocol -- not a base class
-- is what lets `app/parsers/registry.py` add a second one later without touching this file.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from app.ocsf import OCSFEvent


class ParseFailure(BaseModel):
    """docs/03: "Do not silently drop malformed lines; record them."

    One of these is emitted per line a parser could not turn into an `OCSFEvent` — captures
    exactly the two things the doc asks for (line number, reason) plus a bounded excerpt of the
    offending line for debugging. `raw_excerpt` is truncated and is still untrusted log content
    (CLAUDE.md rule 3) — it must not be interpolated into an LLM prompt or any other
    trust-boundary-crossing context without going through the same redaction path as everything
    else in `events.ocsf`; that path is M5's, not this module's.
    """

    model_config = ConfigDict(extra="forbid")

    source_type: str
    line_no: int
    reason: str
    raw_excerpt: str = ""


_EXCERPT_LIMIT = 200


def excerpt(line: str, limit: int = _EXCERPT_LIMIT) -> str:
    """Bounded, single-line preview of a raw log line for `ParseFailure.raw_excerpt`."""
    flat = line.replace("\n", " ").replace("\r", " ")
    return flat if len(flat) <= limit else flat[:limit] + "…"


@runtime_checkable
class LogParser(Protocol):
    source_type: str
    ocsf_class_uid: int

    def sniff(self, sample: str) -> float:
        """Confidence 0..1 that this parser handles the sample. Called on first 50 lines."""
        ...

    def parse_line(self, line: str, line_no: int) -> OCSFEvent | ParseFailure: ...
