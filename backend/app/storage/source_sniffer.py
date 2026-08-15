"""M1's placeholder sniffer, replaced (docs/13 M3).

The heuristic field-matching sniffer this module used to implement is gone. Source-type
detection is now the real thing: `app/parsers/registry.py` runs every `LogParser.sniff()`
against the sample (docs/03's actual registry contract), not a bespoke lookalike of it.

This module now just re-exports that implementation so any existing import of
`app.storage.source_sniffer.detect_source_types` keeps working. New code should import from
`app.parsers.registry` directly -- see `app/api/uploads.py`, which does.
"""

from __future__ import annotations

from app.parsers.registry import SNIFF_LINE_LIMIT, SNIFF_THRESHOLD, detect_source_types

__all__ = ["SNIFF_LINE_LIMIT", "SNIFF_THRESHOLD", "detect_source_types"]
