"""One module per log source (docs/03), implementing the `LogParser` Protocol in `base.py`.

`app/parsers/registry.py` is the docs/03 registry and the seam with the event-store writer
(`iter_events`). See that module's docstring for the exact iterator contract.
"""

from __future__ import annotations

from app.parsers.base import LogParser, ParseFailure, excerpt
from app.parsers.cloudtrail import CloudTrailParser
from app.parsers.okta import OktaParser
from app.parsers.registry import (
    DEFAULT_PARSERS,
    DEFAULT_REGISTRY,
    SNIFF_LINE_LIMIT,
    SNIFF_THRESHOLD,
    ParserRegistry,
    ParseStats,
    detect_source_types,
    iter_events,
    make_parser,
)
from app.parsers.zscaler import ZScalerParser

__all__ = [
    "DEFAULT_PARSERS",
    "DEFAULT_REGISTRY",
    "SNIFF_LINE_LIMIT",
    "SNIFF_THRESHOLD",
    "CloudTrailParser",
    "LogParser",
    "OktaParser",
    "ParseFailure",
    "ParseStats",
    "ParserRegistry",
    "ZScalerParser",
    "detect_source_types",
    "excerpt",
    "iter_events",
    "make_parser",
]
