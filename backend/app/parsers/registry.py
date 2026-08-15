"""Parser registry, docs/03 verbatim.

"Registry in `parsers/registry.py` runs every `sniff()` and picks the highest score above 0.6.
A single upload may contain multiple source types (mixed export) -- detect per-line-block and
fan out to multiple parser queues."

ZScaler is the only registered source today -- Okta and CloudTrail were removed, narrowing this
project to ZScaler web proxy logs only. Nothing about the registry shape changed to do that:
`DEFAULT_PARSERS` is still a tuple, `sniff_scores`/`detect_source_types` still run every entry and
report the whole set above threshold rather than assuming exactly one match. Adding a source back
is "implement `LogParser`, append one entry to `DEFAULT_PARSERS` and `make_parser`" -- no other
module in this package needs to change, which is the extensibility this registry exists to prove.

`sniff_scores` runs every registered parser's `sniff()` against the first `SNIFF_LINE_LIMIT`
lines of the sample, exactly as `LogParser.sniff`'s own docstring specifies. Because every
parser's `sniff` implementation scores per-line and reports a hit *ratio* rather than an
all-or-nothing verdict on the whole block, a sample that interleaves lines from more than one
source (the mixed-export case) still yields a defensible score per source instead of one source's
signal drowning out another's -- which is what "detect per-line-block" buys you without literally
having to segment the sample into contiguous same-format runs first.

This module is also the seam with the event-store writer (a separate agent, docs/02): `iter_events`
is the "clean iterator/generator API over a file handle" that milestone owes it. See its docstring
for the exact signature.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field

from app.ocsf import OCSFEvent
from app.parsers.base import LogParser, ParseFailure
from app.parsers.zscaler import ZScalerParser

SNIFF_LINE_LIMIT = 50
SNIFF_THRESHOLD = 0.6

# One shared, stateless-enough-to-reuse instance per source. ZScalerParser carries mutable
# `_fields` state from `bind_header`, so registry callers that need header-driven binding for a
# specific file should construct their own `ZScalerParser()` via `make_parser` rather than reuse
# the registry's default instance across unrelated files.
DEFAULT_PARSERS: tuple[LogParser, ...] = (ZScalerParser(),)


def make_parser(source_type: str) -> LogParser:
    """A fresh parser instance for `source_type`. Use this (not the registry singletons) when
    parsing a specific file end to end, so ZScaler's header binding never leaks across files."""
    if source_type == "zscaler":
        return ZScalerParser()
    raise KeyError(f"no parser registered for source_type={source_type!r}")


@dataclass
class ParserRegistry:
    """Runs every `sniff()`; docs/03's registry."""

    parsers: Sequence[LogParser] = field(default_factory=lambda: DEFAULT_PARSERS)

    def get(self, source_type: str) -> LogParser:
        for parser in self.parsers:
            if parser.source_type == source_type:
                return parser
        raise KeyError(f"no parser registered for source_type={source_type!r}")

    def sniff_scores(self, sample_text: str) -> dict[str, float]:
        """Every registered parser's confidence against the first `SNIFF_LINE_LIMIT` lines."""
        limited = "\n".join(sample_text.splitlines()[:SNIFF_LINE_LIMIT])
        return {parser.source_type: parser.sniff(limited) for parser in self.parsers}

    def detect_source_types(self, sample_text: str) -> list[str]:
        """Every source scoring at or above `SNIFF_THRESHOLD`, highest-confidence first.

        Not just the single best match: a mixed export must fan out to every parser queue that
        applies (docs/03), so this reports the whole set above threshold rather than picking one.
        """
        scores = self.sniff_scores(sample_text)
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        return [name for name, score in ranked if score >= SNIFF_THRESHOLD]

    def best_match(self, sample_text: str) -> LogParser | None:
        """The single highest-scoring parser above threshold, for parsing one homogeneous file."""
        scores = self.sniff_scores(sample_text)
        if not scores:
            return None
        name, score = max(scores.items(), key=lambda kv: kv[1])
        return self.get(name) if score >= SNIFF_THRESHOLD else None


DEFAULT_REGISTRY = ParserRegistry()


def detect_source_types(sample_text: str) -> list[str]:
    """Module-level convenience wrapper over `DEFAULT_REGISTRY.detect_source_types`.

    This is the function `app/api/uploads.py` calls at upload time.
    """
    return DEFAULT_REGISTRY.detect_source_types(sample_text)


# ---------------------------------------------------------------------------- event-store seam


def iter_events(
    source_type: str, lines: Iterable[str], *, parser: LogParser | None = None
) -> Iterator[OCSFEvent | ParseFailure]:
    """Parse every data line of one file into `OCSFEvent | ParseFailure`, in order.

    **This is the seam with the bulk-COPY event-store writer.** Signature and contract:

    * `source_type`: `"zscaler"` (matches `LogParser.source_type` and `datagen.types.SourceType` --
      the only registered value now that Okta and CloudTrail have been removed).
    * `lines`: any iterable of text lines *with or without trailing newlines* -- an open `TextIO`
      file handle works directly (iterating a file object yields its lines), as does a `list[str]`
      or a generator. Nothing here reads the whole input into memory; this function is itself a
      generator, so the caller controls backpressure/buffering (e.g. batching every N results into
      one `COPY`).
    * Returns: a lazy iterator yielding exactly one `OCSFEvent | ParseFailure` per *non-header*
      physical line, in file order. 1-based `line_no` matches `raw_line_no` (docs/02) and the file
      line numbers datagen's `GroundTruth.malicious_line_numbers` uses -- the header line (ZScaler
      only; `parser.header_lines == 1`) is consumed to bind columns but never yielded, and blank
      lines are skipped without producing a result, so nothing needs to special-case them.
    * `OCSFEvent` carries `.hot_columns()` -- the exact docs/02 hot-column projection (`ts`,
      `principal`, `src_ip`, ... `event_key`) -- so the writer never has to re-derive an OCSF path
      itself. `ParseFailure` carries `line_no` + `reason` (+ a bounded `raw_excerpt`) for
      `analyses.parse_failure_rate` and whatever failure-record sink the writer chooses (docs/02
      has no dedicated failures table; `dead_letters` is the closest existing fit).

    Usage against the real writer (`app/storage/event_writer.py`, built independently against
    this same seam) -- `SimpleEventRecord` there accepts exactly the keys `hot_columns()` returns
    plus `ocsf`/`enrichment`, so the adapter is one dict merge, no field-by-field translation:

    ```python
    from app.storage.event_writer import SimpleEventRecord, bulk_copy_events
    from app.parsers.registry import ParseStats, iter_events, make_parser

    stats = ParseStats()

    def rows() -> Iterator[SimpleEventRecord]:
        parser = make_parser(source_type)
        with storage.open(source_key) as fh:
            for result in iter_events(source_type, fh, parser=parser):
                stats.record(result)
                if isinstance(result, ParseFailure):
                    continue  # tracked in `stats`, never written to `events`
                yield SimpleEventRecord(**result.hot_columns(), ocsf=result.model_dump(mode="json"))

    bulk_copy_events(conn, analysis_id=analysis_id, tenant_id=tenant_id, rows=rows())
    analysis.parse_failure_rate = stats.failure_rate
    ```
    """
    resolved = parser if parser is not None else make_parser(source_type)
    header_budget = getattr(resolved, "header_lines", 0)
    bind_header = getattr(resolved, "bind_header", None)

    for line_no, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n").rstrip("\r")
        if line_no <= header_budget:
            if bind_header is not None and line.strip():
                bind_header(line)
            continue
        if not line.strip():
            continue
        yield resolved.parse_line(line, line_no)


@dataclass
class ParseStats:
    """Running total/failed counter for `analyses.parse_failure_rate` (docs/02).

    Not persistence -- just the arithmetic, so the event-store writer (or a test) can fold
    `iter_events`'s output into the one float docs/02 asks for without recomputing the ratio
    itself. `record` accepts either half of the `OCSFEvent | ParseFailure` union.
    """

    total: int = 0
    failed: int = 0
    failures: list[ParseFailure] = field(default_factory=list)

    def record(self, result: OCSFEvent | ParseFailure) -> None:
        self.total += 1
        if isinstance(result, ParseFailure):
            self.failed += 1
            self.failures.append(result)

    @property
    def failure_rate(self) -> float:
        return self.failed / self.total if self.total else 0.0
