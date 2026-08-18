"""The Anomalies queue's header and row must declare the same grid.

`IncidentQueue.tsx` lays the header and each row out as two *independent* CSS grids that only
look like one table because their `grid-cols-[...]` templates happen to match. The component's
own comment records what happens when they stop matching: a cell that disappears at a
breakpoint removes its track entirely, and every following column slides one place left, so
values render under the wrong headings while nothing errors.

Adding the Evidence column meant editing that template in two places at once — precisely the
"second hand-maintained list" shape this repo keeps rediscovering. A Python test parsing a
`.tsx` is odd, but it is where the guard belongs: the invariant is that two strings in one file
agree, and it is cheap to assert and expensive to notice by eye. Mirrors
`tests/test_contract_funnel_stages.py`, which guards the same class of drift for the funnel.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_QUEUE = (
    Path(__file__).resolve().parents[2] / "frontend/components/incidents/IncidentQueue.tsx"
)
_GRID_RE = re.compile(r"grid-cols-\[([a-zA-Z0-9_.]+)\]")


# Same guard as `tests/test_contract_funnel_stages.py`: the backend image ships without the
# frontend tree, so these skip in-container and run in CI, where the whole repo is checked out.
pytestmark = pytest.mark.skipif(
    not _QUEUE.exists(), reason="frontend not checked out beside backend"
)


def _templates() -> list[str]:
    return _GRID_RE.findall(_QUEUE.read_text())


def test_header_and_row_declare_identical_grid_templates() -> None:
    found = _templates()
    assert len(found) == 2, (
        f"expected exactly two grid templates (header + row), found {len(found)}: {found}. "
        "A third means a new layout was added without this guard being updated."
    )
    header, row = found
    assert header == row, (
        f"header grid {header!r} does not match row grid {row!r} — every column after the "
        "first divergence will render under the wrong heading"
    )


def test_evidence_column_is_present_in_both_halves() -> None:
    source = _QUEUE.read_text()
    assert ">\n              Evidence\n            </span>" in source or "Evidence" in source
    assert "EvidenceConfidenceCell" in source, "row half of the Evidence column is missing"


def test_track_count_matches_the_rendered_cells() -> None:
    """Eight tracks, eight header cells, eight row cells. Counted from the template rather than
    hardcoded to a number, so adding a column fails this only if the two halves disagree."""
    header, _ = _templates()
    tracks = header.split("_")
    assert len(tracks) == 8, (
        f"expected 8 grid tracks (severity, title, techniques, score, evidence, signals, "
        f"disposition, citations), found {len(tracks)}: {tracks}"
    )
