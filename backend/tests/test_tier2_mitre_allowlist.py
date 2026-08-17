"""Unit tests for `app.tier2.mitre_allowlist` -- the standalone `{id: name}` loader
`app.tier2.technique_prevalence` uses to label Tier 2 chart 2. Deliberately does not import
`app.agent` or `app.graph` anywhere in this file -- see the module's own docstring for why a
third loader of the same `allowlist.yml` exists rather than importing either.
"""

from __future__ import annotations

from app.graph.mitre_allowlist import load_allowlisted_technique_ids
from app.tier2.mitre_allowlist import ALLOWLISTED_TECHNIQUE_COUNT, load_allowlisted_techniques

# MIGRATION-01 change 4's exact starting set (`data/kb/mitre/allowlist.yml`).
_EXPECTED_IDS = frozenset(
    {
        "T1071.001",
        "T1102",
        "T1567",
        "T1567.002",
        "T1567.004",
        "T1041",
        "T1029",
        "T1568.002",
        "T1105",
        "T1090",
        "T1505.003",
        "T1595",
        "T1204",
    }
)


def test_loads_exactly_thirteen_techniques_matching_the_kb_file() -> None:
    techniques = load_allowlisted_techniques()
    assert len(techniques) == ALLOWLISTED_TECHNIQUE_COUNT == 13
    assert set(techniques.keys()) == _EXPECTED_IDS


def test_every_technique_has_a_non_empty_name() -> None:
    for tid, name in load_allowlisted_techniques().items():
        assert name, f"{tid} has an empty name"


def test_agrees_with_the_graph_packages_own_loader() -> None:
    """Two independent loaders of the same file (`app.graph.mitre_allowlist`,
    `app.tier2.mitre_allowlist`) -- both `app.graph` and `app.tier2` avoid depending on
    `app.agent` for the cost-boundary reason both modules document, and both must still agree
    on the id set they load from the one file that is actually authoritative."""
    assert set(load_allowlisted_techniques().keys()) == load_allowlisted_technique_ids()
