"""Unit tests for `app.graph.mitre_allowlist` -- the standalone loader `app.graph.tags` filters
incident technique tags against. Deliberately does not import `app.agent` anywhere in this file
(or anywhere else this task touches) -- the cost constraint on this task is absolute: nothing
under `app/agent/` may execute. `data/kb/mitre/allowlist.yml`'s exact 13 ids are asserted here as
a literal, matching the module docstring's rationale for why `app.graph` reads that file with its
own loader instead of importing `app.agent.mitre`'s.
"""

from __future__ import annotations

from app.graph.mitre_allowlist import (
    ALLOWLISTED_TECHNIQUE_COUNT,
    is_allowlisted_technique,
    load_allowlisted_technique_ids,
)

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


def test_loads_exactly_thirteen_ids_matching_the_kb_file() -> None:
    ids = load_allowlisted_technique_ids()
    assert len(ids) == ALLOWLISTED_TECHNIQUE_COUNT == 13
    assert ids == _EXPECTED_IDS


def test_known_allowlisted_id() -> None:
    assert is_allowlisted_technique("T1090")


def test_unknown_id_is_not_allowlisted() -> None:
    assert not is_allowlisted_technique("T9999.999")


def test_id_missing_its_t_prefix_is_not_allowlisted() -> None:
    """The exact malformation observed in this environment's live data (`app/detection/sigma/
    rule.py`'s `mitre_techniques` property strips the leading 'T' -- a pre-existing bug reported
    separately, not fixed here): a bare numeric id must never be treated as if it matched its
    correctly-prefixed counterpart."""
    assert not is_allowlisted_technique("1090")
