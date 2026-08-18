"""The fleet seeder and the real sync path must describe the same taxonomy.

This is a contract test for a failure that already shipped once. `app.scripts.seed_tier2_fleet`
hand-listed its own six `incident_type` labels; only one of them (`data_exfiltration`) was a
label `app.tier2.signature_sync` can actually produce. Nothing failed, nothing logged — the
Tier 2 overview simply grew two rows for the same threat (`c2_beacon`, 86 seeded signatures,
next to `c2_beaconing`, 1 real one) plus four incident types no live triage could ever add to.

The seeder now derives its vocabulary from `signature_sync.INCIDENT_TYPES`, so the specific bug
cannot recur. This test guards the weaker property that actually matters and would survive
someone reintroducing a literal list: every label the seeder can write is a label the sync path
can also write, and the sync path's own mapping stays closed over its declared vocabulary.
"""

from __future__ import annotations

from app.scripts.seed_tier2_fleet import _INCIDENT_TYPES
from app.tier2.signature_sync import (
    _FALLBACK_INCIDENT_TYPE,
    _TECHNIQUE_INCIDENT_TYPE,
    INCIDENT_TYPES,
)


def test_seeder_only_writes_incident_types_the_sync_path_can_produce() -> None:
    unknown = set(_INCIDENT_TYPES) - INCIDENT_TYPES
    assert not unknown, (
        f"seed_tier2_fleet writes incident_type(s) {sorted(unknown)} that "
        "app.tier2.signature_sync can never produce — the Tier 2 overview would group "
        "seeded and real signatures under different labels for the same threat"
    )


def test_declared_vocabulary_is_closed_over_the_technique_mapping() -> None:
    """`INCIDENT_TYPES` is the contract; the mapping is what fills it. Adding a technique
    mapping without it appearing here would let a real run write a label the seeder cannot."""
    assert set(_TECHNIQUE_INCIDENT_TYPE.values()) | {_FALLBACK_INCIDENT_TYPE} == INCIDENT_TYPES


def test_seeder_vocabulary_is_not_empty() -> None:
    """Deriving from another module means a rename upstream could silently empty this, which
    would make `rng.choice` raise deep inside a seeding run rather than fail here."""
    assert len(_INCIDENT_TYPES) >= 5
