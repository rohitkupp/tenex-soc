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
    CLASSIFIED_INCIDENT_TYPES,
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


def test_seeder_never_writes_the_unmapped_fallback() -> None:
    """`uncategorized` is what a signature gets when its technique is not in the mapping. It is
    a real label the sync path emits, so the subset test above would happily allow seeding it —
    but seeding it uniformly made it the second-largest category in the Tier 2 overview, which
    reads as a broken technique mapping instead of the rare edge case it actually is."""
    assert _FALLBACK_INCIDENT_TYPE not in _INCIDENT_TYPES
    assert _FALLBACK_INCIDENT_TYPE in INCIDENT_TYPES  # still producible by a real run
    assert CLASSIFIED_INCIDENT_TYPES == INCIDENT_TYPES - {_FALLBACK_INCIDENT_TYPE}


def test_an_unmapped_verdict_is_not_synced_at_all() -> None:
    """`uncategorized` must never reach the store again.

    A verdict whose techniques fall outside the mapping — including the common
    `NO_KNOWN_MAPPING` case — carries an indicator hash and a tenant hash but no statement about
    what was seen. That is not threat intelligence: the value of this store is answering "three
    other tenants saw this doing X", and a row that cannot name X dilutes every aggregate built
    over it while contributing to none of them.
    """
    from app.tier2.signature_sync import should_sync_to_tier2

    class _V:
        def __init__(self, disposition: str, techniques: list[dict[str, str]]) -> None:
            self.disposition = disposition
            self.mitre_techniques = techniques

    mapped = next(iter(_TECHNIQUE_INCIDENT_TYPE))
    assert should_sync_to_tier2(_V("true_positive", [{"id": mapped}])) is True
    assert should_sync_to_tier2(_V("needs_review", [{"id": mapped}])) is True

    # Unmapped, no techniques at all, and the explicit sentinel all fall to the fallback.
    assert should_sync_to_tier2(_V("true_positive", [{"id": "T9999"}])) is False
    assert should_sync_to_tier2(_V("true_positive", [])) is False
    assert should_sync_to_tier2(_V("needs_review", [{"id": "NO_KNOWN_MAPPING"}])) is False

    # Disposition still governs independently of the mapping.
    assert should_sync_to_tier2(_V("benign", [{"id": mapped}])) is False


def test_the_seeder_history_floor_is_absolute_not_rolling() -> None:
    """`HISTORY_START` is a fixed date, so "nothing before August 12" stays true as time passes.
    A rolling `now - N days` window would silently drift back past it."""
    from datetime import UTC, datetime

    from app.scripts.seed_tier2_fleet import HISTORY_START, _observed_at

    now = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
    for days_ago in (0.0, 0.5, 40.0, 85.0, 88.0, 500.0):
        observed = _observed_at(now, days_ago)
        assert HISTORY_START <= observed <= now, (days_ago, observed)

    # Propagation lag cannot push a signature past the present either.
    assert _observed_at(now, 0.0, extra_hours=10_000) <= now


def test_every_allowlisted_technique_maps_to_an_incident_type() -> None:
    """The map must cover `data/kb/mitre/allowlist.yml` exactly.

    It covered seven of thirteen, so six techniques the Analyst can legitimately cite — T1105,
    T1505.003, T1102, T1090, T1041, T1595, T1204, T1568.002, T1567.004 — fell to
    `uncategorized`. That was the real source of the fallback bucket: an incomplete map, not
    genuinely unmappable incidents. Worse, once `should_sync_to_tier2` began declining unmapped
    verdicts, the same gap would have silently dropped real threat intelligence — including web
    shells and ingress tool transfer, two of the demo's own scenarios — out of Tier 2 entirely.
    Adding a technique to the allowlist without adding it here fails this test.
    """
    import pathlib as _pathlib
    import re

    allowlist_path = _pathlib.Path(__file__).resolve().parents[1] / "data/kb/mitre/allowlist.yml"
    allowlisted = set(re.findall(r"- id: (\S+)", allowlist_path.read_text()))
    assert allowlisted, "allowlist.yml parsed to nothing — the format changed"

    unmapped = sorted(allowlisted - set(_TECHNIQUE_INCIDENT_TYPE))
    assert not unmapped, (
        f"allowlisted technique(s) {unmapped} have no incident_type mapping, so a real verdict "
        "citing one would be refused by should_sync_to_tier2 and never reach Tier 2"
    )


def test_unreachable_mappings_are_known_and_declared() -> None:
    """The reverse direction, held deliberately loose.

    `_TECHNIQUE_INCIDENT_TYPE` maps two techniques the Analyst can never cite: T1078 (Valid
    Accounts) and T1530 (Data from Cloud Storage Object). Neither is in
    `data/kb/mitre/allowlist.yml`, because neither is observable from web proxy telemetry — a
    proxy cannot witness an account being used or a cloud object being read, only traffic.

    They are kept rather than deleted because they are the only bridge to two of docs/11's five
    scenario names (`insider_mass_download`, `peer_group_deviation`), which the fleet seeder
    draws from. Deleting them would shrink the taxonomy to three reachable categories; keeping
    them undeclared would let a genuinely fabricated id slip in unnoticed. So they are named
    here: anything *else* outside the allowlist is a real defect and fails.
    """
    import pathlib as _pathlib
    import re

    allowlist_path = _pathlib.Path(__file__).resolve().parents[1] / "data/kb/mitre/allowlist.yml"
    allowlisted = set(re.findall(r"- id: (\S+)", allowlist_path.read_text()))
    parents = {t.split(".")[0] for t in allowlisted}

    known_unreachable = {"T1078", "T1530"}
    unexpected = sorted(set(_TECHNIQUE_INCIDENT_TYPE) - allowlisted - parents - known_unreachable)
    assert not unexpected, (
        f"mapping references technique(s) {unexpected} that are neither allowlisted nor declared "
        "unreachable above — a fabricated id, or an allowlist entry someone forgot to add"
    )
