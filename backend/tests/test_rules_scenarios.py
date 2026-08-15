"""docs/13 M6 acceptance: "Rules detect scenarios 3, 4, 6 end to end." Generates each scenario
with the real `datagen` generator, parses it with the real `app/parsers/` registry (the same code
`app/pipeline/stages/parse.py` runs), enriches it with the real `app/enrichment` (so
`events.enrichment`-dependent fields are populated exactly as a real pipeline run would leave
them), bulk-loads it into a real `events` table, and runs every rule in `app/detection/rules/`
against it — no shortcuts, no synthetic-fixture substitutes.

`test_scenario_9_prompt_injection_canary_carrier_rule_fires` and
`test_scenario_10_benign_but_weird_false_positive_report` round out the acceptance picture:
scenario 9 proves the rules react to the carrier traffic's real shape (not the injected text —
that is docs/06's job, out of this package's scope) and scenario 10 is the false-positive control
docs/11 says "matters as much as the attacks."
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest

from app.core.config import get_settings
from app.core.db import get_engine
from app.detection.sigma import load_rules, load_suppressions, run_rules
from app.enrichment import enrich_event
from app.models.analysis import Analysis
from app.parsers.base import ParseFailure
from app.parsers.registry import iter_events, make_parser
from app.storage.event_writer import SimpleEventRecord, bulk_copy_events
from datagen.corpus import run_scenario
from datagen.types import LabelSet
from tests.conftest import make_analysis, make_tenant, make_user

# Small enough to run fast in the routine suite; large enough that the scenario's malicious burst
# sits inside a plausible-looking benign background rather than being the entire file.
_TOTAL_EVENTS = 20_000
_WINDOW_DAYS = 14


def _raw_connection() -> psycopg.Connection:
    dsn = get_settings().database_url.replace("postgresql+psycopg://", "postgresql://")
    return psycopg.connect(dsn, autocommit=True)


def _source_type_for(path: Path) -> str:
    if path.suffix == ".jsonl":
        # Both Okta and CloudTrail serialize as JSON Lines; every scenario this module drives
        # is Okta-only or Okta+ZScaler, so a `.jsonl` file here is always Okta.
        return "okta"
    return "zscaler"


def _load_log_file(analysis: Analysis, path: Path) -> int:
    source_type = _source_type_for(path)
    parser = make_parser(source_type)

    def rows() -> Iterator[SimpleEventRecord]:
        with path.open(encoding="utf-8") as fh:
            for result in iter_events(source_type, fh, parser=parser):
                if isinstance(result, ParseFailure):
                    continue
                hot = result.hot_columns()
                enrichment = enrich_event(hot)
                yield SimpleEventRecord(
                    **hot, ocsf=result.model_dump(mode="json"), enrichment=enrichment
                )

    conn = _raw_connection()
    try:
        return bulk_copy_events(
            conn, analysis_id=analysis.id, tenant_id=analysis.tenant_id, rows=rows()
        )
    finally:
        conn.close()


@pytest.fixture
def analysis_factory(tenant_cleanup: list[uuid.UUID]) -> Any:
    counter = {"n": 0}

    def _make(label: str) -> Analysis:
        counter["n"] += 1
        tenant = make_tenant(name=f"Scenario {label} {counter['n']}")
        tenant_cleanup.append(tenant.id)
        user = make_user(tenant_id=tenant.id, email=f"scenario{counter['n']}@example.com")
        return make_analysis(tenant_id=tenant.id, user_id=user.id, filename=f"{label}.log")

    return _make


def _generate_and_load(
    tmp_path: Path, analysis: Analysis, *, name: str, seed: int
) -> tuple[LabelSet, int]:
    written_paths = run_scenario(
        name, seed, tmp_path, total_events=_TOTAL_EVENTS, window_days=_WINDOW_DAYS
    )
    log_paths = [p for p in written_paths if p.suffix in {".jsonl", ".log"}]
    label_paths = [p for p in written_paths if p.name.endswith(".labels.json")]
    assert log_paths and label_paths, f"unexpected run_scenario output for {name}: {written_paths}"

    total_written = 0
    for log_path in log_paths:
        total_written += _load_log_file(analysis, log_path)

    # Multiple label files (one per source, for a cross-source scenario) share one scenario_id;
    # merge them for a single "what should have fired" view.
    label_sets = [LabelSet.from_json(p.read_text()) for p in label_paths]
    merged = label_sets[0]
    for extra in label_sets[1:]:
        merged.scenarios.extend(extra.scenarios)
    return merged, total_written


def _fired_sigma_keys(
    analysis: Analysis, *, rules: list[Any] | None = None
) -> tuple[set[str], list[Any]]:
    with get_engine().connect() as conn:
        drafts = run_rules(
            conn, analysis.id, analysis.tenant_id, rules=rules, suppressions=load_suppressions()
        )
    return {d.detector_key for d in drafts}, drafts


def _expected_sigma_detectors(label_set: LabelSet) -> set[str]:
    keys: set[str] = set()
    for scenario in label_set.scenarios:
        keys |= {d for d in scenario.expected_detectors if d.startswith("sigma.")}
    return keys


# ---------------------------------------------------------------------------- scenario 3


def test_scenario_3_password_spray_end_to_end(tmp_path: Path, analysis_factory: Any) -> None:
    analysis = analysis_factory("password-spray")
    label_set, written = _generate_and_load(tmp_path, analysis, name="password_spray", seed=103)
    assert written > 0

    fired, drafts = _fired_sigma_keys(analysis)
    expected = _expected_sigma_detectors(label_set)
    assert expected, "scenario fixture drift: password_spray now expects no sigma.* detectors"

    missing = expected - fired
    assert not missing, (
        f"scenario 3 (password spray): expected sigma detectors not fired: {missing}. "
        f"Fired: {sorted(fired)}"
    )

    for d in drafts:
        if d.detector_key in expected:
            print(
                f"  FIRED {d.detector_key}: entity={d.entity_value} evidence={d.evidence_event_ids[:5]}..."
            )


# ---------------------------------------------------------------------------- scenario 4


def test_scenario_4_impossible_travel_end_to_end(tmp_path: Path, analysis_factory: Any) -> None:
    analysis = analysis_factory("impossible-travel")
    label_set, written = _generate_and_load(tmp_path, analysis, name="impossible_travel", seed=104)
    assert written > 0

    fired, drafts = _fired_sigma_keys(analysis)
    expected = _expected_sigma_detectors(label_set)
    assert expected

    missing = expected - fired
    assert not missing, f"scenario 4 (impossible travel): expected detectors not fired: {missing}"

    for d in drafts:
        if d.detector_key in expected:
            print(
                f"  FIRED {d.detector_key}: entity={d.entity_value} explanation.match={d.explanation['match']}"
            )


# ---------------------------------------------------------------------------- scenario 6


def test_scenario_6_mfa_fatigue_end_to_end(tmp_path: Path, analysis_factory: Any) -> None:
    analysis = analysis_factory("mfa-fatigue")
    label_set, written = _generate_and_load(tmp_path, analysis, name="mfa_fatigue", seed=106)
    assert written > 0

    fired, drafts = _fired_sigma_keys(analysis)
    expected = _expected_sigma_detectors(label_set)
    assert expected

    missing = expected - fired
    assert not missing, f"scenario 6 (MFA fatigue): expected detectors not fired: {missing}"

    for d in drafts:
        if d.detector_key in expected:
            print(
                f"  FIRED {d.detector_key}: entity={d.entity_value} evidence_n={len(d.evidence_event_ids)}"
            )


# ---------------------------------------------------------------------------- scenario 9 / 10


def test_scenario_9_prompt_injection_canary_carrier_rule_fires(
    tmp_path: Path, analysis_factory: Any
) -> None:
    """docs/11 #9: the injection payloads live in `useragent`/`url`/`referer`, but the carrier
    traffic is a genuine true positive (curl UA, newly-registered domain) — this package's job
    ends at "does the carrier still look suspicious", not at defending the LLM prompt (docs/06).
    """
    analysis = analysis_factory("prompt-injection-canary")
    label_set, written = _generate_and_load(
        tmp_path, analysis, name="prompt_injection_canary", seed=109
    )
    assert written > 0
    fired, _drafts = _fired_sigma_keys(analysis)
    expected = _expected_sigma_detectors(label_set)
    missing = expected - fired
    assert not missing, f"scenario 9 carrier detectors not fired: {missing}"


def test_scenario_10_benign_but_weird_false_positive_report(
    tmp_path: Path, analysis_factory: Any
) -> None:
    """docs/11 #10, the false-positive control: `expected_detectors` is empty by construction —
    none of it is an attack. But this file is not *only* the three sanctioned motifs docs/11
    describes; `run_scenario` also generates a full multi-day benign background for the whole
    simulated org underneath them (docs/11: "the org's own catalogued service accounts... are the
    dominant source of realistic false positives"), and L1 rules are deliberately cheap and
    context-blind (docs/04's layering: L1 "100% of events", correlation/fusion downstream is what
    is supposed to separate signal from this kind of noise, not L1 alone). So the bar this test
    holds is not "zero signals anywhere in the file" — it is the one from CLAUDE.md's own
    verification instructions: **report the false-positive count per rule, honestly, and never let
    a `critical`-level rule (this evaluator's highest-confidence tier) fire on it.**

    Every count below is printed (`pytest -s`) rather than hidden, and the rules whose YAML
    already documents an expected context-blind false-positive mode
    (`non-browser-user-agent.yml`, `privilege-grant.yml`, `xsrc-login-without-proxy-history.yml`,
    `mfa-factor-deactivated.yml` — all `level: low` or `level: medium`) are exactly the ones
    allowed to fire here.
    """
    analysis = analysis_factory("benign-but-weird")
    label_set, written = _generate_and_load(tmp_path, analysis, name="benign_but_weird", seed=110)
    assert written > 0
    assert _expected_sigma_detectors(label_set) == set()

    rules = load_rules()
    by_level = {r.detector_key: r.level for r in rules}
    _fired, drafts = _fired_sigma_keys(analysis, rules=rules)

    counts = Counter(d.detector_key for d in drafts)
    print(f"\nscenario 10 (benign-but-weird) false-positive report, {written} events loaded:")
    if not counts:
        print("  (silent — no sigma rule fired)")
    for key, n in counts.most_common():
        print(f"  {key:45s} level={by_level.get(key, '?'):6s} signals={n}")

    critical_hits = {k: n for k, n in counts.items() if by_level.get(k) == "critical"}
    assert not critical_hits, (
        f"a critical-level rule fired on the false-positive control: {critical_hits}"
    )
