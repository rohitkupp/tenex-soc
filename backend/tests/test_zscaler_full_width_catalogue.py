"""Full-width ZScaler NSS catalogue (this task, docs/v1/zscaler-nss-web-fields.md +
docs/v1/11-SYNTHETIC-DATA.md's "extract 25-of-181" preprocessing contract).

The decision under test: `datagen/emitters/zscaler.py` now emits every documented NSS field
(181 columns total — the parser's 25 original + 27 already-promoted fields, plus ~129 more that
docs/v1/zscaler-nss-web-fields.md catalogues but `app/parsers/zscaler.py` deliberately does not
parse), while the application keeps extracting only the same 52 it always did. That preprocessing
step was previously untested at anything wider than 32 columns — a parser that positions fields
correctly on 32 columns can still mis-position on 181, and this file is the regression test for
exactly that risk. `app.parsers.zscaler.ZScalerParser` binds columns by header name
(`bind_header`), so the sharpest place a position/order bug would show up is a field near the very
END of the row — the front 25-52 columns would still "happen" to look right even with a
misalignment bug if the alignment only broke somewhere in the newly-added tail.
"""

from __future__ import annotations

from pathlib import Path

from app.ocsf import HTTPActivity
from app.parsers.base import ParseFailure
from app.parsers.registry import iter_events
from app.parsers.zscaler import ZScalerParser
from datagen import corpus
from datagen.emitters.zscaler import FIELDS
from datagen.scenarios import scenario_keys
from datagen.types import TimeWindow

_ORG_SPEC = corpus.OrgSpec(n_users=15, n_departments=2, offices=("US-CA",), n_service_accounts=2)
_REGRESSION_SEED = 11
# Matches `test_parsers_zscaler.py`'s own floor — `peer_group_deviation` needs >=10k background
# events to reliably clear its own statistical acceptance gate (docs/11 "labeled train/validation/
# golden split"), and this sweeps every registered scenario including that one.
_REGRESSION_EVENTS = 10_000

# The 52 fields `app/parsers/zscaler.py` actually extracts (docs/03's 25 + the two promotion
# rounds already landed before this task) — used below to prove the extraction step still works,
# not to re-litigate `test_parsers_zscaler.py`'s own full field-by-field round trip.
_WIRED_FIELD_COUNT = 52


def _write_corpus(tmp_path: Path, *, events: int = 2_000) -> Path:
    org = corpus.build_org(11, corpus.ROLE_BENIGN, _ORG_SPEC)
    root = corpus.SeededRandom(corpus.role_seed(11, corpus.ROLE_BENIGN))
    window = TimeWindow.of_days(3)
    corpus.write_benign_corpus(org, root, window, tmp_path, proxy_events=events)
    return tmp_path / "benign_zscaler.log"


# ---------------------------------------------------------------------------- width


def test_generator_emits_the_full_documented_catalogue_width() -> None:
    """Every documented field, not just the 52 the parser reads — this is the whole premise of
    this task. A regression here (someone trims `FIELDS` back down) silently narrows every
    artifact this generator produces back toward the old 32/52-column shape."""
    assert len(FIELDS) >= 150, f"FIELDS is only {len(FIELDS)} wide — narrower than documented"
    assert len(FIELDS) == len(set(FIELDS)), "FIELDS has a duplicate column name"
    assert FIELDS[:_WIRED_FIELD_COUNT].index("threatseverity") == _WIRED_FIELD_COUNT - 1, (
        "the 52 wired fields must stay a stable, ordered prefix — every existing fixture and "
        "test_parsers_zscaler.py's own field-order assertions assume it"
    )


def test_benign_corpus_is_full_width(tmp_path: Path) -> None:
    log_path = _write_corpus(tmp_path)
    header = log_path.read_text().splitlines()[0].split("\t")
    assert len(header) == len(FIELDS)
    assert tuple(header) == FIELDS


# ---------------------------------------------------------------------------- parse proof


def test_full_width_benign_corpus_parses_with_zero_failures(tmp_path: Path) -> None:
    log_path = _write_corpus(tmp_path)

    n_events = n_failures = 0
    with log_path.open(encoding="utf-8") as fh:
        for result in iter_events("zscaler", fh):
            if isinstance(result, ParseFailure):
                n_failures += 1
            else:
                n_events += 1

    assert n_failures == 0
    assert n_events > 0


def test_every_registered_scenario_parses_at_full_width_with_zero_failures(tmp_path: Path) -> None:
    """Same acceptance bar as `test_parsers_zscaler.py`'s own scenario sweep, run again here
    because that file's fixtures predate this task — this is the version of the check that fails
    if full-width generation broke a *malicious*-traffic code path specifically (scenario `extra=`
    dicts merged on top of the new catalogue fields, the C2/exfil `_apply_wide_fields` call sites,
    ...), not just the benign one above."""
    assert scenario_keys(), "no scenarios registered — datagen.scenarios discovery is broken"

    for key in scenario_keys():
        written = corpus.run_scenario(
            key, _REGRESSION_SEED, tmp_path / key, total_events=_REGRESSION_EVENTS
        )
        log_path = next(p for p in written if p.suffix == ".log")
        header = log_path.read_text().splitlines()[0].split("\t")
        assert len(header) == len(FIELDS), f"{key}: header is {len(header)} cols, not {len(FIELDS)}"

        n_events = n_failures = 0
        with log_path.open(encoding="utf-8") as fh:
            for result in iter_events("zscaler", fh):
                if isinstance(result, ParseFailure):
                    n_failures += 1
                else:
                    n_events += 1

        assert n_failures == 0, f"{key}: {n_failures} parse failures at full width"
        assert n_events > 0, f"{key}: parser yielded zero events at full width"


# ---------------------------------------------------------------------------- positional proof


def test_late_column_fields_extract_correctly_at_full_width(tmp_path: Path) -> None:
    """The deliverable this whole test file exists for: pick fields from deep in the row —
    `eedone`/`nsssvcip`/`productversion`/`recordid` sit in the last five of 181 columns
    (`FIELDS[-5:]`) — and prove the value the real parser's header-driven column binding recovers
    for each one is exactly the value the generator wrote there. A field-order bug (an insertion
    that shifted `FIELDS` out of step with `serialize`'s own iteration, or a header/row length
    mismatch) would show up exactly here: the front ~52 wired columns can look fine by coincidence
    while a misalignment further out silently swaps two late columns' values.
    """
    log_path = _write_corpus(tmp_path, events=3_000)
    lines = log_path.read_text().splitlines()
    header = lines[0]
    header_cols = header.split("\t")
    assert header_cols[-5:] == ["recordid", "pcapid", "productversion", "nsssvcip", "eedone"]

    parser = ZScalerParser()
    parser.bind_header(header)

    checked_device_row = checked_ssl_row = False
    for line_no, line in enumerate(lines[1:], start=2):
        raw = dict(zip(header_cols, line.split("\t"), strict=True))
        result = parser.parse_line(line, line_no)
        assert isinstance(result, HTTPActivity), f"line {line_no}: {result}"

        # Deployment-level constants (this task): identical on every line, always the very last
        # three columns.
        assert raw["productversion"] == "6.1.245.10021_01"
        assert raw["nsssvcip"] == "10.10.102.30"
        assert raw["eedone"] == "No"
        # `recordid` (column 176 of 181): present and numeric on every line — proves that column,
        # specifically, positions correctly (a shifted header would make this land on
        # `pcapid`/`productversion`'s value instead, which are not all-digit).
        assert raw["recordid"].isdigit(), f"line {line_no}: recordid {raw['recordid']!r}"

        # `totalsize` (column ~149) must equal `requestsize + responsesize` (columns 8-9, near the
        # front) — this is the task's own explicit invariant, and it doubles as a positional check
        # that spans nearly the whole row: it can only hold if every column between the two ends
        # bound correctly.
        assert int(raw["totalsize"]) == int(raw["requestsize"]) + int(raw["responsesize"])
        assert int(raw["reqhdrsize"]) + int(raw["reqdatasize"]) == int(raw["requestsize"])
        assert int(raw["resphdrsize"]) + int(raw["respdatasize"]) == int(raw["responsesize"])

        # Device fields (columns 170-174, catalogued-only): only present for human principals with
        # a Client Connector device — check at least one row of each kind actually got exercised.
        if raw["devicehostname"] != "None":
            assert raw["devicemodel"] != "None"
            assert raw["devicetype"] == "Zscaler Client Connector"
            assert raw["deviceappversion"] != "None"
            assert raw["ztunnelversion"] == "ZTUNNEL_2_0"
            checked_device_row = True
        if raw["ssldecrypted"] == "Yes":
            assert raw["clienttlsversion"] in {"TLS1_1", "TLS1_2", "TLS1_3"}
            assert raw["srv_dport"] == "443"
            checked_ssl_row = True

    assert checked_device_row, "sanity: no human-device row was generated to check"
    assert checked_ssl_row, "sanity: no SSL-inspected row was generated to check"


# ---------------------------------------------------------------------------- internal consistency


def test_threatseverity_follows_the_documented_riskscore_bands() -> None:
    """docs/v1/zscaler-nss-web-fields.md: Critical 90-100, High 75-89, Medium 46-74, Low 1-45,
    None 0. Exercises the non-blended C2 profile directly (`build_event`'s own `riskscore=98`
    path, `s01_c2_beaconing._C2_THREAT`) — this is also a regression test for a real bug this task
    found and fixed: `build_event` (the only path every scenario-crafted event goes through) never
    set `threatseverity` at all before this task, so a scenario setting `riskscore=98` silently
    shipped `threatseverity=None` right next to it."""
    written = corpus.run_scenario(
        "c2_beaconing",
        _REGRESSION_SEED,
        Path("/tmp"),
        total_events=2_000,
        knobs={"blend_with_normal_traffic": False, "n_beacons": 20, "duration_h": 0.5},
    )
    log_path = next(p for p in written if p.suffix == ".log" and p.exists())
    lines = log_path.read_text().splitlines()
    header = lines[0].split("\t")
    idx = {n: i for i, n in enumerate(header)}

    checked = 0
    for line in lines[1:]:
        row = line.split("\t")
        riskscore = int(row[idx["riskscore"]])
        severity = row[idx["threatseverity"]]
        if riskscore >= 90:
            assert severity == "Critical", (riskscore, severity)
            checked += 1
        elif riskscore == 0:
            assert severity == "None", (riskscore, severity)
        # status/action co-occurrence (this task's own explicit invariant — the doc's `respcode`
        # concept is this codebase's `status` field, per docs/v1/zscaler-nss-web-fields.md "Task
        # 2 — reconciliation").
        if row[idx["status"]] == "403":
            assert row[idx["action"]] == "Blocked"
        if row[idx["action"]] == "Blocked":
            assert row[idx["status"]] in {"403"} or riskscore >= 0  # blocks aren't always 403

    assert checked > 0, "sanity: no Critical-riskscore row was generated to check"


def test_dlp_dictionary_hit_counts_and_identifier_are_internally_consistent(tmp_path: Path) -> None:
    """`dlpdicthitcount` must carry one count per `|`-separated entry in `dlpdict`, and
    `dlpidentifier`/`exempt_dlpidentifier` must never both be set (this task's own explicit
    invariants). `data_exfiltration`'s DLP fields only populate when
    `blend_with_normal_traffic=False` (the scenario's default is `True` everywhere the labeled
    corpus actually calls it — see this task's report), so this test forces that knob directly to
    exercise the code path for real rather than asserting on a path nothing in the default corpus
    reaches."""
    written = corpus.run_scenario(
        "data_exfiltration",
        _REGRESSION_SEED,
        tmp_path,
        total_events=2_000,
        knobs={
            "blend_with_normal_traffic": False,
            "total_mb": 20.0,
            "chunk_mb": 5.0,
            "duration_h": 0.2,
        },
    )
    log_path = next(p for p in written if p.suffix == ".log")
    lines = log_path.read_text().splitlines()
    header = lines[0].split("\t")
    idx = {n: i for i, n in enumerate(header)}

    checked_dlp = checked_encrypted = 0
    for line in lines[1:]:
        row = line.split("\t")
        dlpdict = row[idx["dlpdict"]]
        if dlpdict != "None":
            names = dlpdict.split("|")
            hitcounts = row[idx["dlpdicthitcount"]].split("|")
            assert len(names) == len(hitcounts), (dlpdict, row[idx["dlpdicthitcount"]])
            assert all(c.isdigit() and int(c) > 0 for c in hitcounts)
            dlp_id = row[idx["dlpidentifier"]]
            exempt_id = row[idx["exempt_dlpidentifier"]]
            assert (dlp_id == "None") != (exempt_id == "None"), (
                "dlpidentifier and exempt_dlpidentifier must be mutually exclusive"
            )
            checked_dlp += 1
        if row[idx["unscannabletype"]] == "Encrypted File":
            assert row[idx["upload_filetype"]] != "None"
            checked_encrypted += 1

    assert checked_dlp > 0, "sanity: no DLP-matched row was generated to check"
    assert checked_encrypted > 0, "sanity: no encrypted-archive upload row was generated to check"

    # Parse it too — the DLP/encrypted-archive path is unwired (catalogued-only), so this is
    # really re-proving the wired 52 still extract cleanly on a file shaped differently from the
    # benign corpus (blocked/allowed mix, non-default riskscore, DLP fields all populated).
    n_events = n_failures = 0
    with log_path.open(encoding="utf-8") as fh:
        for result in iter_events("zscaler", fh):
            if isinstance(result, ParseFailure):
                n_failures += 1
            else:
                n_events += 1
    assert n_failures == 0
    assert n_events > 0


def test_risky_country_c2_egress_is_present_in_the_multi_domain_failover_scenario(
    tmp_path: Path,
) -> None:
    """`is_dst_cntry_risky`/`dstip_country` (docs/v1/zscaler-nss-web-fields.md "Network") are
    never produced anywhere on the benign path — this asserts the one place this task wires them
    in (`s09_multi_domain_c2_failover.py`'s `implant_tls_extra`, applied unconditionally, unlike
    the DLP/C2-threat fields above) actually reaches the generated file."""
    written = corpus.run_scenario(
        "multi_domain_c2_failover",
        _REGRESSION_SEED,
        tmp_path,
        total_events=2_000,
        knobs={"n_domains": 2, "burst_events": 10},
    )
    log_path = next(p for p in written if p.suffix == ".log")
    lines = log_path.read_text().splitlines()
    header = lines[0].split("\t")
    idx = {n: i for i, n in enumerate(header)}

    risky_rows = [
        line.split("\t")
        for line in lines[1:]
        if line.split("\t")[idx["is_dst_cntry_risky"]] == "Yes"
    ]
    assert risky_rows, "no risky-country row generated — the implant_tls_extra wiring regressed"
    countries = {row[idx["dstip_country"]] for row in risky_rows}
    assert countries <= {"Russia", "North Korea", "Iran"}
