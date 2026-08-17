# 11 — Synthetic Data Generator

Everything downstream depends on this. **Build it early — milestone M2, before any detector.**
You cannot develop or evaluate detection without labeled ground truth.

`backend/datagen/`. Entry point `make gen-data`. Fully seeded and reproducible.

## History: one generator, not two

For a period this repo carried **two independently hand-maintained generators** for the same
output. `datagen/generate_corpus.py` (delivered per `docs/v2_migration` change 13, wiring the
train/validation/golden split below into `make gen-data`) wrote
`datetime.strftime("%Y-%m-%d %H:%M:%S")`. Every other command in this document — `benign`,
`scenario`, `demo`, and the `datagen/emitters/zscaler.py` module all of them share — writes ISO
`...THH:MM:SSZ`, which is the only format `app/parsers/zscaler.py` accepts. Nobody tied the two
back together with a test, so they drifted silently: **every one of the 271 files under
`backend/data/corpus/` plus the 30 under `backend/data/eval/golden/` was 100% `ParseFailure`, 0
events.** A reviewer running `make gen-data` and uploading the result got nothing.

The fix was not a format patch. `generate_corpus.py` is deleted. The one artifact only it
produced — the labeled train/validation/golden split, `manifest.json`, and the 6-month
`data/baseline/` rollup — is now built on top of the same `datagen` package every other command
in this document uses (`datagen/labeled_corpus.py`), so there is exactly one place a log line's
shape gets decided. `tests/test_parsers_zscaler.py::test_every_registered_scenario_parses_with_zero_failures`
is the regression test: it generates one file per registered scenario through the real generator
and asserts the real parser reads it back with zero failures, so a future scenario module (or a
future emitter timestamp change) that breaks this contract fails in seconds instead of shipping
another unparseable corpus.

## Outputs

| Artifact | Purpose |
|---|---|
| `data/corpus/benign_*.log` | Large clean corpus for training the L3 models |
| `data/eval/scenario_*.log` + `.labels.json` | Held-out labeled test files, one scenario each |
| `data/demo/demo_mixed.log` | The file used in the walkthrough recording |
| `data/corpus/{train,val}_NNNN_<scenario>.log` + `.labels.json`, `data/eval/golden/golden_NNNN_<scenario>.log` + `.labels.json`, `data/corpus/manifest.json` | The labeled train/validation/golden split (`python -m datagen split`, docs/v2_migration change 13) — see below |
| `data/baseline/baseline_{windows.jsonl,profiles.json,contacts.json}` | 6-month per-tenant history, loaded by `app.baseline.loader` into the `baseline_*` tables (`make seed`) |

All ZScaler NSS Web format — there is no Okta or CloudTrail emitter to maintain (`docs/03`).

Benign corpus and eval scenarios use **different seeds and different simulated orgs**. Training
on data that shares a generator seed with the test set is the classic way to fake good numbers.

## Full width, and the 25/52-of-181 extraction contract

Every ZScaler line this generator writes carries **all 181 fields**
`docs/v1/zscaler-nss-web-fields.md` documents from the NSS Web Logs feed reference, not just the
ones the application reads. `app/parsers/zscaler.py` extracts exactly 52 of them by name
(`bind_header` rebinds column order from the file's own header row, so position within the row
never matters, only presence) — docs/03's original 25, plus 27 more promoted across two later
changes (7 device/asset fields, 20 detection-relevant TLS/threat/network fields). The other ~129
are catalogued in the field-reference doc and generated with realistic, internally consistent
values, but deliberately **not** parsed: CLAUDE.md's "do not add a tag just because a field
exists" applies equally to a raw field with no tag, detector, or citation behind it yet.

The point of carrying the full width in the *generator* while the *parser* stays narrow is to make
the extraction step itself testable. A real customer's NSS feed is configured with however many
fields their admin turned on — commonly upward of a hundred — and a parser that positions its 52
fields correctly on a 32-column test file can still mis-position on a 181-column one if extraction
were ever accidentally positional rather than header-driven. `backend/tests/
test_zscaler_full_width_catalogue.py` is the regression test: it generates through this full-width
path, parses with the real `ZScalerParser`, and specifically checks fields from the *last five*
columns (`recordid`, `pcapid`, `productversion`, `nsssvcip`, `eedone`) against the values the
generator wrote there — the position in the row a field-order bug would show up first and, before
that test existed, nowhere else.

**Internal consistency, not just breadth.** A wide row that contradicts itself between two columns
(`totalsize` not equal to `reqsize + respsize`, a `403` status next to `action=Allowed`,
`threatseverity` disagreeing with the `riskscore` band that is supposed to set it) reads as fake
data the moment a reviewer greps two columns side by side. Every full-width field is *derived*
from a field the emitter already set (`_apply_wide_fields` in `datagen/emitters/zscaler.py`) —
`reqhdrsize + reqdatasize == requestsize` by construction, `dlpdicthitcount` always carries one
`|`-delimited count per entry in `dlpdict`, `dlpidentifier`/`exempt_dlpidentifier` are enforced
mutually exclusive, `cintip`/`cpubip` mirror `clientip` (this generator models no additional
internal-NAT hop, stated rather than silently assumed) — never drawn independently. Two real bugs
surfaced and were fixed while wiring this up, both pre-existing rather than introduced by the
widening itself: `status=403` was reachable through the *ordinary* status-code pool as well as the
URL-filter-block path, so an unblocked request could carry `action=Allowed` next to it (`403` is
now block-only); and `bypassed_traffic`/`ssldecrypted` were drawn independently, so a request could
claim to have both skipped the Client Connector *and* been SSL-inspected by it in the same line.

Every documented enum stays inside its documented value set (`flow_type`, `deviceostype`,
TLS versions, certificate validity bands, ...); a field the doc says is conditional stays
conditional (`df_hostname`/`df_hosthead` only on a domain-fronting mismatch — never populated by
this generator's benign path, by design; `userlocationname` only for Zero Trust Browser traffic,
which this org never routes through, so always absent). `is_dst_cntry_risky = Yes` is otherwise
unreachable anywhere in this corpus — `s09_multi_domain_c2_failover.py`'s C2 implant traffic is
the one place it's wired in (a fixed draw from `RISKY_COUNTRIES`, held constant across every
sibling domain the same way its JA4 fingerprint is). The DLP-dictionary and encrypted-archive
fields (`s02_data_exfiltration.py`'s `_DLP_FIELDS`) only populate when that scenario is
constructed with `blend_with_normal_traffic=False` — every call site in the labeled corpus and the
CLI uses the default `True`, so that code path is real and tested
(`test_zscaler_full_width_catalogue.py` exercises it directly) but does not appear in the
committed corpus/samples files; a reviewer grepping those files for `dlpdict` will not find it.

## Realism grounding

The synthetic-data circularity problem is real: a model trained on our generator learns our
generator. Mitigate by grounding distributions in real-world data rather than inventing them.

| Property | Source |
|---|---|
| Domain popularity | Zipf sample over a bundled top-sites list |
| User-agent mix | Real-world browser share table, **desktop rows only** for human principals (see below) |
| Diurnal activity | Business-hours curve with weekend dropoff and per-user jitter |
| Response sizes | Log-normal fit to realistic web content sizes |
| Geography | Weighted by simulated org office locations |

State this mitigation, and its limits, in the README.

**Known limit — human user agents are desktop-only.** `Org._build_users` draws every human's
device fingerprint through `UserAgentMix.sample_desktop()`, which filters `_BROWSER_SHARE` to
`device_type == "desktop"` before sampling. Chrome/Android, Safari/iOS, and Samsung Internet carry
26.3 of the table's 100 share points and are therefore unreachable by any human principal: the
emitted corpus is real-world-proportioned *among desktop browsers*, not against the whole table.
Service accounts are unaffected (they carry automation UAs by design).

This is documented rather than fixed, deliberately. No detector in the system reads mobile-vs-
desktop — the user-agent features are `is_browser_ua` and UA rarity — while changing the generator
would change the emitted corpus for a given seed and invalidate every number in
`evals/results.md`. `tests/test_datagen_realism_perf.py` holds the gap in place with an
`xfail(strict=True)`, so closing it later forces this paragraph to be removed with it.

## Simulated org

```python
Org(n_users=250, n_departments=8, offices=["US-CA","US-NY","IE-DU"],
    n_service_accounts=12, saas_apps=[...], seed=...)
```

Per user: home ASN, home country, work hours, department, a personal domain affinity set, a
device fingerprint. Service accounts get machine-like patterns — regular intervals, automation
user agents, high volume — because they are the dominant source of realistic false positives and
the model needs to learn them as normal.

`n_departments=8` is not decorative — it is the cohort assignment `n_events_z_vs_cohort` and
peer-group LOF (`docs/04` §L3) baseline against, and what scenario 5 below is built to defeat.

## Scenarios

Each emits events into the benign stream and records ground truth. All proxy — there is no
`Sources` column anymore, because there is nothing to vary it against.

| # | Scenario | ATT&CK | What must fire |
|---|---|---|---|
| 1 | C2 beaconing | T1071.001 | beaconing, DGA, rare domain |
| 2 | Data exfiltration | T1567.002 | volumetric burst, out/in ratio, newly-registered domain |
| 3 | Insider mass download | T1530 | volumetric, peer-group deviation |
| 4 | Low-and-slow exfil | T1567 | **autoencoder only** — no single feature in a tail |
| 5 | Peer-group deviation | T1078 | **LOF** — a user adopting another department's behaviour profile. Globally normal, locally anomalous. Every feature sits inside the org-wide distribution; only the comparison to the user's own cohort reveals it. |
| 6 | Seasonal deviation | T1029 | **STL residuals** — sustained off-hours and weekend volume that is unremarkable in daily aggregate. Defeats robust-z on 5-minute buckets, which has no seasonality model. |
| 7 | Prompt injection canary | — | disposition unchanged vs. control |
| 8 | Benign-but-weird | — | must **not** fire — sanctioned backup job, new-hire onboarding, pen-test window |

Scenarios 3, 4, 5, and 6 are the analytical core of this submission — four different, falsifiable
answers to "what does normal mean" (population-wide, this-entity's-own-history, peer-cohort, and
seasonal-rhythm, respectively), each paired with the one model built to answer it.

Scenario 4 exists specifically to test whether the autoencoder earns its slot: low-and-slow exfil
is invisible to per-feature thresholds and only detectable through the joint distribution — and
per the pre-registered prediction (`docs/12`), ECOD should **not** detect it. If ECOD also wins
it, the autoencoder has no remaining justification and should be cut — a good outcome arrived at
honestly.

Scenarios 5 and 6 are new, replacing the four identity scenarios this design used to carry
(password spray, impossible travel, account-takeover chain, MFA fatigue — all deleted along with
Okta). Scenario 5 isolates peer-group deviation to test whether LOF's locally-relative view
catches what the four globally-relative L3 models miss. Scenario 6 isolates seasonal deviation to
test whether STL's model of an entity's own daily/weekly rhythm catches what a robust z-score over
flat 5-minute buckets misses. Both are pre-registered predictions, `docs/12`.

Scenario 8 is the false-positive control and matters as much as the attacks; its benign-but-weird
half (new-hire onboarding, pen-test window) previously had an Okta counterpart — dropped along
with the source, kept as a purely proxy-shaped false-positive test (a burst of new-domain browsing
that looks like reconnaissance but is a new hire's first week, or an automated scan pattern that
looks like a bot but is a scheduled pen test).

### Two more, labeled-corpus only

The labeled train/validation/golden split below carries two additional scenario identities that
predate this table (`generate_corpus.py`'s original eleven) and have no L3-model-vs-baseline
story of their own — they exercise correlation and Sigma rules rather than a specific ML model,
so they are not part of the eight above but are registered `Scenario` subclasses like the rest.

| # | Scenario | ATT&CK | What must fire |
|---|---|---|---|
| 9 | Multi-domain C2 failover | T1008 | beaconing, rarity, `graph.shared_infra` — several short-lived sibling domains sharing one address block, each burst too short for `signal.beaconing` alone to carry, so detection depends on the graph tying them together |
| 10 | Web shell / secret-file probing | T1505.003 | rarity, `sigma.blocked_then_allowed` — a dictionary walk of shell/secret-file paths against one rarely-visited host, mostly blocked with an occasional `200` close behind a block |

Plus an eleventh identity with no `Scenario` subclass at all: a pure `benign` file (background
traffic only, nothing injected) — the false-positive floor `benign_but_weird` is deliberately not
(`benign_but_weird` is suspicious-*shaped* benign traffic; plain `benign` is nothing unusual at
all). `datagen/labeled_corpus.py`'s `_write_benign` builds it directly rather than through a
`Scenario` subclass, since there is no injection behaviour to encapsulate.

## Ground truth format

```json
{
  "scenario_id": "c2_beaconing_001",
  "technique": "T1071.001",
  "malicious_line_numbers": [4021, 4108, ...],
  "primary_entity": {"type": "user", "value": "jdoe@corp.example"},
  "expected_detectors": ["signal.beaconing", "signal.dga", "ml.autoencoder"],
  "expected_disposition": "true_positive",
  "must_correlate_into_one_incident": true,
  "notes": "60s interval, 12% jitter, 6h duration, DGA domain"
}
```

`must_correlate_into_one_incident` is what lets the harness measure incident-level recall —
whether the graph actually pulled related events together rather than fragmenting them.

## Parameterization

Every scenario takes difficulty knobs so the eval can report a detection curve rather than a
single number:

```python
BeaconingScenario(interval_s=60, jitter_pct=0.12, duration_h=6, n_beacons=360,
                  domain_style="dga", blend_with_normal_traffic=True)
```

Sweep jitter from 0.02 to 0.60 and report where detection degrades. A curve is far more
informative than a point estimate, and it shows you understand your own detector's limits.

## Volume targets

| Artifact | Events |
|---|---|
| Benign corpus | ~2M (proxy) |
| Eval scenario file | ~50k, one scenario each |
| Demo file | ~150k, three scenarios plus scenario 8 |

The demo file should take under two minutes end to end. Time it.

## CLI

```bash
python -m datagen benign  --events 2000000 --seed 42 --out data/corpus/
python -m datagen scenario --name c2_beaconing --seed 7 --out data/eval/
python -m datagen sweep   --scenario c2_beaconing --param jitter_pct --range 0.02:0.6:0.05
python -m datagen demo    --out data/demo/
python -m datagen split   --out data/ --files 1000              # make gen-data's target
python -m datagen split   --out data/ --files 40 --skip-baseline # small local check
```

## The labeled train/validation/golden split

`python -m datagen split` (`datagen/labeled_corpus.py`, `make gen-data`) is the one command that
does not appear in the CLI block above: it writes the full labeled corpus that `backend/evals/`
and `app/detection/ml/train.py`/`evaluate.py` benchmark against, not a single eval file.

Three named splits, each a **different seed and a different simulated org** (sharing either
between splits is how synthetic benchmarks fake good numbers, same rule as `benign` vs.
`scenario` above): `train` (org `northwind`, seed 42, 70%), `val` (org `contoso`, seed 1337, 20%),
`golden` (org `fabrikam`, seed 90210, 10%) — `data/corpus/train_NNNN_<scenario>.log` /
`val_NNNN_<scenario>.log`, `data/eval/golden/golden_NNNN_<scenario>.log`, each with a `.labels.json`
sidecar in the ground-truth format above, plus one `data/corpus/manifest.json` covering all three
splits (`splits`, `scenario_counts`, `files`).

File count defaults to 1000 (`--files`, `FILES=n` on `make gen-data`) but the largest split always
reserves its first few slots — one per scenario identity — before falling back to the normal
weighted-random draw for the rest, so even a small `--files` run still proves every scenario type
is represented rather than leaving a low-weight scenario (`prompt_injection_canary` at 3%) to
maybe never appear. The three scenarios with a real statistical acceptance check (`peer_group_
deviation`, `seasonal_deviation`, `low_and_slow_exfil`) get a higher background-event floor than
the rest for the same reason — verified empirically to need it to reliably clear their own gate.

`--skip-baseline` writes the corpus only, skipping the slower `data/baseline/` 6-month rollup —
`make gen-data-quick`'s mode, for a fast local check that a change didn't break generation.
