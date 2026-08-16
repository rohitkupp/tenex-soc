# 11 — Synthetic Data Generator

Everything downstream depends on this. **Build it early — milestone M2, before any detector.**
You cannot develop or evaluate detection without labeled ground truth.

`backend/datagen/`. Entry point `make gen-data`. Fully seeded and reproducible.

## Outputs

| Artifact | Purpose |
|---|---|
| `data/corpus/benign_*.log` | Large clean corpus for training the autoencoder and other L3 models |
| `data/eval/scenario_*.log` + `.labels.json` | Held-out labeled test files |
| `data/demo/demo_mixed.log` | The file used in the walkthrough recording |

All ZScaler NSS Web format — there is no Okta or CloudTrail emitter to maintain (`docs/03`).

Benign corpus and eval scenarios use **different seeds and different simulated orgs**. Training
on data that shares a generator seed with the test set is the classic way to fake good numbers.

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
```
