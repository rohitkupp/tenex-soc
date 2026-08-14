# 11 — Synthetic Data Generator

Everything downstream depends on this. **Build it early — milestone M2, before any detector.**
You cannot develop or evaluate detection without labeled ground truth.

`backend/datagen/`. Entry point `make gen-data`. Fully seeded and reproducible.

## Outputs

| Artifact | Purpose |
|---|---|
| `data/corpus/benign_*.log` | Large clean corpus for training the autoencoder and sequence models |
| `data/eval/scenario_*.log` + `.labels.json` | Held-out labeled test files |
| `data/demo/demo_mixed.log` | The file used in the walkthrough recording |

Benign corpus and eval scenarios use **different seeds and different simulated orgs**. Training
on data that shares a generator seed with the test set is the classic way to fake good numbers.

## Realism grounding

The synthetic-data circularity problem is real: a model trained on our generator learns our
generator. Mitigate by grounding distributions in real-world data rather than inventing them.

| Property | Source |
|---|---|
| Domain popularity | Zipf sample over a bundled top-sites list |
| User-agent mix | Real-world browser share table |
| Diurnal activity | Business-hours curve with weekend dropoff and per-user jitter |
| Response sizes | Log-normal fit to realistic web content sizes |
| Okta event mix | Proportions from documented enterprise tenant patterns |
| Geography | Weighted by simulated org office locations |

State this mitigation, and its limits, in the README.

## Simulated org

```python
Org(n_users=250, n_departments=8, offices=["US-CA","US-NY","IE-DU"],
    n_service_accounts=12, saas_apps=[...], seed=...)
```

Per user: home ASN, home country, work hours, department, a personal domain affinity set, a
device fingerprint. Service accounts get machine-like patterns — regular intervals, automation
user agents, high volume — because they are the dominant source of realistic false positives and
the model needs to learn them as normal.

## Scenarios

Each emits events into the benign stream and records ground truth.

| # | Scenario | Sources | ATT&CK | What must fire |
|---|---|---|---|---|
| 1 | C2 beaconing | proxy | T1071.001 | beaconing, DGA, rare domain |
| 2 | Data exfiltration | proxy | T1567.002 | volumetric burst, out/in ratio, newly-registered domain, autoencoder |
| 3 | Password spray → success → new-geo browsing | okta + proxy | T1110.003, T1078 | spray rule, cross-source rule |
| 4 | Impossible travel | okta | T1078 | impossible travel rule |
| 5 | Account takeover chain | okta | T1556.006, T1098.001 | **sequence model** — each event legitimate, ordering is the attack |
| 6 | MFA fatigue | okta | T1621 | MFA fatigue rule, sequence model |
| 7 | Insider mass download | proxy | T1530 | volumetric, peer-group deviation |
| 8 | Low-and-slow exfil | proxy | T1567 | autoencoder (correlation structure), not thresholds |
| 9 | Prompt injection canary | proxy | — | disposition must be unchanged vs. control |
| 10 | Benign-but-weird | proxy + okta | — | must **not** fire — sanctioned backup job, new hire onboarding, pen-test window |

Scenario 8 exists specifically to test whether the autoencoder earns its slot: low-and-slow
exfil is invisible to per-feature thresholds and only detectable through the joint distribution.
Scenario 10 is the false-positive control and matters as much as the attacks.

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
| Benign corpus | ~2M (proxy) + ~200k (okta) |
| Eval scenario file | ~50k, one scenario each |
| Demo file | ~150k, three scenarios plus scenario 10 |

The demo file should take under two minutes end to end. Time it.

## CLI

```bash
python -m datagen benign  --events 2000000 --seed 42 --out data/corpus/
python -m datagen scenario --name c2_beaconing --seed 7 --out data/eval/
python -m datagen sweep   --scenario c2_beaconing --param jitter_pct --range 0.02:0.6:0.05
python -m datagen demo    --out data/demo/
```
