# 12 — Evaluation Harness

**The single biggest differentiator in this submission.** Almost no take-home ships evals, and
for an AI/ML role the ability to measure a system is the job.

There is a documented gap in the literature here: existing security-AI benchmarks cover
cybersecurity Q&A, attack helpfulness, and prompt-injection susceptibility, but none directly
measures triage accuracy on alert data, investigation speed, hallucination rates, and
prompt-injection robustness together in an analyst tool. This harness measures all four. Cite
that framing in the README — it turns diligence into contribution.

`backend/evals/`. Entry point `make eval`.

## Metrics

### Detection layer
Per scenario and aggregate, against `malicious_line_numbers`:

```
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2PR / (P + R)
```

Reported **per detector and per layer**, so the benchmark tables are automatic rather than
hand-assembled.

Plus a false-positive rate measured on scenario 8 (benign-but-weird) and on pure benign files:
`fp_rate = flagged_benign_entity_windows / total_benign_entity_windows`.

### Model comparison — the headline tables

| Table | Contenders | Metric |
|---|---|---|
| L3 unsupervised | Isolation Forest / Mahalanobis (MCD) / ECOD / LOF / Autoencoder | F1, AUC-PR, per-scenario recall |
| L2 detectors | Beaconing (CV + FFT) / DGA entropy / Volumetric burst (robust-z) / STL seasonal residual / URL path analysis / Rarity | precision, recall, F1 per detector; degradation curve where swept (`docs/11`) |
| Classification | LightGBM / Claude zero-shot | multiclass accuracy, macro-F1 |

Auto-generated into `evals/results.md`. A model losing its table is a valid result and gets
reported as such — that is a stronger signal than a suspiciously clean win. There is no L4 table:
that layer was built, benchmarked, and cut before this milestone — its numbers live in
`docs/04` §L4 as a historical record, not in the live comparison tables.

### Pre-registered predictions

Stated before the eval runs, so a result that contradicts one is reported as a contradiction, not
quietly reframed afterward. Scenarios 4, 5, and 6 (`docs/11`) exist specifically to test these.

| # | Prediction | Falsified if |
|---|---|---|
| 1 | Scenario 4 (low-and-slow exfil): the autoencoder detects it; ECOD does not — ECOD aggregates per-dimension tails and nothing in this scenario sits in a marginal tail by construction. | ECOD also detects it at comparable recall. If so, the autoencoder has no remaining justification on this scenario and should be cut from primary contention — a good outcome arrived at honestly, not a failed prediction. |
| 2 | Scenario 5 (peer-group deviation): LOF detects it; the four global L3 models (Isolation Forest, Mahalanobis, ECOD, Autoencoder) do not. | Any global model detects it at recall comparable to LOF. |
| 3 | Scenario 6 (seasonal deviation): STL residuals detect it; none of the five L3 feature-vector models do — the signal lives in a time series, and L3's per-window snapshot does not represent it. | Any L3 model detects it via the entity-window feature vector. |

Report all three against measured results in the same table as the headline benchmark. A
falsified prediction goes in the report next to the confirmed ones, not buried in prose — the
point of pre-registering is that it cannot be quietly dropped if it turns out wrong.

### Correlation
```
incident_recall = scenarios whose malicious events landed in one incident / total
fragmentation   = mean incidents per scenario (target 1.0)
```

### Agent
```
disposition_accuracy = correct / total   (vs. expected_disposition)
technique_accuracy   = correct technique mapping / total
hallucination_rate   = invalid_citations / total_citations
citation_density     = cited_claims / total_claims
severity_disagreement = LLM opinion ≠ fusion severity / total
```

`severity_disagreement` is reported deliberately — it is the evidence behind the decision to keep
prioritization out of the LLM's hands.

### Robustness
```
injection_resistance = scenarios where disposition is unchanged with the canary present / total
```
Must be 1.0. Any failure fails the build.

### Calibration
Reliability diagram (10 bins, predicted vs. observed precision) and Brier score. A confidence
score that is not calibrated is a number, not a probability.

### Cost & latency
p50 / p95 end-to-end pipeline latency, p50 / p95 agent latency, mean tokens and USD per
incident, and the funnel reduction ratio (`events → signals → incidents → triaged`).

## Harness structure

```
evals/
├── run.py               # orchestrates, writes results.md + eval_runs row
├── golden/              # frozen scenario files + labels, version-controlled
├── metrics/
│   ├── detection.py
│   ├── correlation.py
│   ├── agent.py
│   ├── calibration.py
│   └── cost.py
├── baselines.json       # current promoted-model scores for regression comparison
└── results.md           # generated
```

Agent evaluation uses **recorded LLM responses** from `tests/fixtures/llm/` by default so CI
needs no API key and results are deterministic. `--live` re-records deliberately.

## Regression gate

```bash
make eval          # exits 1 if any gated metric regresses beyond tolerance
```

| Metric | Tolerance |
|---|---|
| Detection F1 (aggregate) | −0.02 |
| Incident recall | −0.02 |
| Disposition accuracy | −0.05 |
| Hallucination rate | +0.01 |
| Injection resistance | any drop below 1.0 |
| Brier score | +0.02 |

Wired into GitHub Actions on every PR, and into the retrain promotion path (`docs/08`). A
candidate model that regresses is rejected and the incumbent stays live.

Keep the rejection history — evidence the gate actually bites is worth more than a clean record.

## Report

`evals/results.md` is a deliverable, referenced from the README. Structure:

1. Summary table — every gated metric, current vs. baseline, pass/fail
2. Model comparison tables with winners marked
3. Per-scenario detection breakdown
4. Detection curves from the difficulty sweeps
5. Calibration diagram
6. Cost and latency
7. **Known weaknesses** — write this section honestly. Synthetic-data circularity, the
   single-file baseline limitation, scenarios the system misses. Naming your own weaknesses is
   what a senior engineer does, and a reviewer who finds an unlisted weakness trusts everything
   else less.
