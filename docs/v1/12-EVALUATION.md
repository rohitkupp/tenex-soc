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
`fp_rate = flagged_benign_entity_windows / total_benign_entity_windows`. Measured for **every**
model in `app.detection.ml.detect.ML_MODEL_FIELDS` — the full six benchmarked L3 models, not only
the three that ship — never just whichever subset a hand-maintained detector list happened to
name; a model silently missing this number is exactly the failure mode that leaves an alert
budget impossible to size (see "Forward changes" below).

Detection-layer aggregates are reported **both ways, labeled, side by side**: the **macro**
mean (the mean of each scenario's own precision/recall/F1 — docs/12's original figure) and the
**pooled/micro** figure (sum TP/FP/FN across scenarios first, divide once). Macro weights a
two-positive scenario the same as a hundred-positive one; pooled does not. Report both — never
silently replace one with the other — plus a full per-model confusion matrix (TP, FP, FN,
FN-per-TP) computed directly from predictions, not backed out of a precision ratio (a model that
flagged nothing in a scenario has a real, countable FP of 0, which precision alone cannot
distinguish from "flagged plenty, all wrong").

### Model comparison — the headline tables

| Table | Contenders | Metric |
|---|---|---|
| L3 unsupervised | Isolation Forest / Mahalanobis (MCD) / ECOD / LOF / EIF / kth-NN | F1 **and** F2, AUC-PR, per-scenario recall, pooled confusion matrix — see "Forward changes" below for the winner rule |
| L2 detectors | Beaconing (CV + FFT) / DGA entropy / Volumetric burst (robust-z) / STL seasonal residual / URL path analysis / Rarity | precision, recall, F1 per detector; degradation curve where swept (`docs/11`) |
| Classification | LightGBM / Claude zero-shot | multiclass accuracy, macro-F1 |

Auto-generated into `evals/results.md`. A model losing its table is a valid result and gets
reported as such — that is a stronger signal than a suspiciously clean win. There is no L4 table:
that layer was built, benchmarked, and cut before this milestone — its numbers live in
`docs/04` §L4 as a historical record, not in the live comparison tables.

### Forward changes

Changes to a pre-registered rule, made **after** the rule was stated but recorded honestly rather
than folded silently into the original text — CLAUDE.md rule 2 treats the winner rule itself as
pre-registered, so a change to it is logged here with a date and rationale, and the result the old
rule produced is reported permanently alongside the new one, never retroactively rewritten.

**2026-08-16 — winner rule changed from mean F1 to mean F2 (`app.detection.ml.evaluate.
WINNER_RULE_CHANGE` is the single source of truth this section restates; `evals/results.md`
renders both every run).**

- **Old rule:** highest mean F1 (precision and recall weighted equally) at the fixed confidence
  threshold, ties broken by mean AUC-PR. Under this rule, on the six-attack-scenario benchmark,
  `ml.ecod` wins — perfectly precise about twelve detections while missing 224, silent through
  most of the attacks in the corpus.
- **New rule:** highest mean F2 (recall weighted 2x precision), same tie-break. This is the rule
  `evals/results.md` uses going forward.
- **Rationale:** F1's equal weighting is the wrong bar for a SOC — a missed breach costs far more
  than a dismissed alert (CLAUDE.md's own governing principle, restated in `docs/04`'s "Shipped
  models vs. benchmark baselines" section, which this harness does not own but which states the
  same problem this change answers). F2 is not recall maximized either: past some false-positive
  ratio, false positives *cause* false negatives, because the analyst stops reading — which is why
  the change is to F2 (a bounded 2x weighting), not to recall alone.
- **What does *not* change:** the old rule's pick is still computed every run
  (`winner_rule_f1_legacy` in `evaluate()`'s return value, and its own labeled row in
  `evals/results.md`) — this is a forward change to which rule *governs going forward*, not an
  edit to what the F1-ranked benchmark already reported.

### Initial fusion weights

`app.detection.fusion.fuse_signals` weights each contributing signal by `detector_stats.
fusion_weight`, and that column defaulted to a uniform 1.0 for every detector until an analyst
had confirmed or dismissed enough alerts for learning mechanism 2 (docs/08 Part 2 §2,
`app.learning.weights.retune_detector_weights`) to run at least once — fusing a detector measured
at 0.003 precision with the same authority as one measured at 0.2, before a single analyst click.
Every run now derives a **seeded** initial weight for the three shipped ML detectors from this
run's own pooled L3 benchmark, using mechanism 2's identical clamp formula
(`clamp(precision_d / prior_precision, 0.25, 1.5)`, `app.learning.weights.clamp_fusion_weight`)
so a seeded value and a later feedback-learned value sit on one scale — see
`app.learning.initial_weights` and `evals/results.md`'s own "Initial fusion weights" section for
the derivation and the numbers this run produced. This is not learning mechanism 2 itself (no
feedback is involved) — it only fixes what mechanism 2's very first run starts adjusting *from*.

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
2. Model comparison tables with winners marked — macro **and** pooled, F1 **and** F2 (see
   "Forward changes"), full confusion matrix, and the initial-fusion-weight derivation
3. Per-scenario detection breakdown
4. Detection curves from the difficulty sweeps
5. Calibration diagram
6. Cost and latency
7. **Known weaknesses** — write this section honestly. Synthetic-data circularity, the
   single-file baseline limitation, scenarios the system misses. Naming your own weaknesses is
   what a senior engineer does, and a reviewer who finds an unlisted weakness trusts everything
   else less.
