# 04 — Detection Layer

The heart of the project. Read fully before implementing anything here.

**Governing rule: every model must beat a simpler baseline on the labeled eval set, or it does
not ship as primary.** Losing is a valid, publishable outcome and a stronger signal than
shipping an unbenchmarked neural net.

Layers run in order, each cheaper than the next stage it feeds:

```
L1 rules (100% of events)  →  L2 signal processing  →  L3 entity-window ML
   →  L4 sequence (identity only)  →  L5 graph  →  classify  →  fuse & calibrate
```

---

## L1 — Sigma rules

Rules are **Sigma-format YAML** in `detection/rules/*.yml`, not Python. A small evaluator
translates Sigma `detection` blocks into SQL predicates over `events`.

```yaml
title: Okta MFA fatigue
id: okta-mfa-fatigue
status: experimental
logsource:
  product: okta
  service: system
detection:
  failures:
    activity_name: 'user.authentication.auth_via_mfa'
    status: 'FAILURE'
  success:
    activity_name: 'user.authentication.auth_via_mfa'
    status: 'SUCCESS'
  timeframe: 15m
  condition: failures | count() by principal >= 5 and success
level: high
tags:
  - attack.credential_access
  - attack.t1621
```

Each rule needs a positive and a negative fixture in `tests/fixtures/rules/`.

### Rule inventory

**Proxy**
| Rule | ATT&CK |
|---|---|
| Access to malware/phishing/C2 URL category | T1071 |
| Threat name present in event | T1071 |
| Credentials in URL query string | T1552.001 |
| Blocked then allowed to same host within 5m | T1090 |
| Non-browser user agent (curl, python-requests, powershell, wget) | T1105 |
| Large POST (>10MB) to uncategorized or newly-registered domain | T1567 |
| Direct-to-IP HTTP request | T1071.001 |

**Identity**
| Rule | ATT&CK |
|---|---|
| Impossible travel (haversine / Δt > 900 km/h) | T1078 |
| Password spray (≥10 distinct principals, ≤3 attempts each, one src_ip, 30m) | T1110.003 |
| Brute force (≥20 failures, one principal, 15m) | T1110.001 |
| MFA fatigue (≥5 MFA failures then success, 15m) | T1621 |
| First login from new country for principal | T1078 |
| MFA factor deactivated | T1556.006 |
| API token created outside business hours | T1098.001 |
| Privilege grant | T1098 |

**Cross-source** — these are the differentiators; they only work because we normalize.
| Rule | ATT&CK |
|---|---|
| Auth failure burst from an IP that also appears in proxy logs contacting a rare domain | T1110 + T1071 |
| Successful login from IP with no prior proxy history for that principal | T1078 |
| Credential reset followed within 1h by large upload by same principal | T1567 |

---

## L2 — Signal processing

Not ML. The right tool for the job, and saying so in the README is a good look.

### Beaconing
Group by `(src_ip, domain)`. Require ≥ 8 events.

```
Δ  = sorted inter-arrival deltas (seconds)
CV = std(Δ) / mean(Δ)                      # low CV ⇒ machine-regular
MADj = median(|Δ - median(Δ)|) / median(Δ) # robust jitter
regularity = 1 - min(CV, 1)
score = regularity * min(n/50, 1) * min(duration_hours/4, 1)
```
Also compute bucketed autocorrelation at the dominant lag as a cross-check.
`explanation`: `{mean_interval, cv, mad_jitter, n_events, duration_h, dominant_lag}`.

### Domain entropy / DGA
On the registrable domain's second-level label:
```
H        = Shannon entropy of character distribution
ngram_ll = mean log-prob under a bigram model fit on data/enrichment/top_domains.txt
score    = sigmoid(w1*H + w2*(-ngram_ll) + w3*digit_ratio + w4*max_consonant_run + w5*len_norm)
```
Fit `w` by logistic regression on a labeled set of known-DGA vs. top-sites domains. Ship the
fitted coefficients as an artifact; do not hardcode magic numbers.

### Volumetric burst
Per `(entity, 5-minute bucket)`, robust z-score — median and MAD, not mean and std, so a single
outlier does not mask the rest:
```
z = 0.6745 * (x - median) / MAD
```
Flag `|z| > 3.5`.

### Rarity / first-seen
```
domain_rarity  = 1 / (1 + org_wide_event_count(domain))
user_novelty   = 1 if (principal, domain) unseen in baseline window else 0
```

---

## L3 — Entity-window ML

### Unit of analysis
`(entity, 1-hour window)` where entity ∈ {principal, src_ip}. **This is the step that turns
categorical logs into the continuous numeric regime these models need.** Raw log lines are
categorical and are never fed to these models directly.

### Feature vector (~50 features)

*Volume:* `n_events`, `n_events_z_vs_own_history`, `n_events_z_vs_cohort`
*Temporal:* `off_hours_ratio`, `weekend_ratio`, `iat_mean`, `iat_cv`, `hour_entropy`, `burstiness`
*Domains:* `n_unique_domains`, `n_rare_domains`, `rare_domain_ratio`, `n_new_domains_for_user`, `mean_domain_entropy`, `max_domain_entropy`, `n_newly_registered_domains`
*Transfer:* `bytes_out_sum`, `bytes_in_sum`, `out_in_ratio`, `bytes_out_max`, `bytes_out_z_vs_own`, `n_large_uploads`
*HTTP:* `post_ratio`, `blocked_ratio`, `error_ratio`, `n_unique_status_codes`, `direct_ip_ratio`
*Device:* `n_unique_user_agents`, `automation_ua_ratio`, `n_unique_asns`, `n_unique_countries`, `hosting_provider_ratio`
*Identity (joined):* `n_auth_failures`, `n_auth_successes`, `auth_failure_ratio`, `n_mfa_challenges`, `n_distinct_geos`, `privilege_events`

Feature code lives in `detection/ml/features.py`. Every feature needs a docstring stating what
attack behavior it is meant to expose.

### Models — benchmark all three

| Model | Config | Role |
|---|---|---|
| Isolation Forest | `n_estimators=200`, `contamination='auto'`, seeded | Baseline. SHAP for attribution. |
| Mahalanobis / RPCA | robust covariance (MCD) | Linear correlation structure; what commercial UEBA ships |
| Autoencoder | PyTorch, `50→32→16→8→16→32→50`, ReLU, MSE, Optuna-tuned | Nonlinear manifold; per-feature reconstruction error = native attribution |

**Autoencoder specifics**
- Train on the clean benign corpus only (`docs/11`), never on the file under analysis
- StandardScaler fit on training corpus, persisted with the model
- Optuna over: latent dim, depth, dropout, LR, batch size, epochs. 50 trials, objective =
  val AUC on held-out labeled scenarios
- Per-feature threshold calibration: for each feature `i`, threshold at the 99.5th percentile of
  `|x_i - x̂_i|` on the benign corpus
- `explanation`: `{total_recon_error, per_feature: [{feature, error, threshold, exceeded}]}`,
  sorted descending — this is what the UI renders as "why this was flagged"

**Known limitation, state it in the README:** trained on a synthetic benign corpus, so the model
partly learns our own generator's distribution. Mitigated by grounding the generator in
real-world-derived distributions (domain popularity, UA mix, diurnal curves). This applies to
every learned model here, not just the autoencoder.

Ship whichever wins on eval as primary; keep the others as ensemble members with fusion weights.

---

## L4 — Sequence models — **identity sources only**

### Why not proxy logs
Deliberate exclusion, and a talking point rather than a gap. Two reasons:
1. Interleaved multi-user browsing produces *unstable sequences* — logs from many independent
   concurrent tasks, low sequence repetitiveness — which is the documented failure mode for
   sequence-based log anomaly detection.
2. Proxy attack signals are quantitative (timing, volume, string statistics), not ordinal.
   Sequence models are known to underperform on quantitative phenomena.

Document this reasoning in the README. It shows per-source modeling judgment.

### Why identity logs work
1. Native discrete vocabulary — `eventType × outcome` *is* the log key. ~150 tokens. No Drain3 needed.
2. Per-principal sessions are genuinely grammatical.
3. **The attacks are ordering patterns.** Every event in an account-takeover chain is individually
   legitimate; the sequence is the attack. No L3 feature vector can see this.

### Sequence construction
Per principal, session = events within a 30-minute idle gap. Truncate/pad to 64 tokens.

### Models — benchmark both

**Markov / n-gram baseline** (`detection/sequence/markov.py`)
- Fit bigram and trigram transition probabilities on benign sessions
- Score = mean negative log-probability of observed transitions
- Fully interpretable: "P(`user.mfa.factor.deactivate` | `user.session.start` from new geo) = 0.0003"
- This is what commercial UEBA ships for pattern anomalies. It is a serious baseline, not a strawman.

**LogBERT-style transformer** (`detection/sequence/logbert.py`)
- 2 transformer encoder layers, `d_model=128`, 4 heads — small, matching the original paper
- Two self-supervised objectives, both required (the paper shows the combination beats either alone):
  - Masked log-key prediction: mask 15% of tokens, predict them
  - Hypersphere objective: minimize volume of normal-session embeddings
- Anomaly score: fraction of masked positions whose true token falls outside the top-`g`
  candidate set (`g=8`), plus distance from hypersphere center
- Must beat the Markov baseline on eval F1 to ship as primary. If it does not, ship Markov and
  report the result.

`explanation` for both: `{surprising_transitions: [{from, to, log_prob}], session_score}`.

---

## L5 — Graph anomaly features

Computed on the entity graph (`docs/05`). Catches what per-entity vectors cannot: lateral
movement and shared infrastructure.

| Feature | Signal |
|---|---|
| `degree`, `weighted_degree` | hub entities |
| `fan_out` | one principal → many rare domains |
| `shared_infra_overlap` | distinct principals converging on the same rare dst |
| `betweenness` | bridging otherwise separate clusters (lateral movement) |
| `clustering_coefficient` | tight suspicious cluster |
| `community_size`, `community_signal_density` | incident-worthiness |

Score via robust z-score against the graph's own distribution.

---

## Classification — LightGBM → ATT&CK

Supervised multiclass over the L3 feature vector plus signal-presence indicators. Trained on
labeled synthetic scenarios (`docs/11`).

- `objective='multiclass'`, classes = the scenario techniques + `benign`
- Class weights to handle imbalance
- SHAP values written to `explanation`
- **Benchmark against Claude zero-shot classification.** Report both accuracies. Expected
  outcome: the trained model wins on labeled techniques, the LLM generalizes better to
  unlabeled ones. Use the model for classification and the LLM for explanation, and justify
  that split with the numbers.

Unsupervised layers catch novelty (things we did not label); the classifier assigns technique.
Both are needed — say so.

---

## Fusion & calibration

The brief asks for a confidence score. Make it a real calibrated probability.

### Per-detector calibration
Each detector's raw score → probability via isotonic regression fit on held-out labeled eval
data. Persist the calibrator per detector. `signals.confidence` is always post-calibration.

### Incident-level fusion
```
fused = 1 - Π (1 - w_d * c_d)     for each contributing signal d
```
where `c_d` is calibrated confidence and `w_d` is `detector_stats.fusion_weight` (updated by
analyst feedback, `docs/08`).

Apply a **multi-source bonus**: an incident containing signals from both proxy and identity
sources gets `fused *= 1.25` (capped at 0.99). Cross-source corroboration is genuinely stronger
evidence and this is where the dual-parser investment pays off.

### Severity
Thresholds on `fused`: `≥0.85 critical`, `≥0.65 high`, `≥0.40 medium`, else `low`.
**Set here, never by the LLM.** Research shows LLMs have poor precision on prioritization;
record the LLM's severity opinion separately and report the disagreement rate as a metric.

### Calibration quality
Emit a reliability diagram (predicted vs. observed precision, 10 bins) in the eval report and
on the `/models` page. Brier score is the headline number.
