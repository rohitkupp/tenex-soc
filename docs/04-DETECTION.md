# 04 — Detection Layer

The heart of the project. Read fully before implementing anything here.

**Governing rule: every model must beat a simpler baseline on the labeled eval set, or it does
not ship as primary.** Losing is a valid, publishable outcome and a stronger signal than
shipping an unbenchmarked neural net.

Layers run in order, each cheaper than the next stage it feeds:

```
L1 rules (100% of events)  →  L2 signal processing  →  L3 entity-window ML
   →  L5 graph  →  classify  →  fuse & calibrate
```

*A fourth layer, sequence modeling, was designed, built, and benchmarked between L3 and L5, then
cut. It is documented at §L4 below, in its historical slot, because the rejection is a finding —
not renumbered away.*

---

## L1 — Sigma rules

Rules are **Sigma-format YAML** in `detection/rules/*.yml`, not Python. A small evaluator
translates Sigma `detection` blocks into SQL predicates over `events`.

```yaml
title: Large POST to newly-registered domain
id: large-post-new-domain
status: experimental
logsource:
  product: zscaler
  service: proxy
detection:
  selection:
    http_method: 'POST'
    bytes_out: '>10000000'
  filter:
    urlcategory: 'known'
  condition: selection and not filter
level: high
tags:
  - attack.exfiltration
  - attack.t1567
```

Each rule needs a positive and a negative fixture in `tests/fixtures/rules/`.

### Rule inventory

Proxy-only. There is no identity or cross-source table anymore — there is one source, so every
rule in this system is a proxy rule. The rules removed when Okta and CloudTrail were cut freed
capacity that went into more proxy-specific coverage (the last four rows below), not into padding
the L1 count for its own sake — each one covers a distinct field ZScaler exposes that the original
seven did not yet use (`dlpengine`, file extension on `url_path`, `urlcategory`'s anonymizer
class, `riskscore`).

| Rule | ATT&CK |
|---|---|
| Access to malware/phishing/C2 URL category | T1071 |
| Threat name present in event | T1071 |
| Credentials in URL query string | T1552.001 |
| Blocked then allowed to same host within 5m | T1090 |
| Non-browser user agent (curl, python-requests, powershell, wget) | T1105 |
| Large POST (>10MB) to uncategorized or newly-registered domain | T1567 |
| Direct-to-IP HTTP request | T1071.001 |
| DLP engine trigger on an outbound request | T1048.003 |
| Executable/archive download from an uncategorized or newly-registered domain | T1105 |
| Access to anonymizer/VPN/proxy-avoidance URL category | T1090.003 |
| ZScaler risk score ≥ 80 on an otherwise-allowed request | T1071 |

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

**Frequency-domain cross-check, primary.** Bucket the pair's event counts into a uniform
1-minute time series and take the FFT. A true periodic beacon concentrates power in one
frequency bin; interleaved human browsing does not concentrate power anywhere. Flag a dominant
peak when a bin's power exceeds `k` times the mean power of the rest of the spectrum (`k=6`,
tuned on the beaconing difficulty sweep, `docs/11`). This replaces bucketed autocorrelation at a
single guessed lag as the primary cross-check: autocorrelation only tests the lags it is told to
test, and a beacon period that does not land on a bucket boundary is invisible to it, while the
FFT scans every candidate period in one pass. Report the peak's period in seconds.

`explanation`: `{mean_interval, cv, mad_jitter, n_events, duration_h, dominant_period_s,
fft_peak_power_ratio}`.

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

### Seasonal residuals (STL)
The robust z-score above has no model of seasonality — every 5-minute bucket is treated as drawn
from the same distribution, so "unusual" and "off-hours" are indistinguishable without a separate
hardcoded business-hours rule. The brief's own example anomaly — "unusual number of requests from
a single IP in a short time frame" — is fundamentally a time-series volume question, and volume
has daily and weekly seasonality a fixed-window z-score cannot see.

Per entity, decompose the hourly request-volume series with STL (`statsmodels.tsa.seasonal.STL`,
period=24 for daily; a second pass at period=168 for weekly where there is enough history):
```
volume(t) = trend(t) + seasonal_daily(t) + seasonal_weekly(t) + residual(t)
```
Flag entities whose residual is a robust-z outlier (`|z| > 3.5`, same MAD formula as above)
against its own residual distribution. This makes off-hours activity a *modelled deviation from
this entity's own learned rhythm* rather than a fixed 9-to-5 rule — a user who legitimately works
evenings gets a seasonal profile that expects evening volume, so only a deviation from *that*
profile fires. Requires enough history to fit a seasonal profile (~3 weeks minimum); short-lived
entities fall back to the plain robust z-score above.

`explanation`: `{trend, seasonal_component, residual, residual_z, period_used}`.

Sits alongside beaconing in L2, not competing with L3 — L2 asks "is this entity's time series
shaped strangely," L3 asks "is this entity-window's feature vector strange jointly." Scenario 6
(`docs/11`) exists to test that STL catches what the L3 feature-vector models do not; see the
pre-registered prediction in `docs/12`.

### URL path analysis
Per request, score the `url_path` (already normalized off `url`, `docs/03`) for structure rather
than content:
```
path_entropy   = Shannon entropy of the path string
segment_random = fraction of path segments matching a high-entropy token pattern
                 (base64-ish or hex-ish, length ≥ 12)
```
C2 frameworks commonly encode a beacon ID or exfiltrated data in the URL path rather than the
query string — the query-string rule (§L1 above) already covers credentials there, but a path
like `/api/v2/c7f3a9e1b2.../checkin` reads as ordinary REST while carrying near-maximal path
entropy for its length. Flag `(entity, domain)` pairs whose mean `path_entropy` or
`segment_random` sits above the 99.5th percentile of the org-wide distribution for that domain's
category. A domain flagged by both beaconing and URL path analysis is materially stronger
evidence than either alone (§Fusion).

`explanation`: `{mean_path_entropy, segment_random_ratio, sample_paths}` — paths truncated to
256 characters per `docs/06`'s field-truncation rule before this reaches a prompt.

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

### Feature vector (~40 named features)

*Volume:* `n_events`, `n_events_z_vs_own_history`, `n_events_z_vs_cohort`
*Temporal:* `off_hours_ratio`, `weekend_ratio`, `iat_mean`, `iat_cv`, `hour_entropy`, `burstiness`
*Domains:* `n_unique_domains`, `n_rare_domains`, `rare_domain_ratio`,
`rare_domain_ratio_z_vs_own_history`, `rare_domain_ratio_z_vs_cohort`, `n_new_domains_for_user`,
`mean_domain_entropy`, `max_domain_entropy`, `n_newly_registered_domains`
*Transfer:* `bytes_out_sum`, `bytes_out_sum_z_vs_own_history`, `bytes_out_sum_z_vs_cohort`,
`bytes_in_sum`, `out_in_ratio`, `bytes_out_max`, `n_large_uploads`
*HTTP:* `post_ratio`, `blocked_ratio`, `error_ratio`, `n_unique_status_codes`, `direct_ip_ratio`
*Device:* `n_unique_user_agents`, `automation_ua_ratio`, `n_unique_asns`, `n_unique_countries`,
`hosting_provider_ratio`
*Session (derived, not sequence-modeled — see §L4):* `n_sessions`, `mean_session_duration`,
`session_duration_cv`, `requests_per_session_mean`, `n_single_request_sessions`

Sessions here are grouped the same way §L4 would have grouped them for sequence modeling — per
principal, 30-minute idle gap — but only their *shape* is used as quantitative features, not their
*token grammar*. That is the distinction §L4 draws: proxy click-paths are unstable as grammar
(interleaved, low repetitiveness), but session shape is a legitimate quantitative signal — a
scripted exfil tool holds one abnormally long, abnormally uniform session; human browsing produces
many short, bursty ones.

The identity-joined family from the old design (`n_auth_failures`, `n_mfa_challenges`, ...) is
gone — there is no identity source left to join against. That is the largest single removal from
the old ~50-feature vector; the new session family and the entity-relative additions below
partly offset it. As before, the named list above is illustrative, not exhaustive — the old
vector's own per-feature attribution examples (`backend/evals/results.md`) show features
(`non_top_site_ratio`, `high_risk_tld_ratio`, `ua_diversity_ratio`) that were never enumerated in
this document either; the discipline that matters is each family's *relative-variant* coverage,
not hitting an exact count.

**Entity-relative variants are normative, not optional — a measured defect, corrected.** Under
the old multi-source design, this benchmark (M8, `backend/evals/results.md`) ran the ~50-feature
vector against ten scenarios and found **no L3 model detected the low-and-slow exfil scenario**
(then numbered scenario 8, renumbered here to **scenario 4** — `docs/11`): autoencoder AUC-PR
0.008, Isolation Forest 0.002. The cause was structural, not a tuning miss — 47 of those 50
features were absolute/population-level; only three were entity-relative
(`n_events_z_vs_own_history`, `n_events_z_vs_cohort`, `bytes_out_z_vs_own`). `docs/11`'s
scenario-4 acceptance gate guarantees separability *relative to the victim's own benign hours*; a
model trained on absolute features learns the *org-wide* manifold instead, and a low-and-slow
campaign built to look normal for its victim sits comfortably inside that manifold. Both
definitions of "anomalous" are internally correct and they do not compose.

Commercial UEBA baselines per entity and per peer group for exactly this reason. The volume,
transfer, and domain families above therefore each carry both an own-history-relative and a
cohort-relative variant — not just volume, and not just one or the other. This is a structural
requirement, not a tuning knob: the `own_history` variants are what the low-and-slow scenario (4)
needs, and the `cohort` variants (against the entity's department, from `docs/11`'s simulated org)
are what LOF and the peer-group scenario (5) need. A user who adopts another department's behavior
profile can sit inside the org-wide distribution *and* inside their own recent history
simultaneously — only the comparison to their cohort reveals it. Both predictions are
pre-registered and falsifiable, `docs/12`.

### Peer-group cohorts
`*_z_vs_cohort` features and LOF answer a related question two different ways, and both are kept
because they can disagree. The cohort features compare an entity's window against an *explicit*
group — its department, from `docs/11`'s simulated org (`n_departments=8`,
`entities.attrs.department`) — using the same robust z-score as L2 (median/MAD across the
cohort's windows in the same time bucket). LOF compares against an *emergent* neighborhood — its
k-nearest neighbors in the full feature space, department unlabeled. LOF is, in effect, a
formalization of the `ml.peer_group` model this design gestured at but never built (see the M8
report, `backend/evals/results.md`, on why the pooled models missed the low-and-slow scenario);
it is now a first-class model in the table below rather than a forward reference.

Feature code lives in `detection/ml/features.py`. Every feature needs a docstring stating what
attack behavior it is meant to expose.

**Canonical shared definitions.** Two pieces of this feature vector already have a load-bearing,
committed definition, ahead of `detection/ml/features.py` existing: per-user `off_hours_ratio`
(local work hours + timezone, not a fixed UTC window — this org has offices in US-CA, US-NY, and
IE-DU, so a UTC-fixed window misclassifies an ordinary US-CA 9-to-5 as off-hours) and the L2
robust z-score (`0.6745 * (x - median) / MAD`, including an explicit policy for `MAD == 0`, stated
above under "Volumetric burst"). Both live in `app/detection/features.py`
(`is_off_hours`, `robust_z`, plus the entity-window feature names as constants) because
`datagen/scenarios/s04_low_and_slow_exfil.py` — the low-and-slow exfil scenario this feature
vector has to be able to catch through the joint distribution alone — depends on getting them
right to construct a campaign that is invisible to marginals by *proof*, not by tuning; its
regression test imports the same two functions to audit that proof independently. When this
feature vector is implemented at M8, extend `app/detection/features.py` rather than
reintroducing either definition — a third, silently different one is exactly how this bug
recurred before the module existed.

### Models — five hypotheses, benchmark all five

Each model tests a specific, falsifiable claim about where the attack signal lives. The eval
table (`docs/12`) does not merely pick a winner — it reports which hypotheses were true.

| Model | Hypothesis it tests |
|---|---|
| Isolation Forest | Baseline: global outliers via axis-aligned partitioning |
| Mahalanobis / MCD | Linear correlation structure; what commercial UEBA ships |
| ECOD | Per-feature tail probability suffices |
| LOF | Peer-relative anomalies exist that global methods miss |
| Autoencoder | Joint-distribution anomalies exist where no single feature is extreme |

**Isolation Forest** — `n_estimators=200`, `contamination='auto'`, seeded. SHAP for attribution.
The baseline every other model must beat. If nothing beats it, the honest conclusion is that this
population has no structure beyond what axis-aligned splits already find.

**Mahalanobis / MCD** — robust covariance via `MinCovDet`. Tests whether the anomaly is a linear
combination of features moving together (the classic UEBA assumption). Wins when an attack shifts
several correlated features together (e.g. volume and bytes_out); loses when the relationship is
nonlinear or the shift is peer-relative rather than population-relative.

**ECOD** (`pyod.models.ecod`) — Empirical Cumulative Distribution-based Outlier Detection.
Parameter-free (no kernel, no neighbor count, no contamination guess to tune), deterministic (no
seed sensitivity), and O(n·d), so it scores the full population in the time the others take to
scale to a sample. Estimates each feature's empirical CDF and aggregates per-feature tail
probability — its output is already close to a probability rather than an unnormalized
reconstruction error or isolation depth, which matters directly at calibration time (§Fusion).
Tests whether per-feature tail probability is *sufficient* — whether this problem needs joint
structure at all. Should win when an attack is extreme on one or two marginal features and lose
when the attack is only visible in combination — see scenario 4's pre-registered prediction,
`docs/12`.

**LOF** (`pyod.models.lof`, or `sklearn.neighbors.LocalOutlierFactor`) — density ratio of a point
to its k-nearest neighbors. The only model in this table that is *locally* relative rather than
globally relative: a window can sit comfortably inside the org-wide distribution — nothing here is
extreme population-wide — and still be anomalous relative to its local neighborhood. This is the
model the cohort-relative features exist to feed. Tests whether peer-group deviation is a real,
separate failure mode from global outlierness. Scenario 5 (`docs/11`) is built specifically to be
globally normal and locally anomalous — LOF should detect it, and the four global models should
not (pre-registered, `docs/12`).

**Autoencoder** — PyTorch, `50→32→16→8→16→32→50` (Optuna may find a shallower bottleneck wins on
a given corpus — the M8 run did, `backend/evals/results.md`), ReLU, MSE, Optuna-tuned. Tests
whether some attacks are only visible in the *joint* distribution — no single feature or pair is
extreme, but the combination reconstructs badly.
- Train on the clean benign corpus only (`docs/11`), never on the file under analysis
- StandardScaler fit on training corpus, persisted with the model
- Optuna over: latent dim, depth, dropout, LR, batch size, epochs. 50 trials, objective =
  val AUC on held-out labeled scenarios
- Per-feature threshold calibration: for each feature `i`, threshold at the 99.5th percentile of
  `|x_i - x̂_i|` on the benign corpus
- `explanation`: `{total_recon_error, per_feature: [{feature, error, threshold, exceeded}]}`,
  sorted descending — this is what the UI renders as "why this was flagged"

**Known limitation, state it in the README:** every learned model here (Mahalanobis, LOF, and
especially the autoencoder) is fit or trained against a synthetic benign corpus, so it partly
learns our own generator's distribution. Mitigated by grounding the generator in real-world-
derived distributions (domain popularity, UA mix, diurnal curves — `docs/11`). ECOD and Isolation
Forest are less exposed to this — order statistics and partition depth are weaker distributional
assumptions than a fitted covariance or a trained network.

Ship whichever wins on eval as primary; keep the others as ensemble members with fusion weights —
five uncorrelated hypotheses are worth more fused than any one hypothesis is worth alone.

---

## L4 — Sequence models — considered, built, benchmarked, and rejected

This layer does not ship. It was designed, built, and benchmarked before being cut — the
rejection is measured, not just argued, which is a stronger result than either alone.

### Why it was proposed
Identity logs have a native discrete vocabulary (`eventType × outcome`, ~150 tokens) and
per-principal sessions are genuinely grammatical. Some identity attacks — account-takeover
chains — are pure ordering: every event individually legitimate, the sequence is the attack. No
entity-window feature vector can see that. That argument justified building a sequence layer.

### Why it does not survive ZScaler-only scope
The entire justification was identity logs, and identity logs are gone — Okta and CloudTrail are
cut (`docs/03`). Proxy logs were always the weaker substrate for this, and this document said so
before the cut, for two reasons that still hold:
1. Interleaved multi-user browsing produces *unstable sequences* — logs from many independent
   concurrent tasks, low sequence repetitiveness — the documented failure mode for sequence-based
   log anomaly detection.
2. Proxy attack signals are quantitative (timing, volume, string statistics), not ordinal.
   Sequence models are known to underperform on quantitative phenomena; that is what §L2 and §L3
   are for.

### The benchmark, run before the cut
A Markov n-gram baseline and a LogBERT-style transformer (2 encoder layers, `d_model=128`,
4 heads) were both built and evaluated on the identity scenarios that existed under the old,
multi-source design (`backend/evals/results.md`):

| Scenario | Markov F1 | LogBERT F1 | Winner |
|---|---|---|---|
| account_takeover_chain | 0.111 | 0.173 | LogBERT |
| mfa_fatigue | **1.000** | 0.006 | Markov |
| **Pooled** | **0.529** | 0.097 | **Markov** |

Markov beat LogBERT pooled, 0.529 to 0.097 — a small n-gram model outperformed a transformer by
roughly 5x, itself evidence this substrate did not reward model capacity. LogBERT was retrained
8 → 25 epochs specifically to rule out undertraining before accepting the loss; that flipped the
takeover-chain scenario in its favor but left MFA fatigue a near-total failure, so the pooled
verdict stood.

**Neither model detected the account-takeover-chain scenario** — the scenario this layer existed
to catch (the M9 benchmark's scenario 5, since removed along with the rest of the identity
scenario set). The eight genuine `deactivate → activate → token_create` chain sessions scored
~2.08 against a best-F1 threshold of 4.49, and the only session clearing that threshold was an
incidental two-event `session.end → session.end` fragment — a session-boundary artifact, not the
attack.

**Root cause, recorded as historical — the layer is gone, but the finding generalizes to any
future mean-aggregated sequence score:** mean negative log-probability dilutes the one to three
genuinely novel transitions across a long session's ordinary ones, so an ordinary single-event
benign session outranked the actual attack chain. Both models ranked the *designed* transition
correctly as least-probable (`activate → system.api_token.create` at p≈0.024 Markov, ≈0.0035
LogBERT) — the mechanism worked and the aggregation discarded it. Max or top-k transition
surprise, not the mean, is what this formula should have used. Left unfixed, because the layer it
would fix is cut.

### The verdict
Two independent lines of evidence agree: the architectural argument (substrate mismatch), made
before any code was written, and the benchmark (weak pooled F1, zero detection on the scenario
the layer existed to catch), run after. A rejection backed by both is stronger than either alone.
The capacity this freed went into proxy-specific depth instead — infrastructure clustering, URL
path analysis, derived sessionisation, and peer-group baselining (§L2, §L3, §L5, `docs/05`).

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

**Infrastructure clustering, the freed-capacity payoff.** `shared_infra_overlap` is where keeping
a real graph — rather than scoring entities independently — pays for itself on a single-source
system: distinct principals independently contacting the same rare `dst_ip` or domain within a
short window is a strong, cheap signal (shared C2 infrastructure, a compromised upstream resource,
coordinated exfiltration to one drop point), and no single entity-window feature vector can see it
because each principal's own window looks unremarkable in isolation. See `docs/05` for the
construction.

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

**No source bonus here.** The old multi-source design applied a bonus at this stage —
`fused *= 1.25` if an incident spanned proxy and identity signals. With one source, cross-source
corroboration is meaningless and the term is gone outright, not renamed. Cross-**layer**
corroboration (a window flagged by a Sigma rule *and* a signal detector *and* an L3 model is
stronger evidence than any one of them) is a real, different claim, and it is applied exactly
once — at the graph-correlation stage, `docs/05`'s `n_distinct_detector_layers` term — not
duplicated here. Applying it in both places would double-count the same evidence.

### Severity
Thresholds on `fused` (after `docs/05`'s graph bonus is applied): `≥0.85 critical`, `≥0.65 high`,
`≥0.40 medium`, else `low`.
**Set here, never by the LLM.** Research shows LLMs have poor precision on prioritization;
record the LLM's severity opinion separately and report the disagreement rate as a metric.

### Calibration quality
Emit a reliability diagram (predicted vs. observed precision, 10 bins) in the eval report and
on the `/models` page. Brier score is the headline number.
