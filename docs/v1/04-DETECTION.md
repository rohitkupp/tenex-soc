# 04 — Detection Layer

The heart of the project. Read fully before implementing anything here.

**Governing rule: every model must beat a simpler baseline on the labeled eval set, or it does
not ship as primary.** Losing is a valid, publishable outcome and a stronger signal than
shipping an unbenchmarked neural net.

Layers run in order, each cheaper than the next stage it feeds:

```
L1 rules (100% of events)  →  L2 signal processing  →  L3 entity-window ML
   →  L5 graph  →  fuse & calibrate
```

*A fourth layer, sequence modeling, was designed, built, and benchmarked between L3 and L5, then
cut. It is documented at §L4 below, in its historical slot, because the rejection is a finding —
not renumbered away.*

**`MIGRATION-01-evidence-first.md` supersedes parts of this document — read it alongside this
one; where the two disagree, the migration wins.** Three changes to the pipeline above and to the
model roster below, applied and reflected here:

- **No `classify` stage.** The old diagram was `L5 graph → classify → fuse & calibrate`, where
  `classify` was a LightGBM multiclass technique classifier (`app.graph.classifier`, now
  deleted). Multiclass technique attribution is the LLM hypothesis-evaluation stage's job now
  (`docs/07`, "hypothesis evaluation replaces free generation") — see §Classification below for
  why keeping both was actively worse than picking one.
- **Autoencoder removed from L3.** §L3's model table below is four models, not five — see
  "Models — four hypotheses" for why, and for what is expected to eventually replace the job it
  did.
- **Navigation chain extractor added to L3.** Change 18 rejected building a sequence model for
  this corpus (§L4 already covers that rejection) but commissioned a small, deterministic
  referer-chain reconstruction instead — see "Navigation chain extractor" under §L3.

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

### Navigation chain extractor

Migration change 18 (`docs/v2_migration/MIGRATION-01-evidence-first.md`) considered, and rejected,
building a sequence model for this corpus — see §L4 below for that rejection in full (it stands;
the migration did not reopen it). But it commissioned this extractor as, in the migration's own
words, "the part of the sequence idea that pays for itself": the HTTP `Referer` header is not a
learned transition probability, it is the browser's own ground-truth statement of which page a
request followed. Reconstructing a chain from it needs bookkeeping, not a model — deterministic,
cheap, and it recovers real structural evidence (how a user actually got somewhere) that §L4's
per-window feature vector cannot see on its own.

**Referer field availability, stated plainly.** The ZScaler `referer` field is parsed end to end
into `HttpRequest.referrer` on every `HTTPActivity` (`app/parsers/zscaler.py`, `app/ocsf/
common.py`) and does survive into the persisted `events.ocsf` JSONB (`app/pipeline/stages/
parse.py`'s `model_dump()`) — but nested under `ocsf->'http_request'->>'referrer'`, not a
top-level JSONB key and **not a docs/02 hot column** on the `events` table (only `principal`/
`src_ip`/`domain`/`url_path`/`action`/... are — see `app/models/event.py`). It was not, before
this extractor, read into either L2's DB-backed `EventRow` or L3's `MLEvent`. This is the same
"real field, no hot-column home" situation `urlcategory` is already in (§L2 "URL path analysis").

**Where it lives, and why.** `app/detection/ml/navigation.py`, feeding `app/detection/ml/
features.py` directly — not `app/detection/signal/` (L2), even though its "not ML, deterministic
bookkeeping" character matches that layer's own philosophy. L2's `EventRow` is deliberately five/
six columns wide and has no path to `referrer` without either a docs/02 migration to add a hot
column or an unindexed per-row JSONB path extraction. `app/detection/ml/events.py` is the one
place in the detection package that already reads the *parsed OCSF object* directly, bypassing
the hot-column path entirely (the same route `MLEvent.department` already takes) — extending it
was the only option that does not invent a new persistence column this document does not own.

**Entity scope.** Reconstructed per `principal` only, never per `src_ip` — the same reasoning
§L3's department-cohort fallback already gives: a `src_ip` can be a shared egress point NAT'd
across many concurrent principals, and interleaving several people's independent referer chains
into one "sequence" is exactly the multi-user disorder §L4's rejection is about. The feature
family is zero-filled for the `src_ip` entity dimension, a stated scope cut, not an oversight.

**The five features**, per-event, aggregated into the `(entity, hour)` grain the rest of L3 uses
(ratio/mean for the four boolean/numeric ones, distinct-count for `entry_domain`):

| Feature | Meaning |
|---|---|
| `referer_less_deep_path` | arrived at a multi-segment path with no referer at all — the shape of a typed/bookmarked/scripted request, not a click-through |
| `navigation_depth` | verified hops from this chain's entry point, by referer linkage |
| `entry_domain` | the registrable domain this chain is attributed to having started from |
| `cross_domain_redirect_chain` | a *verified*, in-chain hop whose referer domain differs from the domain it landed on — the typosquat → legitimate-site handoff shape |
| `download_without_navigation` | a downloadable-extension path fetched at `navigation_depth == 0` — no preceding page load in this chain |

A session (30-minute idle gap per principal — the same boundary the session feature family above
already uses) resets all in-progress chain state; within a session, a referer only counts as
continuing a chain if its domain was itself verifiably observed on this principal's own traffic
already — an external link or a stale/unrelated referer starts a fresh chain at depth 0 rather
than being trusted at face value. See `app/detection/ml/navigation.py`'s own module docstring for
the exact reconstruction algorithm, and `tests/test_ml_navigation.py` for a fire/no-fire fixture
pair per feature.

### Models — four hypotheses, benchmark all four

Each model tests a specific, falsifiable claim about where the attack signal lives. The eval
table (`docs/12`) does not merely pick a winner — it reports which hypotheses were true.

**Post-migration roster (`docs/v2_migration/MIGRATION-01-evidence-first.md` change 19).** The
autoencoder is gone (below), and the migration names a target roster this document records but
does not yet build: **EIF** (Extended/oblique Isolation Forest) and **kth-NN** ship as primary,
alongside **LOF** and the **DGA logistic regression** (§L2) with **isotonic calibrators**
(§Fusion) turning every raw score into a probability. **Isolation Forest, ECOD, and Mahalanobis
are explicitly retained — as benchmarked baselines, not shipped primary** — so EIF has to prove
oblique splitting earns its cost against them, and `docs/12`'s hypothesis-outcome table keeps its
contenders. **EIF and kth-NN are not built in this phase** ("Do not build EIF or kth-NN — that is
a later phase," the migration's own words) — until they land, the table below is what actually
ships, all four as benchmarked, undifferentiated ensemble members:

| Model | Hypothesis it tests |
|---|---|
| Isolation Forest | Baseline: global outliers via axis-aligned partitioning |
| Mahalanobis / MCD | Linear correlation structure; what commercial UEBA ships |
| ECOD | Per-feature tail probability suffices |
| LOF | Peer-relative anomalies exist that global methods miss |

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
globally normal and locally anomalous — LOF should detect it, and the three other (global) models
should not (pre-registered, `docs/12`).

**Autoencoder — removed.** Shipped as a fifth model through this milestone's own development
window (PyTorch, `50→32→16→8→16→32→50`, Optuna-tuned, per-feature reconstruction-error
attribution — see `backend/evals/results.md` for the M8 numbers this doc used to cite here), then
cut by migration change 19. Two justifications, both absorbed elsewhere rather than simply
dropped:

- **Per-feature reconstruction attribution** answered "why was this flagged." Change 2 of the
  migration gave that job to deterministic evidence extractors instead, which produce
  measurements and historical percentiles directly rather than an error term a human has to
  interpret.
- **Joint-distribution anomalies where no single feature is in a tail** — the hypothesis this
  model's whole design existed to test — is what EIF's oblique splits are meant to address
  instead, and this document had already committed to the rule that decided it: *"if EIF matches
  the autoencoder, the autoencoder is cut."* The migration answered that question before EIF's
  own benchmark ran, on the architectural argument alone — a tree that partitions on linear
  combinations of features can, in principle, capture the same non-axis-aligned structure a
  reconstruction error can, at a fraction of the training cost and with a SHAP-attributable split
  path instead of a per-feature error vector.

This is a **reportable outcome, not a retreat**: the model was built, benchmarked, and shipped
honestly, and then deleted once better-suited components existed to absorb its two jobs — exactly
the discipline CLAUDE.md asks for ("losing is a valid, reportable outcome"), just with the losing
model identified by design reasoning instead of only by an eval number.

**Known limitation, state it in the README:** every learned model here (Mahalanobis and LOF) is
fit or trained against a synthetic benign corpus, so it partly learns our own generator's
distribution. Mitigated by grounding the generator in real-world-derived distributions (domain
popularity, UA mix, diurnal curves — `docs/11`). ECOD and Isolation Forest are less exposed to
this — order statistics and partition depth are weaker distributional assumptions than a fitted
covariance.

Ship whichever wins on eval as primary; keep the others as ensemble members with fusion weights —
four uncorrelated hypotheses are worth more fused than any one hypothesis is worth alone. (EIF and
kth-NN join this ensemble once a later phase builds them, per the post-migration roster above.)

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

**Reopened once, on purpose, and rejected again the same way.** Migration change 18
(`docs/v2_migration/MIGRATION-01-evidence-first.md`) revisited this question specifically for
proxy click-paths (as opposed to the identity-session grammar this section's own benchmark was
run against) and reached the identical verdict for the identical structural reasons: browser
parallelism (20-80 subresource requests per page load, nondeterministic order) and multi-tab
concurrency give proxy logs no more grammar to learn than identity logs turned out to have once
Okta was cut. "Per-user filtering was considered and rejected" explicitly — narrowing to one
principal's own events removes inter-user concurrency but leaves both of those disorder sources
untouched, and no scenario in the corpus has an ordering signal no other detector already catches.
What the migration commissioned *instead* — a deterministic navigation chain extractor
reconstructing referer chains, no model, no learned transition probabilities — is documented under
§L3 "Navigation chain extractor" above, not here: it is not a sequence model, and this section's
rejection stands unmodified.

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

## Classification — LightGBM removed

This pipeline used to run a "classify" stage between L5 and fusion: supervised multiclass LightGBM
over the L3 feature vector plus signal-presence indicators (`objective='multiclass'`, classes =
the scenario techniques + `benign`, class weights for imbalance, SHAP values in `explanation`),
trained on labeled synthetic scenarios (`docs/11`), benchmarked against Claude zero-shot
classification.

Migration change 19 (`docs/v2_migration/MIGRATION-01-evidence-first.md`) removed it. **Its job was
multiclass technique attribution; change 5 of the migration replaced that with LLM hypothesis
evaluation over RAG-retrieved candidates** (`docs/07`), which produces evidence-for,
evidence-against, missing-evidence, and an explicit `NO_KNOWN_MAPPING` outcome when nothing fits —
a softmax over a fixed class list produces none of that shape, and it cannot say "none of the
known techniques match" except by picking the least-bad wrong answer. Keeping both a trained
classifier and an LLM hypothesis-evaluation stage would leave two components assigning techniques
to the same incident with no defined precedence between them; the migration picked one rather than
leave that ambiguity live.

**Consequence for this document's own pipeline diagram** (top of file): `L5 graph → classify →
fuse & calibrate` is now `L5 graph → fuse & calibrate`. `mitre_technique` on a `Signal` still comes
from L1 Sigma rule tags and any L2/L3 detector that carries one; an incident with no rule-tagged
technique among its contributing signals now surfaces as untagged at this deterministic layer,
resolved (or explicitly left as `NO_KNOWN_MAPPING`) by the agent stage instead of by a second
classifier guessing here.

**Not the same thing as `app.learning.classifier`.** A different, LightGBM-based module survives
this migration under `app/learning/`: the retrain-candidate classifier inside the continuous-
learning loop (docs/08 §6, `docs/v2_migration/MIGRATION-01-evidence-first.md` change 21's
regression-gate demonstration). It is not part of this deterministic detection pipeline, is never
loaded to score a live incident, and does not create the precedence conflict above — see this
migration phase's own report for the reasoning kept alongside the code.

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

### Calibration provenance, and why the fallback needed a flag

`CalibratorStore.calibrate()` falls back to `clamp01(raw_score)` for any detector with no fitted
isotonic calibrator (never seen during fitting, or too few/degenerate samples —
`MIN_SAMPLES_TO_FIT=8`). That fallback is permanent policy, not a gap to eventually close: new
detectors ship before their first fit, and some genuinely never accumulate enough labeled samples
in a given corpus (§"Calibration roster invariant" below has the full, checked list).

The fallback was silently *unsafe*, not merely interim. Several detectors' raw scores are not
naturally bounded to `[0, 1]` — `signal.stl_residual` emits an unbounded robust-z — so `clamp01`
on an uncalibrated row can saturate at exactly `1.0`, indistinguishable by number alone from a
genuinely calibrated model's most confident possible output. Measured on
`train_0002_low_and_slow_exfil.log` (8,079 events, 10,800 signals) before this fix: **64.0%** of
all signals sat at confidence ≥ 0.99, and the top 30 highest-confidence slots of the file's
largest incident (3,530 contributing signals) were **28/30 `signal.stl_residual`** (uncalibrated,
mean confidence 0.77, *median exactly 1.0*) and 2/30 `ml.peer_group` — every Sigma/L1 signal and
every other L2/L3 detector on that incident pushed out of the Analyst's context window by a
fallback number that only *looked* more confident than they did.

**Fix: `signals.calibrated` (boolean, migration `signals_calibrated_provenance`).** Set once, at
the same call site that computes `confidence` (`CalibratorStore.has(detector_key)`, checked
before `.calibrate()` runs) — never recomputed later, since provenance is a fact about *when the
row was written*, not something safely re-derivable from today's calibrator roster (a
calibrator can be added, or its artifact lost, after the row was persisted). Existing rows were
backfilled to `False` at migration time: their true historical provenance isn't reconstructable,
and "unmeasured until proven otherwise" is the direction it's safe to be wrong in.
`app.agent.orchestrator._build_incident_context_block`'s top-30 selection now sorts
`(calibrated desc, confidence desc)` — an uncalibrated fallback can no longer outrank a
calibrated signal for a context slot, only tie-break against other uncalibrated ones. `SignalOut`
(docs/09) exposes the flag so the UI can render "unmeasured confidence" instead of a number
indistinguishable from a genuinely high-confidence signal. This does **not** touch
`Incident.anomaly_confidence` (incident-level, LLM-immutable, unchanged) — only which of an
incident's *own* signals earn one of the Analyst's 30 context slots.

**Re-measured after the fix** (same file, same seed, `signal.stl_residual` now genuinely fit —
see roster below): **55.6%** of signals still sit at confidence ≥ 0.99 — improved, not
eliminated, exactly as expected (coverage of the fallback is not the same problem as quality of
every calibrator). `signal.stl_residual` itself: mean confidence 0.77 → **0.006**, median 1.0 →
**0.0005**, now genuinely discriminating rather than saturating. The largest incident's top-30
flipped from 28/30 `signal.stl_residual` to **0/30** — replaced by `ml.peer_group` (28/30),
`ml.kth_nn` (1/30), `ml.eif` (1/30), all genuinely calibrated. The remaining saturation is a
*different, disclosed* problem: the three shipped L3 models' own calibrators output a
near-ceiling confidence (mean 0.997–0.999) across nearly every entity-window on this corpus, so
they now correctly dominate the top-30 by real calibrated confidence rather than by fallback
artifact — but that dominance itself means no L1/L2 signal on this incident earns a context slot
either, a quality question this fix does not claim to have solved. `signal.burst`'s calibrator is
separately known to be near-flat (identical output at raw `z=4.05` and `z=1e6`), and
`sigma.non_browser_user_agent`'s was fit on `n_positive=1` of 12,418 — both real, both open.

### Calibration roster invariant — `docs/v2_migration` change 19's own lesson, twice more

`app.graph.pipeline_demo.fit_layer_calibrators` (the offline harness that fits every L1/L2/L3/L5
calibrator into the shared store) used to hand-list its own detector set in two places, both of
which had silently drifted from the codebase's real, single sources of truth:

- `_run_l2` listed four of the six L2 extractors (missing `detect_stl_residual`/
  `detect_url_path`, added to the evidence package after this function was first written) —
  `signal.stl_residual` and `signal.url_path_entropy` could never be sampled for calibration,
  only ever fall back.
- `_ml_model_pairs` listed the *pre-migration-19* L3 roster (`ml.iforest`/`ml.mahalanobis`/
  `ml.ecod`/`ml.peer_group`) instead of `SHIPPED_MODEL_FIELDS` (`ml.eif`/`ml.kth_nn`/
  `ml.peer_group`) — the same class of bug already fixed once for `app.detection.calibration.
  _model_pairs` and `evals.metrics.detection.known_detector_registry`, independently
  reintroduced here because the three functions never shared a source.

Both now read from the same single source every other caller uses. `_run_l2` calls
`app.detection.evidence.run.collect_signal_drafts` — the same function `run_evidence_layer` (the
*production* L2 stage) calls, so `_run_l2` cannot drift from production's own extractor list
again: there is only one list. `_ml_model_pairs` reads `SHIPPED_MODEL_FIELDS` directly. The
benchmark-only models (`ml.iforest`/`ml.mahalanobis`/`ml.ecod`) are deliberately *not* calibrated
by this harness — they never emit a production signal (`score_entity_windows` only scores
`SHIPPED_MODEL_FIELDS`), so a calibrator for them would sit unused here; `app.detection.
calibration.recompare_l3` already benchmarks all six on its own held-out seed for that purpose.

**Refit roster** (`python -m app.graph.pipeline_demo fit-calibrators`, docs/11's eight scenarios
+ FP-control + canary, 50k events each): 16 detectors, including `signal.stl_residual` for the
first time. Nine sigma rules, `signal.url_path_entropy`, and (not production-reachable today)
one graph feature remain without a fitted calibrator — every one checked and named, not silently
missing:

| detector_key | reason |
|---|---|
| `sigma.blocked_then_allowed` | fired, n=2 (< `MIN_SAMPLES_TO_FIT=8`) |
| `sigma.large_post_to_new_domain` | fired, n=1 |
| `signal.url_path_entropy` | fired (n=32), but every sample shared one label — isotonic needs both classes |
| 8 further `sigma.*` rules (`anonymizer_proxy_avoidance_category`, `credentials_in_url`, `direct_to_ip_request`, `dlp_engine_triggered`, `executable_archive_download_new_domain`, `high_risk_score_allowed`, `malicious_url_category`, `threat_name_present`) | zero samples — none of the harness's eight scenarios happens to set that rule's trigger field to a matching value (spot-verified for two of these: the scenario logs' `dlpengine`/`threatname` columns exist but are blank on every row this harness's corpus produced, even though the generator module is *capable* of populating them — a corpus-coverage gap, not a rule bug, and out of this pass's scope to chase) |

`tests/test_calibration_roster_invariant.py` pins this shut three ways: a DB-free test that
`collect_signal_drafts` still calls all six extractors, a DB-free test that `_ml_model_pairs`
still matches `SHIPPED_MODEL_FIELDS` exactly, and a broader test (skipped on a fresh checkout
with no fitted calibrators — neither CI job populates the shared store) that every detector able
to reach `signals` in production has a fitted calibrator or is on the checked exemption table
above.


## L2 is now an evidence layer — `docs/v2_migration` change 2

`detection/signal/` became `detection/evidence/`, and the rename is not cosmetic: the output
contract changed.

**Old contract.** A detector emitted a `signals` row carrying a calibrated score. The score was
the product; the numbers behind it were an explanation payload attached for the UI.

**New contract.** An extractor emits an `EvidencePayload` — raw measurements plus historical
context — and that payload travels to the LLM intact. The governing sentence of the migration is
*machines calculate facts, the LLM interprets meaning*, and the placement test is: could a
deterministic function produce a more precise answer than asking a model? If yes, compute it
first and pass the number in.

```python
class EvidencePayload(BaseModel):
    evidence_id: str                  # "EVIDENCE-14" — stable within an analysis, citable
    extractor: str
    entity: dict
    window: tuple[datetime, datetime]
    measurements: dict[str, float]    # the actual numbers
    historical: dict[str, float]      # percentiles vs. the baseline store
    contributing_line_numbers: list[int]
    nominates_candidate: bool
    nomination_score: float | None
```

### Three stages, and why the boundary is where it is

`raw_evidence_*` is pure and touches no database. `resolve_evidence()` performs the baseline
lookups. `finalize_evidence()` is pure again, assigning ids and resolving nomination.

Each extractor's `detect_*` (the legacy `signals` path) and `raw_evidence_*` compute from the
*same* per-finding dataclass. That is deliberate: both contracts ship simultaneously — correlation,
fusion and the incident path still consume `signals` — and computing them separately would let the
two disagree numerically about the same finding.

### `evidence_id` is stable because citations depend on it

Ordered by fixed extractor sequence, then `(entity.type, entity.value, window_start, window_end)`.
It depends on neither input ordering, dict iteration, nor the clock, so identical input reassigns
identical ids. The narrative cites `[EVIDENCE-14]` and the verifier resolves that back to a
payload; an id that shifted between runs would make every citation unverifiable.

### Historical context comes from the baseline store, never the file

This is the point of change 1. `historical_from_percentile()` is the single place any extractor
writes percentile-derived data, which is what makes the next property enforceable in one location:

**Cold start propagates rather than being smoothed away.** When the baseline resolver returns
`insufficient_history`, the payload literally carries `"percentile": null,
"baseline_status": "insufficient_history", "n_windows": n` — it does not drop the field and does
not coerce a number. It also makes nomination impossible by construction, since `None > 99.5` is
never true.

### Extractors may nominate candidates

A deliberate divergence from the migration's source material, and the reasoning is worth keeping:
sixty requests over six hours produces an entirely unremarkable feature vector, so no
entity-window model would ever surface it. The beacon would simply be lost.

An extractor sets `nominates_candidate = true` when its historical percentile exceeds **99.5**
*and* no existing candidate already covers its entity-window. Nominated candidates enter the same
correlation and triage path as model-detected ones. Rarity's analogue is "never contacted org-wide
in six months", since contact counts have no percentile.

### Known gap in the shipped baseline

`baseline_profiles` currently carries only `entity_type="user"` across four metrics
(`n_events`, `bytes_out`, `bytes_in`, `n_unique_domains`). Department, org and `src_ip` scopes do
not exist yet, nor do detector-specific baselines such as a real beaconing-regularity history.
Extractors query well-named metrics regardless and will report `insufficient_history` against
today's seeded data. That is correct plumbing exercising a real gap in the delivered generator —
closing it means extending the generator, not the extractors. Every extractor's behaviour against
a *populated* baseline is proven by tests that insert synthetic profile and contact rows.


## Shipped models vs. benchmark baselines — `docs/v2_migration` change 19

Three models ship and score live traffic:

| Model | Role |
|---|---|
| EIF | global entity anomaly, oblique splits |
| kth-NN | global distance, handles multimodality |
| LOF | peer-relative / local density |

Isolation Forest, ECOD and Mahalanobis are **benchmarked but not shipped**. They stay in
`evaluate.py` so EIF has to prove oblique splitting earns its cost, and so the hypothesis-outcome
table keeps its contenders — but they emit no `signals` rows.

**This distinction lived only in the migration document until it was caught.**
`score_entity_windows` scored all six, so three benchmark-only baselines were writing signals into
the live pipeline, where they fed fusion, incident formation and the LLM's evidence package.

It is not a tuning detail. On the current corpus ECOD measures **precision 1.000 at recall 0.051**
and LOF measures **precision 0.003**. Fusing detectors three orders of magnitude apart in
precision, without recording that you have done so, produces a score no one can reason about and
inflates the false-positive burden the analyst actually pays. `SHIPPED_MODEL_FIELDS` is now the
runtime roster, `ML_MODEL_FIELDS` remains the full six for benchmarking and calibrator fitting,
and a test pins the two apart so this cannot drift back.

### Reading the benchmark for a SOC rather than for a leaderboard

The pre-registered winner rule is mean F1, tie-broken by AUC-PR, and ECOD wins it. Pooled across
the six attack scenarios the confusion matrix says something the rank does not:

| Model | TP | FP | FN | Recall | Precision | FN per TP |
|---|--:|--:|--:|--:|--:|--:|
| kth-NN | 44 | 4,441 | 192 | 0.186 | 0.010 | 4.4 |
| LOF | 43 | 13,785 | 193 | 0.182 | 0.003 | 4.5 |
| EIF | 33 | 127 | 203 | 0.140 | 0.207 | 6.1 |
| ECOD | 12 | 0 | 224 | 0.051 | 1.000 | 18.7 |
| iForest | 6 | 8 | 230 | 0.025 | 0.429 | 38.3 |
| Mahalanobis | 6 | 55 | 230 | 0.025 | 0.098 | 38.3 |

F1 weights precision and recall equally, which is the wrong weighting for security: a missed
breach costs far more than a dismissed alert. ECOD wins by being perfectly precise about twelve
things while missing 224 — silent through most attacks. That is the profile F1 rewards and a SOC
does not want.

The opposite extreme is not free either. LOF's 13,785 false positives against 43 true ones is 320
false alarms per real detection, and past some ratio false positives *cause* false negatives,
because the analyst stops reading. The useful objective is recall subject to an alert budget a
human can work, not recall maximised.

**Two measurement gaps to close before that budget can be set.** ECOD, EIF and kth-NN have no
false-positive rate measured against the benign control — only iForest, Mahalanobis and LOF do.
And the summary table's *mean* recall is the mean of per-scenario recalls, which weights a
two-positive scenario the same as a hundred-positive one; kth-NN reads 0.525 there against a
pooled 0.186. The pooled figure is the honest one.

Changing the winner rule to F2 is defensible but must be recorded as a forward change with its
rationale, never applied retroactively — the rule is pre-registered, and rewriting it after seeing
results is the exact failure `CLAUDE.md` rule 2 exists to prevent.
