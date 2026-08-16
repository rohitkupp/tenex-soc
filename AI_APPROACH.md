# AI / ML Approach

Every number in this document is measured. `backend/evals/results.md` holds the full tables, the
raw per-feature payloads, the data-provenance check, and the reproduce commands.

The single governing rule of this codebase is in [CLAUDE.md](CLAUDE.md):

> **No model ships without a benchmark.** Every model has a simpler baseline it must beat on the
> labeled eval set. Losing is a valid, reportable outcome.

That rule produced three losses, two falsified predictions, and one measured defect in a feature
vector. Those are the most useful results in the project, and they are what this document is
mostly about.

---

## 1. Why a funnel, not a model

The naive version of this product feeds logs to an LLM and asks what looks bad. That fails on cost
and on determinism. 400,000 proxy lines is roughly 40 M tokens; at Opus rates that is a few hundred
dollars per analysis run, non-reproducible, with no way to tell whether a missed detection was a
model failure or a context-window truncation.

So the architecture is a **cost funnel**, and each layer's job is to be cheap enough to run on
everything the layer above passed it:

| Layer | Runs on | Cost per unit | Output |
|---|---|---|---|
| L1 Sigma rules | every event | SQL, ~0 | rule matches |
| L2 signal processing | grouped events | seconds | 6 detector signal types |
| L3 entity-window ML | `(entity, hour)` rows | ~ms/row | 5 models' anomaly scores |
| L5 graph | signals | seconds | incidents |
| Agent | top 15 incidents | ~$0.02–0.10 each | verdict + narrative |

By the time the LLM is invoked it sees a few dozen correlated events, not 400,000 lines. That is
not a performance optimization bolted on afterwards; it is the reason the design has five layers.

The unit of analysis for L3 — `(entity, 1-hour window)` — is the load-bearing choice. Per-event ML
on proxy logs mostly rediscovers the rules layer. Aggregating to an entity-hour is what makes
"this user moved 40× their normal upload volume between 2 and 3 a.m." expressible as a single row
with 53 features.

---

## 2. Five L3 models, one benchmark, a pre-registered winner rule

Five unsupervised models over the same 53-feature vector, all scored at the same operating point
(`confidence ≥ 0.995`) on the same eight scenarios, with the winner rule — highest mean F1, tied
broken by mean AUC-PR — **written down before the run**.

| Model | Mean F1 | Mean AUC-PR | Mean recall | Mean precision | Scenarios detected | FP rate |
|---|--:|--:|--:|--:|:--:|--:|
| `ml.iforest` (baseline) | 0.125 | 0.183 | 0.167 | 0.100 | 1 / 6 | 0.029% |
| `ml.mahalanobis` | 0.010 | 0.143 | 0.661 | 0.005 | 6 / 6 | **16.648%** |
| **`ml.ecod`** | **0.253** | **0.350** | 0.335 | 0.242 | 3 / 6 | **0.017%** |
| `ml.peer_group` (LOF) | 0.005 | 0.127 | 0.342 | 0.003 | 4 / 6 | 4.593% |
| `ml.autoencoder` | 0.036 | 0.280 | 0.515 | 0.020 | 5 / 6 | 1.227% |

**ECOD wins — and it is the simplest model in the table.** Parameter-free, deterministic, O(n·d),
0.38 s to fit. It beats a 50-trial Optuna-tuned PyTorch autoencoder on F1 by 7×, on AUC-PR by 25%,
and has the lowest false-positive rate of the five.

Two things in this table matter more than the winner:

**Mahalanobis's 6/6 is hollow.** It flags 3,800+ of 23,000+ rows in *every* scenario, including
the benign false-positive control. A 16.6% false-positive rate is not detection; it is an
always-on alarm that happens to overlap the truth. This is why the benchmark reports F1, AUC-PR,
per-scenario recall, *and* false-positive rate together — any one of them alone tells a different
and incomplete story. Reporting "Mahalanobis detects every scenario" would be technically true and
materially misleading.

**Simple beat complex, twice.** ECOD over the tuned autoencoder here; and at L4, bigram transition
probabilities beat a LogBERT transformer 0.529 to 0.097 pooled F1. LogBERT was retrained 8 → 25
epochs specifically to rule out undertraining before that result was recorded, so it is not a
strawman loss.

---

## 3. Pre-registered predictions — two came back falsified

[docs/12](docs/v1/12-EVALUATION.md) states falsifiable predictions *before* the run, and two synthetic
scenarios were built specifically to test them. This is the part of the project I would most want
read closely.

| # | Prediction | Outcome |
|---|---|:--|
| 1 | Low-and-slow exfil: the autoencoder detects it, ECOD does not | **CONFIRMED** |
| 2 | Peer-group deviation: LOF detects it, the four global models do not | **FALSIFIED** |
| 3 | Seasonal deviation: STL detects it, no L3 model does | **FALSIFIED, both halves** |

### Prediction 2 — the fix interfered with the test

The hypothesis was that only LOF, via local density, could see a deviation that is *globally*
normal but abnormal for one person's peer group. LOF did detect it (recall 0.026). So did
Mahalanobis (0.453), ECOD (0.009), and the autoencoder (0.043).

The mechanism is a genuine experimental-design lesson. Earlier in the build, measurement showed
that 47 of 50 features were absolute/population-level — only 3 were entity-relative — and that
this was the structural reason no model detected low-and-slow exfil. The fix added department-cohort
z-scores (`n_events_z_vs_cohort`, `bytes_out_sum_z_vs_cohort`, `rare_domain_ratio_z_vs_cohort`) to
**every model's input vector**.

Which means peer-group information stopped being something LOF alone could *infer* and became a
dimension every model could simply *read*. Mahalanobis then out-detected LOF on LOF's own target
scenario, 0.453 to 0.026.

The finding is more interesting than the prediction: **making peer-group information explicit in
the feature vector helps every model that can read a feature, not only the one architected to
infer it.** It also puts LOF's marginal value in question now that the cohort features exist —
recorded as a testable follow-up, not as a resolved conclusion.

### Prediction 3 — STL fails on the scenario built to justify it

`signal.stl_residual` recovered **0 of 36** malicious lines on `seasonal_deviation`, the scenario
that exists to test it. Two L3 models caught it anyway.

The corpus-wide table shows STL at 43.3% mean recall and "4 of 6 scenarios detected," and that
number is misleading on its own: STL fires broadly (11.4% background false-positive rate) and
incidentally sweeps up a fraction of every scenario's malicious lines by coverage — the way a coin
that comes up heads 89% of the time "detects" almost anything. It scores exactly 0% on the two
scenarios where the campaign is built to be subtle rather than a volume spike.

Root cause, verified rather than hypothesized: the MSTL decomposition is fit **self-inclusively** —
on the same window it scores, campaign hours included. A sustained modest shift gets partially
absorbed into what LOESS learns as "normal," diluting exactly the residual the detector needs.
This was tested directly with `robust=True` (LOESS's own outlier-resistant option), which produced
the same null result — ruling out ordinary noise sensitivity and pointing at the self-inclusive fit
specifically. The production fix (score against a lagging, pre-period-only profile) needs persisted
cross-analysis history this batch harness does not have.

STL's own unit tests prove the mechanism works on a clean synthetic off-hours burst (100% recall,
4/4 injected hours). The gap is between *detector vs. clean signal* and *detector vs. a campaign
built to defeat exactly this check* — which is the gap that matters.

### L4 — the layer that did not ship

Sequence models over event ordering (Markov bigrams vs. LogBERT) were built and benchmarked.
Markov won 0.529 to 0.097 pooled F1, carried by a clean 1.000 on `mfa_fatigue`.

Its 0.111 on `account_takeover_chain` was initially recorded as a partial detection. It wasn't.
The one session clearing Markov's threshold turned out to be an incidental two-event
`session.end → session.end` fragment, not the attack chain — the eight genuine chain sessions
scored ~2.08 against a 4.49 threshold. **Neither model detects that scenario**, and the root cause
is structural: mean negative log-probability dilutes a few novel transitions across a long session.
The correction was committed on its own rather than quietly folded into a later result.

The whole layer was then removed when the project narrowed to proxy-only, since session ordering
is an identity-log signal. Built, benchmarked, rejected, and documented as such — which is cheaper
than a layer that ships because it was already written.

---

## 4. Calibration: what it fixed and what it didn't

Raw anomaly scores from five different models are not comparable — an Isolation Forest path-length
and an autoencoder reconstruction error do not live on the same axis, so they cannot be summed,
ranked, or thresholded together. Per-detector **isotonic regression** maps each detector's raw
score to a calibrated probability against labeled outcomes; fusion then combines calibrated scores
with a bonus for signals from distinct detector *layers* (a rule plus a signal plus an ML model
agreeing is stronger evidence than three ML models agreeing, because the latter share a feature
vector and therefore share failure modes).

Measured effect of calibration:

- Autoencoder mean F1 **0.037 → 0.143**, a 4× lift — confirming the earlier diagnosis that its
  problem was threshold *placement*, not ranking. It always ranked anomalies well (2nd-best AUC-PR);
  it just cut in the wrong place.
- **The winner did not change.** ECOD wins both uncalibrated and calibrated. Calibration is not a
  way to rescue a losing model into a winning one, and it did not become one here.

**The LLM never sets priority.** Severity and queue rank come from this calibrated fusion score.
The agent contributes disposition, narrative, and technique mapping only. That separation is a
design rule, not an implementation detail — a language model's confidence is not calibrated
against anything, and letting it rank a queue would put an uncalibrated number where an analyst
reads a priority.

---

## 5. The agent layer

The agent is a tool-using Claude loop over one incident at a time, with hard caps
(`AGENT_MAX_TOOL_CALLS=8`, `AGENT_TIMEOUT_SECONDS=120`, `MAX_TRIAGE_INCIDENTS=15`).

**Citations are programmatically verified, not trusted.** Every narrative claim must cite event
IDs. A verifier then checks each citation for existence, scope (does this event actually belong to
this incident), and temporal plausibility. Failures are recorded in `invalid_citations` and the UI
renders those claims with a warning glyph and a dashed border — **still fully visible**, because
hiding an unverified claim removes the analyst's ability to catch the model being wrong.

**Log content is untrusted input.** Proxy logs are attacker-controllable: a URL path, a user agent,
a domain name are all fields an attacker chooses. Every one of them flows toward a prompt. So log
content never enters a system prompt, is always delimited and marked as data, and there is a
`prompt_injection_canary` scenario in the corpus whose entire job is to attempt the injection.

**MITRE technique IDs come from a corpus, never from the model.** `backend/data/mitre/` holds the
technique text; retrieval is over pgvector embeddings. A model asked to produce a technique ID
freehand will produce plausible, well-formatted, non-existent ones.

**Tests never call the API.** Agent tests replay recorded responses from
`backend/tests/fixtures/llm/`, so CI requires no key and costs nothing. `DEMO_MODE=true` makes zero
API calls.

---

## 6. Explainability, end to end

Every signal carries a detector-specific `explanation` payload, and it survives all the way to the
screen without being flattened into prose or dumped as JSON.

- `ml.iforest` — SHAP values, sign-corrected so positive means "pushed toward flagged."
- `ml.ecod` — its own native per-dimension tail decomposition (`self.O`), not a post-hoc proxy.
- `ml.peer_group` — deviation from this row's own k-nearest neighbors' mean, per feature.
- `ml.autoencoder` — per-feature reconstruction error against per-feature thresholds.
- `signal.beaconing` — interval CV, MAD jitter, FFT dominant period and peak power ratio.
- `signal.stl_residual` — trend, daily and weekly seasonal components, residual, residual z.

The frontend dispatches on `detector_key` to a dedicated renderer per payload shape. There is no
`JSON.stringify` in any render path.

Here is ECOD's real payload for a true positive on `data_exfiltration`
(`user=csallie@corp.example`, window `2026-02-23 03:00 UTC`):

```json
{
  "total_score": 113.31,
  "per_feature": [
    {"feature": "bytes_out_sum_z_vs_own_history", "contribution": 10.94},
    {"feature": "n_large_uploads",                "contribution": 10.94},
    {"feature": "bytes_out_sum",                  "contribution": 10.94},
    {"feature": "out_in_ratio",                   "contribution": 10.25},
    {"feature": "high_risk_tld_ratio",            "contribution": 9.33}
  ]
}
```

Semantically coherent for exfiltration — and note the top contributor is the entity-relative
feature. This victim's transfer volume is extreme not just absolutely but *relative to their own
history*, which is precisely the comparison the earlier feature audit found missing.

---

## 7. What I would do next

In priority order, and each one is a consequence of something measured above rather than a
generic roadmap item:

1. **Fix STL's self-inclusive fit.** Score each hour against a lagging, pre-period-only profile.
   This needs persisted cross-analysis entity history — a schema change, not a tuning change.
2. **Root-cause Mahalanobis's 16.6% false-positive rate.** The leading hypothesis is the
   `Z_SCORE_CLIP=100.0` sentinel that entity-relative features emit under the documented MAD==0
   policy, producing high-leverage points a covariance model is far more sensitive to than a
   partition-based or per-feature-CDF one. Testable directly.
3. **Retest LOF's marginal value** now that cohort features are explicit inputs. Prediction 2's
   falsification implies it may be redundant; that is a hypothesis, not a conclusion.
4. **Per-entity baselines.** Every L3 model fits one global distribution. Six of 53 entity-relative
   features partially compensate; a per-entity or per-cohort model architecture would not need to.
5. **A scenario that exercises URL path analysis.** Its 0/6 is "not tested," and shipping a
   detector whose only correctness evidence is its own unit tests is a gap worth closing.

---

## Reproducing any of this

```bash
make gen-data   # regenerate the synthetic corpus + labeled scenarios (seeded)
make train      # train all five L3 models → backend/data/models/
make eval       # score the golden dataset; exits 1 on regression
```

Training, Optuna tuning, and final evaluation use three different seeds, and `datagen.corpus.role_seed`
namespaces the `benign` and `eval` roles independently so even a seed collision could not produce
the same simulated org. No model in any table above is scored on data it was fit or tuned on; the
org fingerprints were compared directly rather than assumed.
