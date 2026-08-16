# Post-build validation run — partial

`docs/v2_migration` change 26 defines ten items. **Four are complete and evidenced here. Six are
not, and are listed below with what each needs.** Nothing in this directory is estimated or
hand-edited; every number was produced by a real run against a real database.

## Complete

### 1. Seed — baseline loaded, Tier 2 overlap non-zero

`seed-state.json`, read directly from Postgres:

| | |
|---|--:|
| `baseline_windows` | 130,837 |
| `baseline_profiles` | 1,048 |
| `baseline_contacts` — user scope | 2,252 |
| — department scope | 208 |
| — org scope | 26 |
| `tier2_signatures` | 13 |

Six months of history for the `northwind` live tenant. The department and org scopes are derived
by the loader, since the generator emits contacts at user scope only.

**A real limitation, visible in that table:** 26 distinct domains org-wide across six months is
thin. Rarity at org scope will report almost everything as first-seen, which makes that signal far
less discriminating than change 1 intends. The plumbing is correct — this is a property of the
delivered generator's contact model, and closing it means widening the generator's domain pool.

### 2. Corpus

`corpus-manifest-summary.json`. 150 files across 11 scenario types, split 105 train
(`northwind`) / 30 validation (`contoso`) / 15 golden (`fabrikam`), each split a different seed
**and** a different simulated org.

**Deviation from change 13, stated plainly:** the migration specifies 1000 files. 150 were
generated. At ~2.3 MB per file that is 308 MB rather than ~2.5 GB, which is what made a full
generate-load-benchmark cycle tractable here. The split ratios, seeds, org separation and scenario
distribution are exactly as specified; only the count differs. `make gen-data` defaults to 1000.

### 4. Detection accuracy — the benchmark

`benchmark-results.md`, the full report. The headline is the first six-model comparison including
the two models the migration added:

| Model | Mean F1 | Mean AUC-PR | Mean recall | Scenarios detected |
|---|--:|--:|--:|:--:|
| `ml.iforest` (baseline) | 0.100 | 0.180 | 0.167 | 1 / 6 |
| `ml.mahalanobis` | 0.030 | 0.176 | 0.167 | 1 / 6 |
| **`ml.ecod`** (winner) | **0.333** | **0.427** | 0.333 | 2 / 6 |
| `ml.peer_group` (LOF) | 0.006 | 0.236 | 0.536 | 6 / 6 |
| `ml.eif` | 0.224 | 0.241 | 0.506 | 5 / 6 |
| `ml.kth_nn` | 0.018 | 0.369 | 0.525 | 6 / 6 |

**ECOD still wins on the pre-registered rule.** Change 19 removed the autoencoder and LightGBM on
the argument that EIF's oblique splits and kth-NN's distance would absorb their jobs. Measured:
EIF does not beat ECOD on mean F1 (0.224 vs 0.333). That is a reportable outcome, not a failure —
it is exactly why change 19 kept iForest, ECOD and Mahalanobis as baselines rather than deleting
them.

The more interesting result is the shape rather than the ranking. ECOD wins F1 while detecting
**2 of 6** scenarios; EIF scores lower but detects **5 of 6**, and kth-NN and LOF detect **6 of 6**
at very low precision. Mean F1 rewards a few precise hits over broad noisy coverage, which is the
same tension the v1 benchmark surfaced between Isolation Forest and the autoencoder. Any single
number here tells a different and incomplete story, which is why the report carries F1, AUC-PR,
per-scenario recall and false-positive rate together.

### 3. Gate behaviour

`PASS`, but honestly vacuous on this run and the report says so: this is the first run, so no
baseline exists to regress against, and the agent-dependent metrics (`disposition_accuracy`,
`hallucination_rate`, `injection_resistance`) are **not measured** because `evals.run` makes no
LLM calls. Those metrics are covered by the pytest suite instead — `injection_resistance` is
computed there over all eight datagen injection styles and asserted `== 1.0`.

A stale message in `evals/gate.py` claimed these were unmeasured because "app/agent/ has no
orchestrator/verifier yet". That was false — the orchestrator is 1,397 lines — and is corrected.

## Not done

| # | Item | Needs |
|---|---|---|
| 2 | Ingest 50 corpus files through the live pipeline | Real LLM calls and real spend; ~50 × 3 calls per triaged incident |
| 5 | Hallucination audit + 10 narratives read end to end | Depends on 2 |
| 6 | Learning replay over 200 incidents, improvement curve | Depends on 2; this is the headline chart |
| 7 | Contamination check on a live re-run | Depends on 2 |
| 8 | Tier 2 cross-tenant check on live data | Partially evidenced by seed overlap; the live half depends on 2 |
| 9 | Injection canaries end to end | Covered at unit level; the live half depends on 2 |
| 10 | Failure injection — kill a worker, kill the broker, malformed file | Covered at integration level by `test_pipeline_retry.py`, which drops a real delivery unacked and proves both redelivery and DLQ convergence. The UI-visible half is not exercised |

The blocker for all six is item 2, which is a long live run with real cost. The pipeline itself is
ready for it — `test_pipeline_e2e_real` proves a full upload through `tier2` produces non-zero
events, signals, incidents and needs-attention, which was untrue before the stages were wired.
