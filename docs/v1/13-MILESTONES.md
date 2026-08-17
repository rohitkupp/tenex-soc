# 13 — Milestones

Build in this order. Each milestone has acceptance criteria — do not advance until they pass.
Commit at every milestone boundary.

**Two rules that override enthusiasm:**
1. **Deploy at M1 and keep deploying.** Deployment left to the end eats a day and produces a
   panic. Ship a skeleton to Vercel and Fly on day one and redeploy every milestone.
2. **Build the data generator before any detector (M2).** You cannot develop or measure
   detection without labeled ground truth. Doing this out of order means rewriting detectors.

---

## M0 — Scaffold
Repo layout, `docker-compose.yml` with postgres/rabbitmq/minio/redis, Makefile, Alembic,
ruff/mypy/eslint config, CI skeleton.

**Accept:** `make up` brings up every container. `make lint` and `make test` pass on an empty suite.

## M1 — Auth, upload, deploy
Argon2 credentials, JWT cookie, tenant scoping. Upload endpoint streaming to MinIO. Minimal
Next.js shell with login and an upload page. Deployed to Vercel + Fly.

**Accept:** Log in on the deployed URL, upload a file, see it in MinIO. No cold start over 3s.

## M2 — Synthetic data generator
`docs/11` in full. Benign corpus, all eight scenarios, ground truth, difficulty sweeps, demo file.

**Accept:** `make gen-data` produces the corpus and every scenario with labels. Different seeds
for corpus and eval. Demo file parses in under 2 minutes.

## M3 — Parser, OCSF, event store
The ZScaler parser, sniffing registry (single-parser today, pluggable — `docs/03`), OCSF mapper,
bulk COPY, parse-failure tracking, event explorer UI.

**Accept:** The ZScaler sample format parses with under 1% failures. Event explorer filters and
paginates 1M+ rows without timing out.

## M4 — Pipeline skeleton
Orchestrator, all worker containers, queue topology, DLQ, SSE progress, `/ops` page.

**Accept:** An upload flows through every stage. Killing a worker mid-run dead-letters cleanly
and retries. Funnel counters stream live to the UI.

## M5 — Enrichment, anonymization, privacy
Offline enrichment datasets, HMAC pseudonymization, redaction, injection-defense scaffolding.

**Accept:** No identifiable value appears in any prompt payload or Tier 2 record. Redaction
count surfaces in the UI. Unit tests cover every redaction pattern.

## M6 — Sigma rules
Rule evaluator, the proxy-only rule inventory (`docs/04` §L1), positive and negative fixture per
rule, ATT&CK mapping. Smaller than the old multi-source design: no identity or cross-source
tables to build, capacity redirected into the four added proxy rules.

**Accept:** Every rule fires on its positive fixture and stays silent on its negative. Rules
detect scenario 2 (data exfiltration, via the large-POST/newly-registered-domain rule) end to
end and correctly stay silent on scenario 8 (benign-but-weird).

## M7 — Signal processing
Beaconing (CV + FFT periodicity), DGA, volumetric burst, STL seasonal residuals, URL path
analysis, rarity. Fitted DGA coefficients as an artifact.

**Accept:** Scenario 1 detected via beaconing, with the FFT cross-check agreeing on a dominant
period. Scenario 6 (seasonal deviation) detected via STL residuals. Jitter sweep produces a
degradation curve. Every detector writes a structured `explanation`. (The pre-registered
prediction that no L3 feature-vector model catches scenario 6 either, `docs/12`, is checked once
M8 lands — flag it there if L3 detects it too.)

## M8 — L3 models + benchmark
Feature extraction — including the entity-relative and cohort-relative variants for volume,
transfer, and domain families (`docs/04` §L3) — Isolation Forest, Mahalanobis, ECOD, LOF,
autoencoder with Optuna, per-feature thresholds, calibration. Grows from three models to five
relative to the old design; smaller feature vector (~35 vs ~50) with the identity-joined family
gone.

**Accept:** All five trained and benchmarked; `evals/results.md` reports which of the five
hypotheses (§L3) held, not just a winner. Scenario 4 (low-and-slow) detected by the autoencoder
and, per the pre-registered prediction, **not** by ECOD. Scenario 5 (peer-group) detected by LOF
and **not** by the four global models. Per-feature attribution renders.

## M9 — removed

Sequence models (Markov, LogBERT) were designed, built, and benchmarked under the old
multi-source design, then cut when the system moved to ZScaler-only — their entire justification
was identity-log ordering, and identity logs are gone. See `docs/04` §L4 for the rationale and the
benchmark that was run before the cut (pooled F1: Markov 0.529, LogBERT 0.097; neither detected
the account-takeover-chain scenario that motivated the layer). The milestone number is retired,
not reused — the M8 → M10 gap in this document is the fossil record of a layer that was built,
measured, and rejected, not a numbering error.

## M10 — Graph, correlation, fusion
Entity graph, Louvain incidents, graph features, LightGBM classifier, calibration and fusion,
recurrence detection.

**Accept:** `incident_recall ≥ 0.9`, fragmentation near 1.0. Severity set by fusion. Reliability
diagram generated. Recurrence links correctly on a repeated scenario.

## M11 — Agent
Tools, MITRE RAG, three-role flow, structured output, citation verifier, injection defense,
cost tracking.

**Accept:** Verdicts on all incidents. `hallucination_rate` measured and near zero.
`injection_resistance = 1.0`. Recorded fixtures let CI run without an API key.

## M12 — Response graph + enforcement plane
Action catalog, planner, LLM verification, stateful enforcement plane, execution journal,
rollback, outcome verification.

**Accept:** Approve a plan → state mutates → rollback restores exactly → re-detection reports
`contained`. A deliberately failing precondition halts the plan and is recorded.

## M13 — Learning loop
All six feedback consumers, retrain gate, `/learning` page, seeded feedback history.

**Accept:** Feedback measurably shifts calibration and detector weights. A deliberately worse
candidate model is rejected by the gate. Few-shot memory visibly changes an agent verdict.

## M14 — Tier 2
Signature sync, cross-tenant dashboard, indicator overlap, NL→SQL with full validation.

**Accept:** Indicator overlap surfaces across two simulated tenants. Every generated query is
displayed. A malicious NL prompt cannot produce a mutating or out-of-scope query.

**Later update:** the NL→SQL chatbot described above was removed under a hard cost constraint
on a later task (no code path may make a live Anthropic call) — see docs/06's "Text-to-SQL
safety (Tier 2 chatbot) — removed" section. It was replaced with four deterministic,
non-LLM cross-tenant learning charts (docs/09's Tier 2 section) that answer questions the
chatbot could have been asked anyway (indicator overlap distribution, technique prevalence,
detector reliability, first-seen propagation) without any LLM surface at all. The acceptance
criteria above describe the milestone as originally built and are left as a historical
record.

## M15 — Frontend completion
All routes per `docs/10`. `ExplanationRenderer` for every detector type. Case file screen
complete. Empty states, keyboard nav, responsive.

**Accept:** Every route usable on mobile. Citation expansion works. No raw JSON rendered anywhere.

## M16 — Eval harness + CI gate
Full harness, all metrics, `results.md`, GitHub Actions gate.

**Accept:** `make eval` produces the report and exits 1 on an induced regression. CI green on
a clean tree.

## M17 — Docs, demo mode, recording
README, `AI_APPROACH.md`, `ARCHITECTURE.md`, `EVALUATION.md`. `DEMO_MODE` with precomputed
results. Final deploy. Walkthrough recording.

**Accept:** A stranger can clone, `make up`, and reach a triaged incident in under 15 minutes
following only the README.

---

## Recording plan

Roughly 10 minutes. Lead with the thesis, not the tech stack.

1. **The loop** (60s) — "I built a closed detect → classify → RCA → remediate → verify loop at
   Qualcomm for network device faults. This is that loop for security telemetry."
2. **Upload → funnel** (90s) — 1.4M events reduce to a handful of incidents. The funnel is the
   architecture.
3. **The case file** (3m) — narrative, expand a citation to the raw log line, contradicting
   evidence, per-feature attribution, the agent trace.
4. **Response + containment** (90s) — plan, blast radius, approve, state diff, re-detect,
   contained.
5. **The benchmarks** (2m) — the `/models` page. "Here is where the autoencoder won and where it
   lost." This is the segment that separates the submission.
6. **Learning + Tier 2** (60s) — alignment trend, cross-tenant indicator overlap.
7. **Limitations** (30s) — say them out loud. Synthetic-data circularity, simulated enforcement,
   single-file baselines.

Close on limitations deliberately. Naming your own weaknesses is what makes the rest credible.
