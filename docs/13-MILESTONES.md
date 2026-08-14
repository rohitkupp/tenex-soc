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
`docs/11` in full. Benign corpus, all ten scenarios, ground truth, difficulty sweeps, demo file.

**Accept:** `make gen-data` produces the corpus and every scenario with labels. Different seeds
for corpus and eval. Demo file parses in under 2 minutes.

## M3 — Parsers, OCSF, event store
All three parsers, sniffing registry, OCSF mappers, bulk COPY, parse-failure tracking, event
explorer UI.

**Accept:** All three sample formats parse with under 1% failures. Event explorer filters and
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
Rule evaluator, full rule inventory, positive and negative fixture per rule, ATT&CK mapping.

**Accept:** Every rule fires on its positive fixture and stays silent on its negative. Rules
detect scenarios 3, 4, 6 end to end.

## M7 — Signal processing
Beaconing, DGA, volumetric burst, rarity. Fitted DGA coefficients as an artifact.

**Accept:** Scenario 1 detected. Jitter sweep produces a degradation curve. Every detector writes
a structured `explanation`.

## M8 — L3 models + benchmark
Feature extraction, Isolation Forest, Mahalanobis, autoencoder with Optuna, per-feature
thresholds, calibration.

**Accept:** All three trained and benchmarked; `evals/results.md` has the comparison table with a
winner. Scenario 8 (low-and-slow) detected by at least one. Per-feature attribution renders.

## M9 — Sequence models + benchmark
Session construction, Markov baseline, LogBERT. Identity sources only.

**Accept:** Scenario 5 (account takeover ordering) detected by a sequence model and **not** by L3
features — that contrast is the proof the layer earns its place. Comparison table published.

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
