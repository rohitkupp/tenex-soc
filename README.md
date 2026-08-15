# Tenex SOC Analyst

An AI SOC analyst pipeline for **ZScaler web proxy logs**. It normalizes raw proxy lines to OCSF,
detects anomalies through a layered funnel, correlates signals into incidents on an entity graph,
triages each incident with a Claude agent that cites its evidence, derives an ordered containment
plan from an action graph, and learns from analyst feedback.

**Live demo:** https://tenex-soc.vercel.app · **API:** https://34-150-170-252.sslip.io/api/docs

> **Start here:** [AI_APPROACH.md](AI_APPROACH.md) — what the models are, what they were
> benchmarked against, and the three results that came back different from what was predicted.
> [backend/evals/results.md](backend/evals/results.md) has every number behind it.

---

## The organizing idea

Each stage is 10–100× more expensive than the last, so **each stage must reduce volume before the
next one runs.** The LLM never sees raw log volume — it sees a few dozen correlated events per
incident, for at most the top 15 incidents by fused score.

```
400k proxy lines
  → L1 Sigma rules            (every event, SQL)
  → L2 signal processing      (beaconing, DGA, burst, rarity, STL residual, URL path)
  → L3 entity-window ML       (5 models over 53 features per (entity, hour))
  → L5 entity graph           (Louvain communities → incidents)
  → fuse & calibrate          (isotonic per detector → one comparable score)
  → agentic triage            (top 15 incidents only)
  → response plan → learn
```

L4 (sequence models over event ordering) was built, benchmarked, and **rejected** — see
[AI_APPROACH.md](AI_APPROACH.md#l4-the-layer-that-did-not-ship).

## One log source, deliberately

The brief says "pick your favorite log format" — singular. Multi-source correlation was never
asked for. The parser interface stays pluggable ([docs/03](docs/03-PARSERS-OCSF.md)) so a second
source is cheap to add, but shipping one source is the scope that matches the brief and leaves
room for analytical depth on it instead of breadth across three.

An earlier revision of this project *did* ingest Okta and CloudTrail. Narrowing to proxy-only was
a deliberate mid-build decision, and the freed capacity went into the two extra L3 models (ECOD,
LOF), two extra L2 detectors (STL, URL path), and entity-relative features — all of which are
benchmarked below.

---

## Running it locally

**Prerequisites:** Docker Desktop. Nothing else — no Python or Node install needed.

```bash
cp .env.example .env     # optional: add ANTHROPIC_API_KEY for the agent layer
make up                  # postgres, rabbitmq, minio, redis, api, web
make migrate             # apply schema
make seed                # demo user + seeded feedback history
```

| Service | URL |
|---|---|
| Web | http://localhost:3000 |
| API health | http://localhost:8000/api/health |
| API docs | http://localhost:8000/api/docs |
| RabbitMQ | http://localhost:15672 (tenex / tenex) |
| MinIO | http://localhost:9001 (tenexminio / tenexminio123) |

`make help` lists everything else.

**The pipeline runs end to end without an Anthropic API key** — only agentic triage is skipped.
`DEMO_MODE=true` serves precomputed verdicts, making zero API calls.

**Fitted model artifacts are committed.** A reviewer's first five minutes should not be a training
run. `make train` reproduces them from scratch (~165 s) if you want to.

---

## What is actually built

| Layer | Shipped | Where |
|---|---|---|
| Parser + OCSF | ZScaler NSS web log → OCSF HTTP Activity (4002) | `backend/app/parsers/`, `backend/app/ocsf/` |
| L1 rules | 11 Sigma-format YAML rules compiled to SQL — no rule logic in Python | `backend/app/detection/rules/` |
| L2 signal | beaconing (CV/MAD + FFT), DGA, burst, rarity, STL residual, URL path entropy | `backend/app/detection/signal/` |
| L3 ML | Isolation Forest, Mahalanobis, ECOD, LOF, autoencoder — 53 features per `(entity, hour)` | `backend/app/detection/ml/` |
| L5 graph | entity graph, Louvain communities, incident formation, recurrence via pgvector | `backend/app/graph/` |
| Fusion | isotonic calibration per detector, layer-diversity bonus | `backend/app/detection/fusion.py` |
| Agent | tool-using Claude triage, MITRE RAG, citation verification | `backend/app/agent/` |
| Response | action graph → topologically ordered plan, stateful simulated enforcement, rollback | `backend/app/response/` |
| Learning | 5 feedback consumers, detector reweighting, suppression candidates, retraining gate | `backend/app/learning/` |
| Tier 2 | cross-tenant indicator overlap, NL→SQL with a read-only role | `backend/app/tier2/` |
| Frontend | 12 routes, per-detector explanation renderers, entity graph, case file | `frontend/` |

**1,033 tests.** ~40k lines of Python across `app/`, `datagen/`, `evals/`; ~21k lines of tests.

---

## Seven rules this codebase actually enforces

These are in [CLAUDE.md](CLAUDE.md) and each one is load-bearing, not aspirational:

1. **The LLM never sees raw log volume.** Every stage reduces before the next.
2. **No model ships without a benchmark it must beat.** Losing is a valid, reportable outcome —
   and it happened three times. See [AI_APPROACH.md](AI_APPROACH.md).
3. **Log content is untrusted input.** It is attacker-controllable and flows into prompts. Never
   in a system prompt; always delimited and marked as data. There is a
   `prompt_injection_canary` scenario in the corpus that exists to test this.
4. **Pseudonymize before any external call.** HMAC with a per-tenant salt, allowlist not denylist.
5. **The LLM does not set priority.** Severity and queue rank come from the calibrated fusion
   score. The LLM contributes disposition, narrative, and technique mapping only.
6. **Every LLM claim cites event IDs, and citations are programmatically verified.** Unverified
   claims are flagged in the UI, not silently rendered.
7. **Determinism where possible.** Seeded RNG, temperature 0, recorded LLM responses in tests.

---

## Security work worth reading

- **SQL injection via CTE shadowing.** The Tier 2 NL→SQL validator originally subtracted forbidden
  table names from the parsed query's table set. `WITH users AS (SELECT * FROM users) SELECT *
  FROM users` defeats that — the CTE name masks the real table. Found by attacking our own code;
  fixed with `sqlglot.optimizer.scope.build_scope` proper scope resolution; locked in by
  regression test. The chatbot also connects as a dedicated `tier2_readonly` Postgres role that is
  **proven denied at the database level** on `events`, `users`, and the signatures base table,
  with a 5 s `statement_timeout` that actually kills `pg_sleep(10)`.
- **Structural tenant isolation.** Not a filter a handler can forget — a SQLAlchemy
  `do_orm_execute` hook installs `with_loader_criteria` for every tenant-scoped model. It must use
  a true closure, not a lambda default arg; SQLAlchemy's statement cache does not track the latter.
- **Cross-domain auth.** Vercel and the API VM are different registrable domains, so `SameSite=Lax`
  cookies are never sent. Chose `SameSite=None` + double-submit CSRF (`hmac.compare_digest`) +
  Origin validation, with the decision recorded in [docs/06](docs/06-PRIVACY-SECURITY.md).
- **Streaming uploads.** `app/storage/streaming_upload.py` drives `python-multipart`'s parser
  against `Request.stream()` rather than FastAPI's `UploadFile`, which spools to disk. A 150 MB
  upload grows RSS by 17.5 MB.

## Bugs the tests caught that are worth naming

- **float4 keyset pagination never terminated.** `incidents.fused_score` is `REAL`; a Python float
  binds as float8, and Postgres resolves `float4 < float8` by *widening the column* — `0.7` stored
  as float4 reads back as `0.699999988079071`, strictly less than the `0.7` in the cursor. Every
  row on the page satisfied the predicate again, forever. Fixed by casting the parameter down to
  `REAL`. The test that caught it constructs five incidents at an identical score.
- **`CORS_ORIGINS` crash-looped the API on first deploy.** pydantic-settings JSON-decodes
  complex-typed env fields *before* validators run, so a comma-delimited string dies inside
  `json.loads`. `Annotated[list[str], NoDecode]` is the fix and it is load-bearing.
- **STL flagged 50% of all events** before two fixes: near-degenerate residual populations
  producing spurious finite z-scores, and idle-hour contamination of the scoring population.
  Both are documented in `backend/evals/results.md`. It still isn't good enough — see below.

---

## Known gaps, stated plainly

Nothing here is hidden in a footnote. Each is a real limitation of what shipped.

1. **STL does not detect the scenario it was built for.** 0 of 36 malicious lines on
   `seasonal_deviation`. Its 11.4% background false-positive rate is too high for production. Root
   cause analyzed (self-inclusive MSTL fit absorbing a deliberately subtle campaign); the fix needs
   persisted cross-analysis history this batch harness does not have.
2. **Mahalanobis's false-positive rate is 16.6%** on the 53-feature vector, roughly tripled from
   the earlier 50-feature run. Flagged as a real regression; not root-caused.
3. **URL path analysis is untested by the eval suite** — no scenario encodes data in URL paths, so
   its 0/6 is "not exercised," not "failed." Unit tests are the only correctness evidence.
4. **All L3 models are global, not per-entity.** Six of 53 features are entity-relative, which
   partially addresses this, but Mahalanobis still fits one org-wide covariance.
5. **Synthetic data circularity.** The generator and the detectors were written by the same author.
   The eval corpus uses a different seed and a namespaced org fingerprint from training, and no
   model is scored on data it was fit or tuned on — but that does not make the scenarios
   adversarially realistic. One measured fidelity gap within that: **human user agents are
   desktop-only**, so the 26.3% mobile share of the real browser table is unreachable
   ([docs/11](docs/11-SYNTHETIC-DATA.md)). Held in place by an `xfail(strict=True)` test rather
   than fixed, because changing the generator would invalidate every number in
   `backend/evals/results.md` for a realism detail no detector reads.
6. **The enforcement plane is deliberately simulated** and stateful. Everything else runs for real.
7. **`GET /api/models` is not implemented.** The `/models` page therefore renders the committed
   benchmark tables from `backend/evals/results.md` as a clearly-labeled static report rather than
   a live call. The numbers are the real ones; the delivery mechanism is not the live one. Every
   other page in the UI is driven by a working endpoint.

---

## Documentation

Design docs were written before the code and are normative — the implementation follows them, and
where they disagreed with each other (three times, found by independent implementations
conflicting) the doc was fixed first.

| Doc | Covers |
|---|---|
| [01-ARCHITECTURE](docs/01-ARCHITECTURE.md) | Services, queue topology, stage contracts, deployment |
| [02-DATA-MODEL](docs/02-DATA-MODEL.md) | Postgres schema |
| [03-PARSERS-OCSF](docs/03-PARSERS-OCSF.md) | Parser contract and OCSF field mappings |
| [04-DETECTION](docs/04-DETECTION.md) | The detection layers, models, fusion and calibration |
| [05-CORRELATION](docs/05-CORRELATION.md) | Entity graph and incident formation |
| [06-PRIVACY-SECURITY](docs/06-PRIVACY-SECURITY.md) | Pseudonymization, redaction, prompt-injection defense |
| [07-AGENT](docs/07-AGENT.md) | Tools, three-role flow, citation verification |
| [08-RESPONSE-AND-LEARNING](docs/08-RESPONSE-AND-LEARNING.md) | Action graph, enforcement plane, feedback consumers |
| [09-API-CONTRACT](docs/09-API-CONTRACT.md) | Every endpoint |
| [10-FRONTEND](docs/10-FRONTEND.md) | Routes, design direction, components |
| [11-SYNTHETIC-DATA](docs/11-SYNTHETIC-DATA.md) | Generator and the eight labeled scenarios |
| [12-EVALUATION](docs/12-EVALUATION.md) | Metrics, harness, pre-registered predictions, CI gate |
| [13-MILESTONES](docs/13-MILESTONES.md) | Build order and acceptance criteria |

Built as a take-home exercise for Tenex.ai.
