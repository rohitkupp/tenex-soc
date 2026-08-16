# CLAUDE.md

Project memory. Read this first, every session.

## What this is

An AI SOC analyst pipeline. Ingests ZScaler web proxy logs, normalizes to OCSF, detects
anomalies through a layered funnel, correlates signals into incidents on an entity graph, triages
each incident with a Claude agent that cites its evidence, and learns from analyst feedback.

**A v2 migration is in progress** — `docs/v2_migration/MIGRATION-01-evidence-first.md`. It
outranks every doc in `docs/v1/` where they disagree. Governing sentence: *machines calculate
facts, the LLM interprets meaning.* Before adding anything, check whether the migration deletes
or reshapes it.

One log source, deliberately. The brief says "pick your favorite log format" — singular. Multi-
source correlation was never asked for; the parser interface stays pluggable (`docs/v1/03-PARSERS-OCSF.md`) so
adding a second source later is cheap, but shipping one is the scope that matches the brief and
leaves room for analytical depth on it instead.

Built as a take-home for an AI/ML Engineer role at Tenex.ai (an AI-native MDR provider).
The reviewer is their CTO. Optimize for **technical depth in the AI/ML layer** and
**explainability of every decision**, not for feature count.

## Non-negotiable rules

1. **The LLM never sees raw log volume.** Every stage must reduce volume before the next.
   If you find yourself passing more than a few hundred events into a prompt, stop.
2. **No model ships without a benchmark.** Every model has a simpler baseline it must beat
   on the labeled eval set. Results go in `EVALUATION.md`. Losing is a valid, reportable outcome.
3. **Log content is untrusted input.** It is attacker-controllable and flows into LLM prompts.
   Never put it in a system prompt. Always delimit and mark as data. See `docs/v1/06-PRIVACY-SECURITY.md`.
4. **Pseudonymize before any external call.** Nothing identifiable leaves the tenant boundary.
5. **The LLM does not set priority.** Severity and queue rank come from the calibrated fusion
   score. The LLM contributes disposition, narrative, and technique mapping only.
6. **Every LLM claim cites event IDs, and citations are programmatically verified.**
   Unverified claims get flagged, not silently rendered.
7. **Determinism where possible.** Seeded RNG, recorded LLM responses in tests. The same input
   file must produce the same signals. Note: `temperature` is *not* sent — sampling parameters
   are removed on `claude-opus-5` and passing one returns a 400 (`app/agent/client.py`).
   Determinism comes from recorded fixtures, which was always the real guarantee.

## Stack

| Layer | Choice |
|---|---|
| Frontend | Next.js 15 App Router, TypeScript strict, Tailwind, shadcn/ui |
| Backend | Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0 |
| Workers | Python, `aio-pika` on RabbitMQ |
| DB | Postgres 16 + pgvector |
| Object store | MinIO (S3 API) |
| ML | scikit-learn, LightGBM (learning-loop retrain only), networkx, pyod, statsmodels, shap |
| LLM | Anthropic Claude via `anthropic` SDK |

## Repo layout

```
.
├── CLAUDE.md
├── docs/                  # design docs — read the relevant one before implementing
├── docker-compose.yml
├── Makefile
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/           # FastAPI routers
│   │   ├── core/          # config, security, db, logging
│   │   ├── models/        # SQLAlchemy
│   │   ├── schemas/       # Pydantic
│   │   ├── parsers/       # one module per log source (zscaler today — the interface is the point)
│   │   ├── ocsf/          # OCSF classes + mappers
│   │   ├── detection/
│   │   │   ├── rules/     # Sigma YAML + evaluator
│   │   │   ├── signal/    # beaconing, dga, burst, rarity, stl, url_path (→ evidence/, change 2)
│   │   │   ├── ml/        # features, navigation, iforest, mahalanobis, ecod, lof
│   │   │   └── fusion.py  # calibration + score fusion
│   │   ├── graph/         # entity graph, correlation, incident scoring
│   │   ├── privacy/       # pseudonymizer, redactor
│   │   ├── agent/         # claude client, tools, prompts, verifier
│   │   ├── learning/      # feedback consumers, retraining
│   │   ├── workers/       # one entrypoint per service
│   │   └── pipeline/      # orchestrator, stage contracts, progress
│   ├── evals/
│   ├── datagen/           # synthetic log generator
│   ├── data/              # mitre corpus, sample logs, enrichment datasets
│   └── tests/
└── frontend/
    ├── app/
    ├── components/
    └── lib/
```

## Commands

```bash
make up            # docker-compose up, all services
make down
make migrate       # alembic upgrade head
make seed          # demo user + seeded feedback history
make gen-data      # regenerate synthetic corpus + labeled scenarios
make train         # train all models, write artifacts to backend/data/models/
make eval          # run golden dataset, write evals/results.md, exit 1 on regression
make test          # pytest + vitest
make lint          # ruff + mypy + eslint + tsc
```

## Conventions

**Python.** Ruff (line length 100). Full type hints; `mypy --strict` on `app/detection`,
`app/agent`, `app/graph`. Pydantic v2 for every boundary. No bare `except`. Structured logging
via `structlog` — never `print`.

**TypeScript.** `strict: true`, no `any`. Server Components by default; `"use client"` only
where interaction requires it. Types for API responses generated from the OpenAPI schema — do
not hand-write them.

**SQL.** Alembic for every schema change. Every query filtered by `tenant_id`. Never string-
interpolate user input.

**Tests.** Every detector needs a unit test with a synthetic fixture that must fire and one
that must not. Every Sigma rule needs a positive and negative fixture. Agent tests use recorded
LLM responses, not live calls.

## Documents

Read the relevant doc before implementing. Do not infer a design that a doc already specifies.

| Doc | Read before |
|---|---|
| `docs/v1/01-ARCHITECTURE.md` | touching services, queues, or deployment |
| `docs/v1/02-DATA-MODEL.md` | any schema or migration work |
| `docs/v1/03-PARSERS-OCSF.md` | writing a parser or touching normalization |
| `docs/v1/04-DETECTION.md` | any detector, feature, or model |
| `docs/v1/05-CORRELATION.md` | entity graph or incident formation |
| `docs/v1/06-PRIVACY-SECURITY.md` | auth, anonymization, prompts, or SQL generation |
| `docs/v1/07-AGENT.md` | anything touching the Claude agent |
| `docs/v1/08-RESPONSE-AND-LEARNING.md` | feedback consumers and the learning loop (Part 1 deleted — migration change 20) |
| `docs/v1/09-API-CONTRACT.md` | any endpoint, on either side |
| `docs/v1/10-FRONTEND.md` | any UI work |
| `docs/v1/11-SYNTHETIC-DATA.md` | the generator or scenario definitions |
| `docs/v1/12-EVALUATION.md` | metrics or the CI gate |
| `docs/v1/13-MILESTONES.md` | starting any new milestone |

## Anti-patterns

- Do not add libraries not listed in the stack table without asking.
- Do not build UI beyond the routes in `docs/v1/10-FRONTEND.md`.
- Do not add auth features beyond credentials login, self-serve signup, and email verification
  (no password reset, no OAuth, no MFA). Signup and verification were added after the original
  scope was set — `docs/06` records the design, why Supabase Auth is only an email-ownership
  oracle rather than the identity provider, and why email MFA was rejected on the merits.
- Do not "improve" a detector's math without updating `docs/v1/04-DETECTION.md` and re-running `make eval`.
- Do not write hardcoded rule logic in Python — rules are Sigma YAML.
- Do not fabricate ATT&CK technique IDs. They come from `backend/data/kb/mitre/` — an allowlist
  of 13 **proxy-observable** techniques, not all of ATT&CK (migration change 4). A web proxy
  cannot observe registry writes or process injection, and retrieving those invites hypotheses
  the telemetry can never support. Loading anything outside the allowlist is rejected.
- Do not mock what should be real. Everything runs for real; `DEMO_MODE` was removed (migration
  change 12), so every upload makes live API calls. Tests still replay recorded fixtures and CI
  must never need a key.
- Do not reintroduce the response action graph, the enforcement plane, the autoencoder, LightGBM
  as a technique classifier, or any sequence model. All four were deleted deliberately — the
  migration records why for each.

## When uncertain

Stop and ask. A wrong architectural guess costs more than a question. Specifically: if a doc
is silent on something load-bearing, ask rather than inventing — then we update the doc.
