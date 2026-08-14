# Tenex SOC Analyst

An AI SOC analyst pipeline. It ingests raw security logs (ZScaler web proxy, Okta system log,
AWS CloudTrail), normalizes them to OCSF, detects anomalies through a layered funnel, correlates
signals into incidents on an entity graph, triages each incident with a Claude agent that cites
its evidence, derives an ordered containment plan from an action graph, and learns from analyst
feedback.

> **Status: M0 (scaffold).** The full milestone plan is in [docs/13-MILESTONES.md](docs/13-MILESTONES.md).
> This README is expanded into the real deliverable at M17.

## The organizing idea

Each stage is 10–100× more expensive than the last, so **each stage must reduce volume before the
next one runs.** The LLM never sees raw log volume.

```
L1 rules (100% of events) → L2 signal processing → L3 entity-window ML
  → L4 sequence models (identity only) → L5 graph → classify → fuse & calibrate
  → agentic triage (top-N incidents only) → response plan → learn
```

## Running it locally

**Prerequisites:** Docker Desktop. Nothing else — no Python or Node install required, and no
cloud dependency except an Anthropic API key for the triage layer.

```bash
cp .env.example .env     # optional: add ANTHROPIC_API_KEY for the agent layer
make up                  # brings up postgres, rabbitmq, minio, redis, api, web
make migrate             # apply schema
```

| Service | URL |
|---|---|
| Web | http://localhost:3000 |
| API health | http://localhost:8000/api/health |
| API docs | http://localhost:8000/api/docs |
| RabbitMQ | http://localhost:15672 (tenex / tenex) |
| MinIO | http://localhost:9001 (tenexminio / tenexminio123) |

`make help` lists everything else.

The pipeline runs end to end **without** an Anthropic API key — only the agentic triage stage is
skipped. `DEMO_MODE=true` serves precomputed verdicts so the deployed demo is explorable without
latency or spend.

## Documentation

| Doc | Covers |
|---|---|
| [01-ARCHITECTURE](docs/01-ARCHITECTURE.md) | Services, queue topology, stage contracts, deployment |
| [02-DATA-MODEL](docs/02-DATA-MODEL.md) | Postgres schema |
| [03-PARSERS-OCSF](docs/03-PARSERS-OCSF.md) | Parser contract and OCSF field mappings |
| [04-DETECTION](docs/04-DETECTION.md) | The five detection layers, models, fusion and calibration |
| [05-CORRELATION](docs/05-CORRELATION.md) | Entity graph and incident formation |
| [06-PRIVACY-SECURITY](docs/06-PRIVACY-SECURITY.md) | Pseudonymization, redaction, prompt-injection defense |
| [07-AGENT](docs/07-AGENT.md) | Tools, three-role flow, citation verification |
| [08-RESPONSE-AND-LEARNING](docs/08-RESPONSE-AND-LEARNING.md) | Action graph, enforcement plane, feedback consumers |
| [09-API-CONTRACT](docs/09-API-CONTRACT.md) | Every endpoint |
| [10-FRONTEND](docs/10-FRONTEND.md) | Routes, design direction, components |
| [11-SYNTHETIC-DATA](docs/11-SYNTHETIC-DATA.md) | Generator and the ten labeled scenarios |
| [12-EVALUATION](docs/12-EVALUATION.md) | Metrics, harness, CI regression gate |
| [13-MILESTONES](docs/13-MILESTONES.md) | Build order and acceptance criteria |

Built as a take-home exercise for Tenex.ai.
