# 01 — Architecture

## Services

Each worker is a separate container with its own queue. This is deliberate: it demonstrates
horizontal scale-out, and it is how the pattern works in production.

| Service | Type | Consumes | Produces |
|---|---|---|---|
| `web` | Next.js | — | HTTP to `api` |
| `api` | FastAPI | HTTP | publishes to `q.orchestrator` |
| `orchestrator` | worker | `q.orchestrator` | routes to parser queues |
| `parser-zscaler` | worker | `q.parse.zscaler` | `q.enrich` |
| `parser-okta` | worker | `q.parse.okta` | `q.enrich` |
| `parser-cloudtrail` | worker | `q.parse.cloudtrail` | `q.enrich` |
| `enricher` | worker | `q.enrich` | `q.anonymize` |
| `anonymizer` | worker | `q.anonymize` | `q.detect` |
| `detector` | worker | `q.detect` | `q.correlate` |
| `correlator` | worker | `q.correlate` | `q.triage` |
| `agent` | worker | `q.triage` | `q.respond` |
| `responder` | worker | `q.respond` | `q.tier2` |
| `tier2-sync` | worker | `q.tier2` | — |

Infra: `rabbitmq`, `postgres` (pgvector), `minio`, `redis` (SSE pub/sub only).

## Queue topology

- One durable queue per worker, prefetch 1.
- Every queue has a paired `dlq.<name>` bound via `x-dead-letter-exchange`.
- Retry policy: 3 attempts with exponential backoff (1s, 4s, 16s), then dead-letter.
- Parser fan-out is **parallel** — one analysis containing three source types publishes to three
  parser queues, and a completion counter in `analyses.pending_parsers` gates the move to enrich.

## Message envelope

Every inter-service message uses this shape. Never pass payloads larger than this.

```python
class StageMessage(BaseModel):
    analysis_id: UUID
    tenant_id: UUID
    stage: str
    storage_ref: str | None      # s3://bucket/key for raw or parsed artifacts
    source_type: str | None      # zscaler | okta | cloudtrail
    attempt: int = 0
    emitted_at: datetime
```

Bulk data goes to Postgres or MinIO. Queues carry references, never rows.

## Stage contracts

Each stage reads its input from the DB/object store, writes its output there, updates
`analyses.stage` and `analyses.progress`, publishes a progress event to Redis, then publishes
the next `StageMessage`.

| Stage | Precondition | Postcondition |
|---|---|---|
| ingest | file in MinIO | `analyses` row, source types detected, `pending_parsers` set |
| parse | raw artifact exists | `events` rows written, `parse_failure_rate` recorded |
| enrich | events exist | `events.enrichment` populated, `entities` seeded |
| anonymize | events enriched | `pseudonym_map` written, `events.redacted` populated |
| detect | events anonymized | `signals` rows with calibrated confidence |
| correlate | signals exist | `entities`, `entity_edges`, `incidents` |
| triage | incidents exist | `triage_verdicts` for top-N, citations verified |
| respond | verdicts exist | `response_plans` in `pending_approval` |
| tier2 | plans exist | `tier2_signatures` rows |

## Progress streaming

`api` exposes `GET /api/analyses/{id}/stream` (SSE). Workers publish to Redis channel
`analysis:{id}`; the API relays. Event shape:

```json
{ "stage": "detect", "progress": 0.62, "message": "Running sequence models",
  "counters": { "events": 1412903, "signals": 812, "incidents": 14 } }
```

The funnel counters are the headline UI element — keep them current at every stage.

## Deployment

| Component | Target |
|---|---|
| `web` | Vercel |
| `api` + all workers + rabbitmq + minio | Fly.io (or Railway) |
| Postgres | Neon |

**Do not use Render's free tier** — 15-minute spin-down with ~50s cold start. The reviewer
will hit it.

Uploads go **browser → `api` directly**, not through Vercel. This avoids the ~4.5 MB serverless
body limit entirely. Configure CORS on `api` for the Vercel origin.

`docker-compose.yml` must bring up the full topology locally with one command and no cloud
dependencies except the Anthropic API.

## Environment

```
DATABASE_URL, RABBITMQ_URL, REDIS_URL
S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY, S3_BUCKET
ANTHROPIC_API_KEY, ANTHROPIC_MODEL
JWT_SECRET, JWT_TTL_MINUTES
PSEUDONYM_SALT              # per-tenant salt, never logged
MAX_TRIAGE_INCIDENTS=15     # LLM cost ceiling
AGENT_MAX_TOOL_CALLS=8
AGENT_TIMEOUT_SECONDS=120
DEMO_MODE=false             # serve precomputed results, skip LLM calls
```

`DEMO_MODE` matters — it lets the reviewer explore the deployed app without waiting on the
pipeline or burning API budget.
