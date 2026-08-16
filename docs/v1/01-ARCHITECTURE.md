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
| `enricher` | worker | `q.enrich` | `q.anonymize` |
| `anonymizer` | worker | `q.anonymize` | `q.detect` |
| `detector` | worker | `q.detect` | `q.correlate` |
| `correlator` | worker | `q.correlate` | `q.triage` |
| `agent` | worker | `q.triage` | `q.tier2` |
| `tier2-sync` | worker | `q.tier2` | — |

The `responder` worker and `q.respond` (the response action graph and simulated enforcement
plane) were removed — docs/v2_migration change 20. `agent` now publishes directly to `q.tier2`.

Infra: `rabbitmq`, `postgres` (pgvector), `minio`, `redis` (SSE pub/sub only).

## Queue topology

- One durable queue per worker, prefetch 1.
- Every queue has a paired `dlq.<name>` bound via `x-dead-letter-exchange`.
- Retry policy: 3 attempts with exponential backoff (1s, 4s, 16s), then dead-letter.
- Parser fan-out is trivial today: one source type means ingest always publishes to a single
  `q.parse.zscaler`, and `analyses.pending_parsers` is always 1. The completion-counter mechanism
  stays anyway — it is what makes a second parser a queue-topology no-op instead of a rewrite. A
  mixed upload would fan out to N parser queues in parallel and gate the move to `enrich` on N
  completions, exactly as this mechanism already does at N=1.

## Message envelope

Every inter-service message uses this shape. Never pass payloads larger than this.

```python
class StageMessage(BaseModel):
    analysis_id: UUID
    tenant_id: UUID
    stage: str
    storage_ref: str | None      # s3://bucket/key for raw or parsed artifacts
    source_type: str | None      # zscaler
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
| ingest | file in MinIO | `analyses` row, source type detected, `pending_parsers` set (always 1) |
| parse | raw artifact exists | `events` rows written, `parse_failure_rate` recorded |
| enrich | events exist | `events.enrichment` populated, `entities` seeded |
| anonymize | events enriched | `pseudonym_map` written, `events.redacted` populated |
| detect | events anonymized | `signals` rows with calibrated confidence |
| correlate | signals exist | `entities`, `entity_edges`, `incidents` |
| triage | incidents exist | `triage_verdicts` for top-N, citations verified |
| tier2 | verdicts exist | `tier2_signatures` rows |

## Progress streaming

`api` exposes `GET /api/analyses/{id}/stream` (SSE). Workers publish to Redis channel
`analysis:{id}`; the API relays. Event shape:

```json
{ "stage": "detect", "progress": 0.62, "message": "Scoring entity windows",
  "counters": { "events": 1412903, "signals": 812, "incidents": 14 } }
```

The funnel counters are the headline UI element — keep them current at every stage.

**Terminal contract.** Every event carries `status`, one of `queued | running | complete | failed`,
mirroring `analyses.status`. The stream is terminal when `status` is `complete` or `failed`; the
API then closes the SSE connection and the client closes its `EventSource`.

This is specified because it cannot be inferred. Reading terminality from `stage`/`progress` means
guessing which stage is last — and the last stage changes as milestones land, so a client that
guesses today breaks silently at M12 and leaks one connection per analysis while the funnel sits
at 99% forever.

```json
{ "stage": "triage", "progress": 1.0, "status": "complete", "message": "Done",
  "counters": { "events": 1412903, "signals": 812, "incidents": 14, "needs_attention": 3 } }
```

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
```

`DEMO_MODE` was removed (docs/v2_migration change 12). Every upload now runs the full pipeline
and agent triage makes a real Anthropic API call for every incident — `ANTHROPIC_API_KEY` is
required for triage to succeed; a missing key surfaces as a clear 503 from
`POST /api/incidents/{id}/triage` / `POST /api/analyses/{id}/triage`, not a silent fallback to
synthesized verdicts. `MAX_TRIAGE_INCIDENTS` remains the cost ceiling, and per-analysis spend
(`analyses.llm_cost_usd`) accumulates from each triage verdict's real per-call cost and is
exposed on `GET /api/analyses/{id}`.
