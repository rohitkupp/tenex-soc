# 09 — API Contract

FastAPI. OpenAPI schema is the source of truth for frontend types — generate them, never
hand-write. All routes except auth require a valid JWT cookie and are tenant-scoped.

## Conventions

- Base path `/api`
- Snake_case JSON
- Errors: `{"detail": "...", "code": "machine_readable_code"}`
- Pagination: `?limit=&cursor=`, response `{items: [], next_cursor: str | null}`
- Timestamps: RFC 3339 UTC

## Auth

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | `/api/auth/login` | `{email, password}` | sets cookie, `{user}` |
| POST | `/api/auth/logout` | — | 204 |
| GET | `/api/auth/me` | — | `{user, tenant}` |

Rate limited to 5/min. Generic failure message — never reveal whether the email exists.

## Uploads & analyses

| Method | Path | Notes |
|---|---|---|
| POST | `/api/uploads` | `multipart/form-data`. Streams to MinIO. Returns `{upload_id, detected_sources, analysis_id}`. Kicks off the pipeline. 200 MB cap. |
| GET | `/api/analyses` | List, newest first |
| GET | `/api/analyses/{id}` | Status, stage, progress, counters, cost, parse failure rate |
| GET | `/api/analyses/{id}/stream` | **SSE.** Progress events until terminal state |
| DELETE | `/api/analyses/{id}` | Cascades |

SSE event:
```json
{ "stage": "detect", "progress": 0.62, "message": "Scoring entity windows",
  "counters": {"events": 1412903, "signals": 812, "incidents": 14, "needs_attention": 3} }
```

## Events

| Method | Path | Query |
|---|---|---|
| GET | `/api/analyses/{id}/events` | `principal, domain, src_ip, action, ts_from, ts_to, has_signal, limit, cursor` |
| GET | `/api/events/{event_id}` | Full OCSF + enrichment. Used by citation expansion in the UI. |

## Signals & incidents

| Method | Path | Notes |
|---|---|---|
| GET | `/api/analyses/{id}/signals` | Filter by `detector_layer`, `min_confidence` |
| GET | `/api/analyses/{id}/incidents` | Sorted by `fused_score` desc. Includes verdict summary if triaged. |
| GET | `/api/incidents/{id}` | Full detail: signals with explanations, entities, timeline, verdict, plan |
| GET | `/api/incidents/{id}/graph` | `{nodes: [], edges: []}` for the graph viz |
| GET | `/api/incidents/{id}/timeline` | Deterministic ordered phases |
| POST | `/api/incidents/{id}/feedback` | `{agrees, corrected_disposition?, corrected_technique?, dismissal_reason?, mark_benign_baseline?, note?}` |

Incident list item shape — keep it flat, the queue view renders hundreds:
```json
{ "id": "...", "title": "...", "severity": "high", "fused_score": 0.82,
  "disposition": "true_positive", "citation_valid": true,
  "mitre_techniques": ["T1071.001"], "entity_count": 4, "signal_count": 7,
  "recurrence_of": null, "created_at": "..." }
```

No `source_types` field — with one source there is nothing to badge.

## Response plans

| Method | Path | Notes |
|---|---|---|
| GET | `/api/incidents/{id}/plan` | Ordered actions, preconditions, verification result |
| POST | `/api/plans/{id}/approve` | Executes against the enforcement plane. Returns journal + outcome. |
| POST | `/api/plans/{id}/rollback` | Reverse-applies the journal |
| GET | `/api/plans/{id}/state-diff` | Before/after enforcement state |

Approval is the only state-mutating action in the product. Require an explicit confirmation
payload `{confirm: true}` — no accidental clicks.

## Models & learning

| Method | Path | Notes |
|---|---|---|
| GET | `/api/models` | Benchmark comparison tables, current promoted versions |
| GET | `/api/models/calibration` | Reliability diagram data |
| GET | `/api/models/versions` | Version history with gating eval scores |
| GET | `/api/learning/metrics` | Alignment %, per-detector precision trend, containment rate |
| GET | `/api/learning/suppressions` | Pending suppression rule candidates |
| POST | `/api/learning/suppressions/{id}/accept` | Writes the rule |

## Tier 2

| Method | Path | Notes |
|---|---|---|
| GET | `/api/tier2/overview` | Cross-tenant aggregates |
| GET | `/api/tier2/indicator-overlap` | Indicators seen across multiple tenants |
| POST | `/api/tier2/query` | `{question}` → `{sql, explanation, columns, rows, chart_hint}` |

`/api/tier2/query` **always returns the generated SQL**, and the UI always displays it before
results. See `docs/06` for the validation pipeline.

## Ops

| Method | Path | Notes |
|---|---|---|
| GET | `/api/ops/queues` | Depth per queue |
| GET | `/api/ops/dead-letters` | Failed messages |
| POST | `/api/ops/dead-letters/{id}/retry` | Republish |
| GET | `/api/health` | Unauthenticated. Dependency checks. |
