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
| POST | `/api/auth/signup` | `{email, password, org_name}` | 201 `{status, email}` |
| POST | `/api/auth/resend-verification` | `{email}` | 202 `{status, email}` |
| POST | `/api/auth/login` | `{email, password}` | sets cookie, `{user}` |
| POST | `/api/auth/logout` | — | 204 |
| GET | `/api/auth/me` | — | `{user, tenant}` |

`signup` returns the same 201 for an address that is already registered, and `resend-verification`
returns 202 for every address, known or not — neither may disclose whether an account exists
(docs/06). `login` gains one new failure, `403 email_not_verified`, which is only reachable *after*
the password check passes; a caller without valid credentials still gets the generic
`401 invalid_credentials`. All three are exempt from the double-submit CSRF check for the reason
login always was: there is no session yet from which to derive a token.

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
| GET | `/api/tier2/overlap-distribution` | Chart 1: indicator count by tenant-count bucket (`1`/`2`/`3+`) |
| GET | `/api/tier2/technique-prevalence` | Chart 2: all 13 allowlisted ATT&CK techniques, tenant count per technique |
| GET | `/api/tier2/detector-reliability` | Chart 3: per-detector confirm/dismiss counts, pooled across every tenant's analyst feedback |
| GET | `/api/tier2/first-seen` | Chart 4: for indicators seen by 2+ tenants, each tenant's first-observed timestamp |

**`POST /api/tier2/query` (the NL-to-SQL chatbot) has been removed.** It was the one route
in this section that could make a live Anthropic call; removed under a hard cost constraint
that this surface must shrink, never grow. Every route above is deterministic and non-LLM,
including the four cross-tenant learning charts. `app.tier2.nl_to_sql`/`sql_validator` are
deleted with it; `app.tier2.readonly_db`/`views` (the `tier2_readonly` Postgres role and its
two allowlisted views) are kept — see `backend/app/tier2/__init__.py`'s docstring.

## Ops

| Method | Path | Notes |
|---|---|---|
| GET | `/api/ops/queues` | Depth per queue |
| GET | `/api/ops/dead-letters` | Failed messages |
| POST | `/api/ops/dead-letters/{id}/retry` | Republish |
| GET | `/api/health` | Unauthenticated. Dependency checks. |


## Endpoints removed by `docs/v2_migration`

| Endpoint | Removed by | Note |
|---|---|---|
| `GET /api/ops/queues` | change 27 | queue depth belongs in Cloud Monitoring |
| `GET /api/ops/dead-letters` | change 27 | the table stays; only the console is gone |
| `POST /api/ops/dead-letters/{id}/retry` | change 27 | replaced by `POST /api/analyses/{id}/retry` |
| `GET /api/incidents/{id}/plan` | change 20 | response action graph deleted |
| `POST /api/plans/{id}/approve` | change 20 | |
| `POST /api/plans/{id}/rollback` | change 20 | |
| `GET /api/plans/{id}/state-diff` | change 20 | |

Added: `POST /api/analyses/{id}/retry` — republishes the dead-lettered `StageMessage` from the
failed stage with a fresh attempt budget and reopens the analysis. `GET /api/health` and the
`/api/models/*` endpoints are explicitly retained; change 27 removed the `/models` *route*, not
its API.
