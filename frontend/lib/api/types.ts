/**
 * PLACEHOLDER — hand-written temporary types.
 *
 * CLAUDE.md requires API types to be generated from the OpenAPI schema
 * (`npm run gen:api`, which writes `lib/api/schema.d.ts`). That target needs
 * the backend running at NEXT_PUBLIC_API_URL, and it was not reachable while
 * this milestone was built. These interfaces are hand-derived from
 * docs/09-API-CONTRACT.md so the app has no `any` in the meantime.
 *
 * TODO(replace): once the backend is up, run `npm run gen:api` and swap the
 * imports below for the generated `components["schemas"][...]` types. Fields
 * marked "best-effort" are not explicitly specified in docs/09 and should be
 * checked against the generated schema first.
 */

export interface ApiErrorBody {
  detail: string;
  code: string;
}

export function isApiErrorBody(value: unknown): value is ApiErrorBody {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as Record<string, unknown>).detail === "string" &&
    typeof (value as Record<string, unknown>).code === "string"
  );
}

// docs/09 documents auth responses as `{user}` / `{user, tenant}` without
// listing user/tenant fields. id + email are the minimum the UI needs.
export interface AuthUser {
  id: string;
  email: string;
}

export interface AuthTenant {
  id: string;
  name: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  user: AuthUser;
}

export interface MeResponse {
  user: AuthUser;
  tenant: AuthTenant;
}

export interface UploadResponse {
  upload_id: string;
  detected_sources: string[];
  analysis_id: string;
}

/**
 * Best-effort: docs/09 only spells out the fields for
 * `GET /api/analyses/{id}` (status, stage, progress, counters, cost,
 * parse_failure_rate), not the flat list-item shape returned by
 * `GET /api/analyses`. Consumers should treat every field but `id` and
 * `created_at` as possibly absent until the generated schema confirms them.
 */
export interface AnalysisListItem {
  id: string;
  created_at: string;
  status?: string;
  stage?: string | null;
  progress?: number | null;
  detected_sources?: string[];
}

// Pagination shape is documented generically in docs/09's conventions.
export interface AnalysesListResponse {
  items: AnalysisListItem[];
  next_cursor: string | null;
}

// ---- Analysis detail + pipeline streaming (M4) ----

/**
 * Full analysis resource — `GET /api/analyses/{id}`. Read directly off
 * `backend/app/schemas/uploads.py::AnalysisOut` since the OpenAPI generator
 * has nothing to point at yet (see the PLACEHOLDER note above); swap for
 * the generated `components["schemas"]["AnalysisOut"]` once `npm run
 * gen:api` is runnable.
 */
export interface AnalysisDetail {
  id: string;
  upload_id: string;
  status: string;
  stage: string | null;
  progress: number;
  pending_parsers: number;
  counters: Record<string, unknown>;
  parse_failure_rate: number | null;
  llm_cost_usd: number | string | null;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
}

/**
 * SSE payload from `GET /api/analyses/{id}/stream` — docs/01-ARCHITECTURE.md
 * and docs/09-API-CONTRACT.md give this shape verbatim (docs/09 additionally
 * documents `needs_attention` inside `counters`). There is no explicit
 * "done"/terminal flag on the wire; see `lib/api/stream.ts` for how terminal
 * state is inferred from `stage` + `progress` instead.
 */
export interface AnalysisStreamEvent {
  stage: string;
  progress: number;
  message: string;
  counters: Record<string, unknown>;
}

export function isAnalysisStreamEvent(value: unknown): value is AnalysisStreamEvent {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.stage === "string" &&
    typeof v.progress === "number" &&
    typeof v.message === "string" &&
    typeof v.counters === "object" &&
    v.counters !== null
  );
}

/**
 * Pulls out only the numeric entries of a counters payload. docs' examples
 * are all-numeric, but the wire type is loose (`dict[str, object]` on the
 * backend model), so this guards `AnimatedCounter` against ever being handed
 * a non-numeric value instead of trusting the payload blindly.
 */
export function numericCounters(counters: Record<string, unknown>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(counters)) {
    if (typeof value === "number") out[key] = value;
  }
  return out;
}

// ---- Ops (M4) ----

/**
 * PLACEHOLDER — best-effort, hand-derived, like the rest of this file.
 *
 * docs/09-API-CONTRACT.md documents `/api/ops/queues`, `/api/ops/dead-letters`,
 * and `/api/ops/dead-letters/{id}/retry` by one-line description only
 * ("Depth per queue", "Failed messages", "Republish") — it does not specify a
 * JSON shape. These are inferred from docs/01's queue topology (one durable
 * queue per worker, one paired `dlq.<name>`) and docs/09's generic
 * list-endpoint convention (`{items, next_cursor}`). Re-check against the
 * generated schema once `/api/ops/*` exists on the backend.
 */
export interface QueueDepth {
  name: string;
  depth: number;
  consumers?: number;
}

export interface QueuesResponse {
  queues: QueueDepth[];
}

/** Mirrors docs/01's `StageMessage` envelope — the payload a dead-lettered
 * message actually carries, for context alongside the failure. */
export interface DeadLetterMessage {
  analysis_id?: string;
  tenant_id?: string;
  stage?: string;
  storage_ref?: string | null;
  source_type?: string | null;
  attempt?: number;
  emitted_at?: string;
}

export interface DeadLetter {
  id: string;
  queue: string;
  error: string;
  attempts: number;
  failed_at: string;
  message?: DeadLetterMessage;
}

export interface DeadLettersResponse {
  items: DeadLetter[];
  next_cursor: string | null;
}
