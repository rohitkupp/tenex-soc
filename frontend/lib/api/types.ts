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
