/**
 * Browser-side API client. Every call goes straight to the API's own origin
 * (never a Next.js route handler) and sends `credentials: "include"` so the
 * httpOnly session cookie the API sets rides along — see docs/09 and
 * docs/06. Do not add a proxy layer here.
 *
 * **CSRF.** The API's session cookie is `SameSite=None` in every deployed
 * environment (Vercel web + Fly api are different registrable domains, so
 * `SameSite=Lax` would never ride along on a cross-site fetch at all) — see
 * `backend/app/core/csrf.py` and docs/06's "SameSite decision record". That
 * gives up the browser's own CSRF defense, so the API compensates with a
 * double-submit token: login also sets a second, JS-readable cookie
 * (`tenex_csrf`), and every mutating request (POST/PUT/PATCH/DELETE) must
 * echo its value back in an `X-CSRF-Token` header or the API rejects it
 * with 403. `apiFetch` reads that cookie and attaches the header
 * automatically for every mutating call, so callers never have to think
 * about it — including `login`/`logout` below and `lib/api/upload.ts`'s
 * separate XHR-based upload path, which reads the same cookie the same way.
 */
import {
  isApiErrorBody,
  type LoginRequest,
  type LoginResponse,
  type ResendVerificationRequest,
  type ResendVerificationResponse,
  type SignupRequest,
  type SignupResponse,
} from "./types";

/**
 * Base for every browser-originated API call. `""` means same-origin: requests go to
 * `/api/...` on the frontend's own host, and `next.config.ts`'s rewrite proxies them to
 * the API. That indirection is what makes the session cookie first-party — see that
 * file's comment for why addressing the API's own origin directly could never
 * authenticate in a split-domain deploy.
 *
 * Same-origin is the default for any production build precisely because it is the safe
 * one: a deploy that forgets to configure anything gets the arrangement that works,
 * rather than silently falling back to a cross-domain URL that cannot carry a session.
 * `NEXT_PUBLIC_API_URL` still overrides it, which is what the docker-compose frontend
 * (`http://api:8000`, same-origin impossible across containers) relies on.
 */
export const API_URL =
  process.env.NEXT_PUBLIC_API_URL ??
  (process.env.NODE_ENV === "production" ? "" : "http://localhost:8000");

export const CSRF_COOKIE_NAME = "tenex_csrf";
export const CSRF_HEADER_NAME = "X-CSRF-Token";

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * Reads the CSRF cookie straight out of `document.cookie`. It is
 * deliberately NOT httpOnly (see the module docstring) — that's what makes
 * this possible at all. Returns `null` before the first login, when the
 * cookie doesn't exist yet (e.g. the login request itself, which the API
 * exempts from the token check for exactly this reason).
 */
export function readCsrfToken(): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(
    new RegExp(`(?:^|; )${CSRF_COOKIE_NAME}=([^;]*)`),
  );
  return match ? decodeURIComponent(match[1] ?? "") : null;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, body: { detail: string; code: string }) {
    super(body.detail);
    this.name = "ApiError";
    this.status = status;
    this.code = body.code;
  }
}

async function parseErrorBody(res: Response): Promise<{ detail: string; code: string }> {
  try {
    const data: unknown = await res.json();
    if (isApiErrorBody(data)) return data;
  } catch {
    // Body wasn't JSON — fall through to the generic message below.
  }
  return { detail: `Request failed with status ${res.status}.`, code: "unknown_error" };
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? "GET").toUpperCase();
  const csrfToken = MUTATING_METHODS.has(method) ? readCsrfToken() : null;

  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(csrfToken ? { [CSRF_HEADER_NAME]: csrfToken } : {}),
      ...init?.headers,
    },
  });

  if (!res.ok) {
    throw new ApiError(res.status, await parseErrorBody(res));
  }

  if (res.status === 204) {
    return undefined as T;
  }

  return (await res.json()) as T;
}

export function login(body: LoginRequest): Promise<LoginResponse> {
  return apiFetch<LoginResponse>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function logout(): Promise<void> {
  return apiFetch<void>("/api/auth/logout", { method: "POST" });
}

export function signup(body: SignupRequest): Promise<SignupResponse> {
  return apiFetch<SignupResponse>("/api/auth/signup", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function resendVerification(
  body: ResendVerificationRequest,
): Promise<ResendVerificationResponse> {
  return apiFetch<ResendVerificationResponse>("/api/auth/resend-verification", {
    method: "POST",
    body: JSON.stringify(body),
  });
}
