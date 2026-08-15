/**
 * Browser-side API client. Every call goes straight to the API's own origin
 * (never a Next.js route handler) and sends `credentials: "include"` so the
 * httpOnly session cookie the API sets rides along — see docs/09 and
 * docs/06. Do not add a proxy layer here.
 */
import { isApiErrorBody, type LoginRequest, type LoginResponse } from "./types";

export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

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
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
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
