/**
 * Server Component data fetching. `fetch` in a Server Component does not
 * inherit the browser's cookie jar, so the incoming request's cookies are
 * read via `next/headers` and forwarded explicitly on the outgoing request
 * to the API. Using `next/headers` here also means Next.js will refuse to
 * bundle this module into a Client Component, which is the guarantee we
 * want: this file never runs in the browser.
 */
import { cookies } from "next/headers";
import { API_URL } from "./client";

/**
 * Fetches from the API on behalf of the current request, forwarding
 * whatever cookies the browser attached. Returns `null` on any non-2xx
 * response or network failure — callers render an empty/unauthenticated
 * state rather than throwing, since middleware is the enforcement point for
 * route protection.
 */
export async function fetchServer<T>(path: string): Promise<T | null> {
  const cookieStore = await cookies();
  const cookieHeader = cookieStore.toString();

  try {
    const res = await fetch(`${API_URL}${path}`, {
      headers: cookieHeader ? { cookie: cookieHeader } : undefined,
      cache: "no-store",
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}
