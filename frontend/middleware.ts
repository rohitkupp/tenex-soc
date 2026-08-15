import { NextResponse, type NextRequest } from "next/server";

/**
 * Server-side route protection (docs/06: "never client-side only").
 *
 * The session is an httpOnly JWT cookie *set by the API's origin*, signed
 * with a secret this app never holds — so middleware cannot decode or
 * verify it locally. Instead it asks the API's own `/api/auth/me`,
 * forwarding whatever cookie header the browser attached to the incoming
 * request. This is deliberate: duplicating JWT_SECRET into the frontend to
 * verify tokens locally would cross a trust boundary docs/06 treats as
 * load-bearing (the secret is API/tenant-boundary material), for a check
 * the API can answer authoritatively in one request.
 *
 * Known limitation, not papered over: this only works when the browser
 * actually attaches the API's cookie to a request aimed at *this* app's
 * origin. In local dev (both on `localhost`, cookies are host-only and not
 * port-scoped) that holds. In a genuinely cross-site production deploy
 * (e.g. Vercel + Fly on unrelated domains) it does not — the cookie belongs
 * to the API's origin only, and no server-side code running on the
 * frontend's origin can observe it, regardless of CORS settings. See the
 * handoff notes for the same caveat and the two ways to close it.
 */

// The API's real origin, server-side only. Middleware calls the API directly rather
// than through `next.config.ts`'s own `/api/*` rewrite: it already holds the cookie
// header it needs to forward, so the extra proxy hop back through this same app would
// buy nothing. `NEXT_PUBLIC_API_URL` is "" in production (same-origin, for the
// browser), which is not a usable base for `fetch` here — hence a separate variable
// rather than reusing that one.
const API_ORIGIN = process.env.API_ORIGIN ?? "http://localhost:8000";
const LOGIN_PATH = "/login";
// Unauthenticated-only pages: an anonymous visitor must be able to reach
// both without first having a session, and an already-authenticated visitor
// is bounced to "/" from either one.
const PUBLIC_PATHS = new Set([LOGIN_PATH, "/signup"]);

async function hasValidSession(cookieHeader: string): Promise<boolean> {
  try {
    const res = await fetch(`${API_ORIGIN}/api/auth/me`, {
      headers: { cookie: cookieHeader },
      cache: "no-store",
    });
    return res.ok;
  } catch {
    // API unreachable — fail closed rather than let an unverifiable
    // request through.
    return false;
  }
}

export async function middleware(request: NextRequest) {
  const cookieHeader = request.headers.get("cookie");
  const isAuthed = cookieHeader ? await hasValidSession(cookieHeader) : false;
  const isPublicPage = PUBLIC_PATHS.has(request.nextUrl.pathname);

  if (isPublicPage) {
    if (isAuthed) {
      return NextResponse.redirect(new URL("/", request.url));
    }
    return NextResponse.next();
  }

  if (!isAuthed) {
    return NextResponse.redirect(new URL(LOGIN_PATH, request.url));
  }

  return NextResponse.next();
}

export const config = {
  // Everything except static assets and the favicon goes through the auth
  // check above; /login and /signup are handled inside the middleware itself.
  //
  // `api` must be excluded, and it is load-bearing now in a way it wasn't before.
  // `next.config.ts` proxies `/api/*` to the real API, so those paths are no longer
  // hypothetical on this origin — without this exclusion the middleware answers them
  // itself, and since an unauthenticated caller has no session it 307s them to
  // /login. That turns *every* API call into a redirect, including the login request
  // whose whole job is to create the session the middleware is looking for: the
  // deadlock is total and presents as a login form that never resolves. Route
  // protection is not weakened by this — the API authenticates and tenant-scopes
  // every one of these requests itself, and always did; the middleware only ever
  // decided whether to render an app shell.
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
