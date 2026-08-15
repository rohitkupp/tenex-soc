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

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const LOGIN_PATH = "/login";

async function hasValidSession(cookieHeader: string): Promise<boolean> {
  try {
    const res = await fetch(`${API_URL}/api/auth/me`, {
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
  const isLoginPage = request.nextUrl.pathname === LOGIN_PATH;

  if (isLoginPage) {
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
  // check above; /login is handled inside the middleware itself.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
