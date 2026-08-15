import type { NextConfig } from "next";

/**
 * `API_ORIGIN` is the API's real origin (e.g. https://34-150-170-252.sslip.io).
 * Server-only — deliberately not `NEXT_PUBLIC_`, since nothing in the browser
 * should address the API by its own origin any more. See the rewrite below.
 */
const API_ORIGIN = process.env.API_ORIGIN ?? "http://localhost:8000";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  output: "standalone",
  typescript: { ignoreBuildErrors: false },
  eslint: { ignoreDuringBuilds: false },

  /**
   * Same-origin proxy for the API, and the thing that makes authentication work
   * at all in the split-domain production deploy.
   *
   * The session is an httpOnly cookie the API sets on *its own* origin. Vercel and
   * the API VM are different registrable domains, so the browser correctly refuses
   * to attach that cookie to any request aimed at the frontend's origin — this is
   * cookie *scope*, not SameSite, and no CORS setting can change it. The practical
   * consequence was total: `middleware.ts` could never observe a session, so every
   * authenticated route bounced to /login, and all nine dashboard pages'
   * `fetchServer` calls returned null. `middleware.ts`'s own docstring predicted
   * this ("in a genuinely cross-site production deploy... it does not [hold]").
   *
   * Routing the browser through `/api/*` on the frontend's own origin makes the
   * Set-Cookie first-party: the browser stores it against the Vercel domain, sends
   * it on every subsequent navigation, and `cookies()` in a Server Component and
   * `request.headers` in middleware can both finally see it. The API is unchanged
   * and still authoritative — it reads the same JWT out of the same cookie name,
   * and neither knows nor cares which host the browser filed it under.
   *
   * Cost, stated rather than discovered later: proxied request bodies are size-capped
   * (Vercel's platform limit is well below this API's own 200 MB ceiling), so a large
   * upload can no longer stream browser → API directly the way `docs/01` describes.
   * Small files are unaffected. Restoring direct large uploads needs the upload to
   * carry its own short-lived credential instead of the cookie, since a direct request
   * to the API origin will not include a cookie scoped to the Vercel domain.
   */
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API_ORIGIN}/api/:path*` }];
  },
};

export default nextConfig;
