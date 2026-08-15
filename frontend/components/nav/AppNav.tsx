import Link from "next/link";
import { fetchServer } from "@/lib/api/server";
import type { MeResponse } from "@/lib/api/types";
import { LogoutButton } from "./LogoutButton";

// Server Component: reads the session once per request so the nav can show
// who's signed in, without shipping the lookup to the client.
export async function AppNav() {
  const me = await fetchServer<MeResponse>("/api/auth/me");

  return (
    <header className="border-b border-[var(--color-border)] bg-[var(--color-surface-1)]">
      <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-4 px-6 py-3">
        <Link
          href="/"
          className="text-sm font-semibold tracking-tight text-[var(--color-text-hi)]"
        >
          Tenex SOC Analyst
        </Link>
        <nav className="flex items-center gap-5 text-sm">
          <Link
            href="/"
            className="text-[var(--color-text-mid)] transition-colors hover:text-[var(--color-text-hi)]"
          >
            Analyses
          </Link>
          <Link
            href="/upload"
            className="text-[var(--color-text-mid)] transition-colors hover:text-[var(--color-text-hi)]"
          >
            Upload
          </Link>
          {me && (
            <span className="hidden font-mono text-xs text-[var(--color-text-lo)] sm:inline">
              {me.user.email}
            </span>
          )}
          <LogoutButton />
        </nav>
      </div>
    </header>
  );
}
