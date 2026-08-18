"use client";

/**
 * Refreshes the Tier 2 page when a pipeline run contributes to it.
 *
 * Every panel here is a `GROUP BY` over the whole signature store, so a run finishing anywhere in
 * the fleet changes what this page shows — but the page is server-rendered once and had no way to
 * learn that. It went stale the moment an analysis completed and stayed stale until a manual
 * reload.
 *
 * Subscribes to `/api/tier2/stream`, the single fleet-wide SSE channel the `tier2` stage publishes
 * to on completion. On an event it calls `router.refresh()`, which re-runs the server components
 * in place — the charts re-fetch, scroll position survives, and no client-side chart state is
 * thrown away. Deliberately a refresh rather than applying the event's counts as a delta: these
 * are aggregates over the entire store, and a partial update could not be applied correctly.
 *
 * The connection is best-effort. If SSE never opens, the page behaves exactly as it did before —
 * correct on load, stale afterwards — rather than erroring.
 */
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export function Tier2LiveRefresh() {
  const router = useRouter();
  const [lastUpdate, setLastUpdate] = useState<string | null>(null);

  useEffect(() => {
    // Same-origin: `next.config.ts` rewrites /api/* to the backend, which is what keeps the
    // session cookie first-party. EventSource sends cookies only for same-origin requests.
    const source = new EventSource("/api/tier2/stream");

    source.onmessage = (event) => {
      let payload: { signatures_written?: number; type?: string };
      try {
        payload = JSON.parse(event.data);
      } catch {
        return;
      }
      // The hello frame just confirms the stream is open; nothing has changed yet.
      if (payload.type === "connected") return;

      setLastUpdate(new Date().toLocaleTimeString());
      router.refresh();
    };

    // No `onerror` retry loop: EventSource reconnects on its own, and a hand-rolled one would
    // race it. A permanently failed stream leaves the page in its load-time state, which is
    // correct — just not live.
    return () => source.close();
  }, [router]);

  if (!lastUpdate) return null;

  return (
    <p className="text-xs text-[var(--color-text-lo)]">
      Updated {lastUpdate} — a pipeline run added to the cross-tenant store.
    </p>
  );
}
