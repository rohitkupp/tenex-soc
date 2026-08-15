import type { Metadata } from "next";
import Link from "next/link";
import { fetchServer } from "@/lib/api/server";
import type { EventListResponse } from "@/lib/api/types";
import { EventExplorer } from "@/components/events/EventExplorer";

export const metadata: Metadata = { title: "Events — Tenex SOC Analyst" };

export default async function EventsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const data = await fetchServer<EventListResponse>(`/api/analyses/${id}/events?limit=100`);
  const unreachable = data === null;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <Link
          href={`/analyses/${id}`}
          className="text-xs text-[var(--color-text-lo)] transition-colors hover:text-[var(--color-text-mid)]"
        >
          ← Analysis
        </Link>
        <h1 className="mt-1 text-xl font-semibold tracking-tight text-[var(--color-text-hi)]">Events</h1>
        <p className="mt-1 text-sm text-[var(--color-text-mid)]">Raw parsed events for this analysis, filterable.</p>
      </div>

      {unreachable ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-16 text-center">
          <p className="text-sm text-[var(--color-severity-high)]">Could not load events — the API is unreachable.</p>
          <p className="text-xs text-[var(--color-text-lo)]">Reload the page once it is back.</p>
        </div>
      ) : (
        <EventExplorer analysisId={id} initial={data} />
      )}
    </div>
  );
}
