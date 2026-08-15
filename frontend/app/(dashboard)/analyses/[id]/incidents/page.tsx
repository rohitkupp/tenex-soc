import type { Metadata } from "next";
import Link from "next/link";
import { fetchServer } from "@/lib/api/server";
import type { IncidentsListResponse } from "@/lib/api/types";
import { IncidentQueue } from "@/components/incidents/IncidentQueue";

export const metadata: Metadata = { title: "Incidents — Tenex SOC Analyst" };

// docs/10: "/analyses/[id]/incidents — the queue, the primary working view." Server-fetched
// once; filtering, sorting-preservation, and keyboard nav all live client-side in
// `IncidentQueue` over that one snapshot (docs/09's list-item shape is deliberately flat
// because this view can render hundreds of rows).
export default async function IncidentsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const data = await fetchServer<IncidentsListResponse>(`/api/analyses/${id}/incidents`);
  const unreachable = data === null;
  const incidents = data?.items ?? [];

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <Link
            href={`/analyses/${id}`}
            className="text-xs text-[var(--color-text-lo)] transition-colors hover:text-[var(--color-text-mid)]"
          >
            ← Analysis
          </Link>
          <h1 className="mt-1 text-xl font-semibold tracking-tight text-[var(--color-text-hi)]">Incidents</h1>
        </div>
        <Link
          href={`/analyses/${id}/events`}
          className="text-sm text-[var(--color-text-mid)] transition-colors hover:text-[var(--color-text-hi)]"
        >
          Raw events →
        </Link>
      </div>

      {unreachable ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-16 text-center">
          <p className="text-sm text-[var(--color-severity-high)]">Could not load incidents — the API is unreachable.</p>
          <p className="text-xs text-[var(--color-text-lo)]">Reload the page once it is back.</p>
        </div>
      ) : (
        <IncidentQueue analysisId={id} incidents={incidents} />
      )}
    </div>
  );
}
