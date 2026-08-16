import type { Metadata } from "next";
import Link from "next/link";
import { fetchServer } from "@/lib/api/server";
import type { AnalysisEvidenceResponse } from "@/lib/api/types";
import { EvidenceExplorer } from "@/components/evidence/EvidenceExplorer";

export const metadata: Metadata = { title: "Evidence — Tenex SOC Analyst" };

// docs/v2_migration change 16 (secondary view): "/analyses/[id]/evidence — every payload
// produced for the analysis, filterable by extractor, entity and percentile, including
// evidence that never formed an incident."
export default async function AnalysisEvidencePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const data = await fetchServer<AnalysisEvidenceResponse>(`/api/analyses/${id}/evidence`);
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
        <h1 className="mt-1 text-xl font-semibold tracking-tight text-[var(--color-text-hi)]">Evidence</h1>
        <p className="mt-1 text-sm text-[var(--color-text-mid)]">
          Every evidence payload produced for this analysis, including evidence that never formed an incident.
        </p>
      </div>

      {unreachable ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-16 text-center">
          <p className="text-sm text-[var(--color-severity-high)]">Could not load evidence — the API is unreachable.</p>
          <p className="text-xs text-[var(--color-text-lo)]">Reload the page once it is back.</p>
        </div>
      ) : (
        <EvidenceExplorer analysisId={id} initial={data} />
      )}
    </div>
  );
}
