"use client";

/**
 * The Evidence tab, fetched on first activation rather than with the page.
 *
 * `GET /api/analyses/{id}/evidence` returns up to `MAX_ANALYSIS_EVIDENCE_ITEMS` payloads — 328KB
 * and ~13s against production. Fetching it server-side alongside the other three tabs would put
 * that on the critical path of the analysis page, so opening the page at all would cost the
 * slowest tab nobody had asked for yet. Overview, Incidents and Events are all sub-second and
 * stay server-rendered; only this one defers.
 *
 * Fetched once and kept — switching away and back does not re-request.
 */
import { useEffect, useRef, useState } from "react";
import { apiFetch } from "@/lib/api/client";
import type { AnalysisEvidenceResponse } from "@/lib/api/types";
import { EvidenceExplorer } from "@/components/evidence/EvidenceExplorer";

export function LazyEvidenceTab({ analysisId, active }: { analysisId: string; active: boolean }) {
  const [data, setData] = useState<AnalysisEvidenceResponse | null>(null);
  const [failed, setFailed] = useState(false);
  // A ref, not state, and the effect depends only on (active, analysisId).
  //
  // The first version kept `state` in the dependency array and returned a cleanup that set
  // `cancelled = true`. Calling `setState("loading")` re-rendered immediately, React ran that
  // cleanup, and the in-flight request's `.then` saw `cancelled` and dropped the response — so
  // the panel sat on "Loading evidence…" forever even though the request had returned 200.
  // Nothing about the fetch needs to be re-run or torn down when local state changes; it needs
  // to happen exactly once per analysis, which is what a ref expresses.
  const started = useRef<string | null>(null);

  useEffect(() => {
    if (!active || started.current === analysisId) return;
    started.current = analysisId;
    apiFetch<AnalysisEvidenceResponse>(`/api/analyses/${analysisId}/evidence`)
      .then(setData)
      .catch(() => setFailed(true));
  }, [active, analysisId]);

  if (failed) {
    return (
      <div className="flex flex-col items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-16 text-center">
        <p className="text-sm text-[var(--color-severity-high)]">
          Could not load evidence — the API is unreachable.
        </p>
      </div>
    );
  }

  if (data === null) {
    return <p className="px-1 py-8 text-sm text-[var(--color-text-mid)]">Loading evidence…</p>;
  }

  return <EvidenceExplorer analysisId={analysisId} initial={data} />;
}
