"use client";

/**
 * The case file's Evidence section, fetched after the page renders rather than with it.
 *
 * `GET /api/incidents/{id}/evidence` recomputes every `EvidencePayload` for the incident on each
 * request (`build_agent_context`), which measured ~12s against production. The case file used to
 * `await` it inside its server-side `Promise.all`, so the whole page waited on it and blew
 * Vercel's server-render budget — that is the "server-side exception" analysts hit on every
 * incident click (digest 2144078614).
 *
 * Everything else on the case file (verdict, narrative, signals, graph) is sub-second and still
 * renders server-side. Only this section defers, so the page appears immediately and the
 * evidence fills in.
 */
import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api/client";
import type { IncidentEvidenceResponse } from "@/lib/api/types";
import { EvidenceSection } from "@/components/incidents/case/EvidenceSection";

export function LazyEvidenceSection({
  analysisId,
  incidentId,
}: {
  analysisId: string;
  incidentId: string;
}) {
  const [data, setData] = useState<IncidentEvidenceResponse | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    apiFetch<IncidentEvidenceResponse>(`/api/incidents/${incidentId}/evidence`)
      .then((res) => {
        if (!cancelled) setData(res);
      })
      .catch(() => {
        // Say so rather than sitting on a spinner forever — a silent permanent "Loading…" is
        // indistinguishable from a hang, which is how the analysis-level Evidence tab failed.
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [incidentId]);

  if (failed) {
    return (
      <p className="text-sm text-[var(--color-severity-high)]">
        Could not load evidence for this incident.
      </p>
    );
  }

  if (data === null) {
    return <p className="text-sm text-[var(--color-text-mid)]">Loading evidence…</p>;
  }

  return <EvidenceSection data={data} analysisId={analysisId} incidentId={incidentId} />;
}
