import type { Metadata } from "next";
import Link from "next/link";
import { fetchServer } from "@/lib/api/server";
import type {
  IncidentDetail,
  IncidentGraph,
  TimelineResponse,
} from "@/lib/api/types";
import { CaseHeader } from "@/components/incidents/case/CaseHeader";
import { NarrativeBlock } from "@/components/incidents/case/NarrativeBlock";
import { ContradictingEvidence } from "@/components/incidents/case/ContradictingEvidence";
import { TimelinePhases } from "@/components/incidents/case/TimelinePhases";
import { LazyEvidenceSection } from "@/components/incidents/case/LazyEvidenceSection";
import { SignalsSection } from "@/components/incidents/case/SignalsSection";
import { EntityGraph } from "@/components/incidents/case/EntityGraph";
import { InvestigationGuidance } from "@/components/incidents/case/InvestigationGuidance";
import { AgentTrace } from "@/components/incidents/case/AgentTrace";
import { IncidentFeedback } from "@/components/incidents/case/IncidentFeedback";

export const metadata: Metadata = { title: "Case file — Tenex SOC Analyst" };

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-[var(--color-text-lo)]">{children}</h2>
  );
}

/**
 * docs/10: "the most important screen in the product... a vertical document, not a grid of
 * widgets." Every section fetches in parallel server-side; the client-only pieces
 * (`NarrativeBlock`'s citation expansion, `IncidentFeedback`) hydrate on top of that one
 * server-rendered pass rather than each re-fetching their own snapshot.
 */
export default async function CaseFilePage({
  params,
}: {
  params: Promise<{ id: string; iid: string }>;
}) {
  const { id, iid } = await params;

  // Evidence is deliberately absent from this batch: the endpoint recomputes every payload
  // per request (~12s), and awaiting it here is what made the case file exceed Vercel's
  // server-render budget and throw. `LazyEvidenceSection` fetches it after paint.
  const [incident, timeline, graph] = await Promise.all([
    fetchServer<IncidentDetail>(`/api/incidents/${iid}`),
    // `TimelineResponse`, not a bare array: the route returns `{phases: [...]}`. Typed as an
    // array it type-checked fine and then threw `phases.map is not a function` during the
    // server render — the whole case file 500'd on every incident click.
    fetchServer<TimelineResponse>(`/api/incidents/${iid}/timeline`),
    fetchServer<IncidentGraph>(`/api/incidents/${iid}/graph`),
  ]);

  if (incident === null) {
    return (
      <div className="flex flex-col items-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-16 text-center">
        <p className="text-sm text-[var(--color-text-mid)]">
          Incident not found, or the API is unreachable.
        </p>
        <Link href={`/analyses/${id}/incidents`} className="text-sm text-[var(--color-text-hi)] underline underline-offset-2">
          Back to incidents
        </Link>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-10 pb-16">
      <Link
        href={`/analyses/${id}/incidents`}
        className="w-fit text-xs text-[var(--color-text-lo)] transition-colors hover:text-[var(--color-text-mid)]"
      >
        ← Incidents
      </Link>

      {/* 1. Header */}
      <CaseHeader incident={incident} analysisId={id} />

      {/* 2. Summary — always present (this is a pipeline output now, not an LLM side effect):
          `incident.summary` is deterministic, computed at correlate time for every incident,
          zero LLM cost (`app.graph.summary`), and never destructively replaced. When a richer
          LLM narrative exists (`incident.verdict.summary`) it takes the primary serif slot per
          docs/10's "richer narrative should take precedence"; the deterministic one still
          renders underneath, labelled, so both provenances stay legible — never one silently
          standing in for the other. */}
      <section className="flex flex-col gap-3">
        {incident.verdict?.summary ? (
          <>
            <p className="max-w-[68ch] font-serif text-[17px] leading-[1.65] text-[var(--color-text-hi)]">
              {incident.verdict.summary}
            </p>
            <div className="max-w-[68ch]">
              <p className="mb-1 text-xs uppercase tracking-wide text-[var(--color-text-lo)]">
                Detected automatically, before triage
              </p>
              <p className="text-sm leading-[1.6] text-[var(--color-text-mid)]">{incident.summary}</p>
            </div>
          </>
        ) : (
          <p className="max-w-[68ch] font-serif text-[17px] leading-[1.65] text-[var(--color-text-hi)]">
            {incident.summary}
          </p>
        )}
      </section>

      {/* 3. Narrative — the signature element */}
      <section>
        <SectionHeading>Narrative</SectionHeading>
        <NarrativeBlock
          narrative={incident.verdict?.narrative ?? []}
          invalidCitations={incident.verdict?.invalid_citations ?? []}
          analysisId={id}
        />
      </section>

      {/* 4. Contradicting evidence — above the fold, visually distinct */}
      <ContradictingEvidence text={incident.verdict?.contradicting_evidence} />

      {/* 5. Timeline */}
      <section>
        <SectionHeading>Timeline</SectionHeading>
        <TimelinePhases phases={timeline?.phases ?? []} />
      </section>

      {/* 6. Evidence — docs/v2_migration change 16, between Timeline and Signals */}
      <section>
        <SectionHeading>Evidence</SectionHeading>
        <LazyEvidenceSection analysisId={id} incidentId={iid} />
      </section>

      {/* 7. Signals */}
      <section>
        <SectionHeading>Signals ({incident.signals.length})</SectionHeading>
        <SignalsSection signals={incident.signals} />
      </section>

      {/* 8. Entity graph */}
      <section>
        <SectionHeading>Entity graph</SectionHeading>
        <EntityGraph graph={graph ?? { nodes: [], edges: [] }} />
      </section>

      {/* 9. Investigation guidance */}
      <section>
        <SectionHeading>Investigation guidance</SectionHeading>
        <InvestigationGuidance actions={incident.verdict?.recommended_actions} />
      </section>

      {/* 10. Agent trace — collapsed by default */}
      <section>
        <SectionHeading>Agent trace</SectionHeading>
        <AgentTrace verdict={incident.verdict} />
      </section>

      {/* 11. Feedback */}
      <section>
        <SectionHeading>Feedback</SectionHeading>
        <IncidentFeedback incidentId={incident.id} />
      </section>
    </div>
  );
}
