import type { Metadata } from "next";
import Link from "next/link";
import { fetchServer } from "@/lib/api/server";
import type { IncidentDetail, IncidentGraph, PlanOut, TimelinePhaseOut } from "@/lib/api/types";
import { CaseHeader } from "@/components/incidents/case/CaseHeader";
import { NarrativeBlock } from "@/components/incidents/case/NarrativeBlock";
import { ContradictingEvidence } from "@/components/incidents/case/ContradictingEvidence";
import { TimelinePhases } from "@/components/incidents/case/TimelinePhases";
import { SignalsSection } from "@/components/incidents/case/SignalsSection";
import { EntityGraph } from "@/components/incidents/case/EntityGraph";
import { ResponsePlanStepper } from "@/components/incidents/case/ResponsePlanStepper";
import { AgentTrace } from "@/components/incidents/case/AgentTrace";
import { FeedbackControls } from "@/components/incidents/case/FeedbackControls";

export const metadata: Metadata = { title: "Case file — Tenex SOC Analyst" };

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-[var(--color-text-lo)]">{children}</h2>
  );
}

/**
 * docs/10: "the most important screen in the product... a vertical document, not a grid of
 * widgets." Every section fetches in parallel server-side; the client-only pieces
 * (`NarrativeBlock`'s citation expansion, `ResponsePlanStepper`'s approve/rollback,
 * `FeedbackControls`) hydrate on top of that one server-rendered pass rather than each
 * re-fetching their own snapshot.
 */
export default async function CaseFilePage({
  params,
}: {
  params: Promise<{ id: string; iid: string }>;
}) {
  const { id, iid } = await params;

  const [incident, timeline, graph, plan] = await Promise.all([
    fetchServer<IncidentDetail>(`/api/incidents/${iid}`),
    fetchServer<TimelinePhaseOut[]>(`/api/incidents/${iid}/timeline`),
    fetchServer<IncidentGraph>(`/api/incidents/${iid}/graph`),
    fetchServer<PlanOut>(`/api/incidents/${iid}/plan`),
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

      {/* 2. Summary */}
      {incident.verdict?.summary && (
        <section>
          <p className="max-w-[68ch] font-serif text-[17px] leading-[1.65] text-[var(--color-text-hi)]">
            {incident.verdict.summary}
          </p>
        </section>
      )}

      {/* 3. Narrative — the signature element */}
      <section>
        <SectionHeading>Narrative</SectionHeading>
        <NarrativeBlock
          narrative={incident.verdict?.narrative ?? []}
          invalidCitations={incident.verdict?.invalid_citations ?? []}
        />
      </section>

      {/* 4. Contradicting evidence — above the fold, visually distinct */}
      <ContradictingEvidence text={incident.verdict?.contradicting_evidence} />

      {/* 5. Timeline */}
      <section>
        <SectionHeading>Timeline</SectionHeading>
        <TimelinePhases phases={timeline ?? []} />
      </section>

      {/* 6. Signals */}
      <section>
        <SectionHeading>Signals ({incident.signals.length})</SectionHeading>
        <SignalsSection signals={incident.signals} />
      </section>

      {/* 7. Entity graph */}
      <section>
        <SectionHeading>Entity graph</SectionHeading>
        <EntityGraph graph={graph ?? { nodes: [], edges: [] }} />
      </section>

      {/* 8. Response plan */}
      <section>
        <SectionHeading>Response plan</SectionHeading>
        <ResponsePlanStepper initialPlan={plan} />
      </section>

      {/* 9. Agent trace — collapsed by default */}
      <section>
        <SectionHeading>Agent trace</SectionHeading>
        <AgentTrace verdict={incident.verdict} />
      </section>

      {/* 10. Feedback */}
      <section>
        <SectionHeading>Feedback</SectionHeading>
        <FeedbackControls incidentId={incident.id} />
      </section>
    </div>
  );
}
