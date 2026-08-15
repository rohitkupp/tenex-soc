import type { AnalysisTimelineResponse, TimelinePhaseOut } from "@/lib/api/types";
import { formatDate, formatScore } from "@/lib/format";
import { Badge } from "@/components/ui/Badge";
import { Panel } from "@/components/ui/Panel";

/**
 * `GET /api/analyses/{id}/timeline` (M15, new) — the brief's "summarized timeline of events"
 * deliverable, rendered high on `/analyses/[id]` rather than nested three clicks deep inside
 * one incident's case file. This is analysis-wide: phases span every entity the correlation
 * layer found across the whole run, not one incident's phases.
 *
 * Shares `TimelinePhases`' (`components/incidents/case/TimelinePhases.tsx`) dot-and-rail
 * visual language deliberately — same product, same "this is a sequence of things that
 * happened" idiom — but is a distinct component for a distinct scope, and additionally
 * surfaces `confidence` and `mitre_technique` per phase, which the case-file version doesn't
 * carry.
 *
 * `tactic_is_placeholder` is rendered exactly like `TimelinePhases` does it: an outline badge
 * instead of a filled one, plus a title making the distinction explicit on hover. A
 * deterministic tactic lookup must never read as though the agent attributed it.
 */
export function AnalysisTimeline({ data }: { data: AnalysisTimelineResponse | null }) {
  if (data === null) {
    return (
      <div className="flex flex-col items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-10 text-center">
        <p className="text-sm text-[var(--color-text-mid)]">
          Timeline not available — the analysis may still be processing, or the API is unreachable.
        </p>
      </div>
    );
  }

  const { phases, truncated } = data;

  return (
    <Panel
      title="Timeline"
      padding="tight"
      right={
        truncated ? (
          <span className="text-xs text-[var(--color-text-lo)]">
            Showing the {phases.length} highest-confidence phase{phases.length === 1 ? "" : "s"} — more phases exist
            and are not shown.
          </span>
        ) : undefined
      }
    >
      {phases.length === 0 ? (
        <p className="px-1 py-4 text-sm text-[var(--color-text-mid)]">
          No timeline phases yet — nothing has been correlated for this analysis so far.
        </p>
      ) : (
        <ol className="flex max-h-[32rem] flex-col gap-3 overflow-y-auto px-1 py-1">
          {phases.map((phase, i) => (
            <TimelineRow key={i} phase={phase} last={i === phases.length - 1} />
          ))}
        </ol>
      )}
    </Panel>
  );
}

function TimelineRow({ phase, last }: { phase: TimelinePhaseOut; last: boolean }) {
  const hasEntity = Boolean(phase.entity_type && phase.entity_value);
  const hasConfidence = phase.confidence !== undefined && phase.confidence !== null;
  return (
    <li className="flex gap-3">
      <div className="flex flex-col items-center pt-1">
        <span aria-hidden="true" className="h-2 w-2 rounded-full bg-[var(--color-text-mid)]" />
        {!last && <span aria-hidden="true" className="mt-1 w-px flex-1 bg-[var(--color-border)]" />}
      </div>
      <div className="flex flex-1 flex-col gap-1 pb-2">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={phase.tactic_is_placeholder ? "outline" : "neutral"}>
            <span
              title={
                phase.tactic_is_placeholder
                  ? "Deterministic lookup, not an agent attribution"
                  : "Agent-attributed ATT&CK tactic"
              }
            >
              {phase.tactic}
            </span>
          </Badge>
          {phase.mitre_technique && (
            <span className="rounded border border-[var(--color-border)] px-1.5 py-0.5 font-mono text-xs text-[var(--color-text-mid)]">
              {phase.mitre_technique}
            </span>
          )}
          <span className="text-xs text-[var(--color-text-lo)]">{phase.ts ? formatDate(phase.ts) : "no timestamp"}</span>
        </div>
        <p className="text-sm text-[var(--color-text-hi)]">{phase.summary}</p>
        <span className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-[var(--color-text-lo)]">
          {hasEntity && (
            <span>
              {phase.entity_type} <span className="font-mono text-[var(--color-text-mid)]">{phase.entity_value}</span>
            </span>
          )}
          {phase.detector_key && <span className="font-mono">{phase.detector_key}</span>}
          {hasConfidence && <span>confidence {formatScore(phase.confidence)}</span>}
          <span>
            {phase.event_ids.length} event{phase.event_ids.length === 1 ? "" : "s"}
          </span>
        </span>
      </div>
    </li>
  );
}
