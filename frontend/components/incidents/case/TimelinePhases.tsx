import type { TimelinePhaseOut } from "@/lib/api/types";
import { formatDate } from "@/lib/format";
import { Badge } from "@/components/ui/Badge";

// 5. Timeline — docs/10: "deterministic phases with ATT&CK tactic labels."
export function TimelinePhases({ phases }: { phases: TimelinePhaseOut[] }) {
  if (phases.length === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No timeline available yet.</p>;
  }
  return (
    <ol className="flex flex-col gap-4">
      {phases.map((phase, i) => (
        <li key={i} className="flex gap-4">
          <div className="flex flex-col items-center pt-1">
            <span aria-hidden="true" className="h-2 w-2 rounded-full bg-[var(--color-text-mid)]" />
            {i < phases.length - 1 && <span aria-hidden="true" className="mt-1 w-px flex-1 bg-[var(--color-border)]" />}
          </div>
          <div className="flex flex-1 flex-col gap-1 pb-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={phase.tactic_is_placeholder ? "outline" : "neutral"}>{phase.tactic}</Badge>
              <span className="text-xs text-[var(--color-text-lo)]">{phase.ts ? formatDate(phase.ts) : "no timestamp"}</span>
            </div>
            <p className="text-sm text-[var(--color-text-hi)]">{phase.summary}</p>
            <span className="font-mono text-xs text-[var(--color-text-lo)]">
              {phase.event_ids.length} event{phase.event_ids.length === 1 ? "" : "s"}
              {phase.detector_key ? ` · ${phase.detector_key}` : ""}
            </span>
          </div>
        </li>
      ))}
    </ol>
  );
}
