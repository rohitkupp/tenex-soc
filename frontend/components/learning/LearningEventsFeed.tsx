import type { LearningEventOut } from "@/lib/api/types";
import { formatCompactDate } from "@/lib/format";
import { Badge } from "@/components/ui/Badge";

// docs/10 /learning section 5: "learning events" — docs/v2_migration change 21's feed. One row
// per `learning_events` write: an auto mechanism's immediate state change, or a gated
// mechanism's proposal/decision.
export function LearningEventsFeed({ events }: { events: LearningEventOut[] }) {
  if (events.length === 0) {
    return (
      <p className="text-sm text-[var(--color-text-mid)]">
        No learning events yet — give an incident some feedback to start the loop.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      {events.map((e) => (
        <div
          key={e.id}
          className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-[var(--color-border)] px-3 py-2 text-xs"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[var(--color-text-hi)]">
              #{e.mechanism} {e.mechanism_name}
            </span>
            <Badge variant={e.applied ? undefined : "outline"}>
              {e.applied ? "applied" : "proposed"}
            </Badge>
            {e.metric_delta && Object.keys(e.metric_delta).length > 0 && (
              <span className="text-[var(--color-text-lo)]">
                {Object.entries(e.metric_delta)
                  .slice(0, 3)
                  .map(([k, v]) => `${k}: ${typeof v === "number" ? v.toFixed(3) : String(v)}`)
                  .join(" · ")}
              </span>
            )}
          </div>
          <span className="text-[var(--color-text-lo)]">{formatCompactDate(e.created_at)}</span>
        </div>
      ))}
    </div>
  );
}
