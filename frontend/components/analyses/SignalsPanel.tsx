"use client";

/**
 * The Signals tab: every detector firing for the analysis, strongest first.
 *
 * This was the "Timeline" box on the Overview tab, and it was chronological with a
 * confidence-based *cut* — the worst of both. It showed the 100 highest-confidence phases
 * re-sorted by time, so it was neither a complete chronology nor a clean ranking, and the
 * heading had to admit "more phases exist and are not shown".
 *
 * It is now purely a ranking: highest confidence first, `PAGE_SIZE` at a time, with a button to
 * reveal more. Chronology moved to where it belongs — the Events tab, which windows the raw
 * events in order.
 *
 * A signal whose detector has no fitted isotonic calibrator carries `calibrated: false`, and its
 * `confidence` is `clamp01(raw_score)` — a raw score, not a probability. Those are labelled as
 * such rather than rendered as a percentage; a raw score clamped at 1.0 shown as "100% confident"
 * is the most misleading thing this view can say.
 */
import { useMemo, useState } from "react";
import { EventInspector } from "@/components/events/EventInspector";
import type { AnalysisTimelineResponse, TimelinePhaseOut } from "@/lib/api/types";
import { formatDate, formatScore } from "@/lib/format";
import { Badge } from "@/components/ui/Badge";
import { Panel } from "@/components/ui/Panel";

const PAGE_SIZE = 100;

export function SignalsPanel({
  data,
  analysisId,
}: {
  data: AnalysisTimelineResponse | null;
  analysisId: string;
}) {
  const [shown, setShown] = useState(PAGE_SIZE);

  const ranked = useMemo(() => {
    const phases = [...(data?.phases ?? [])];
    // Descending confidence, with detector key then timestamp as deterministic tiebreaks so the
    // order is stable across renders rather than dependent on the server's array order.
    phases.sort((a, b) => {
      const byConfidence = (b.confidence ?? -1) - (a.confidence ?? -1);
      if (byConfidence !== 0) return byConfidence;
      const byDetector = (a.detector_key ?? "").localeCompare(b.detector_key ?? "");
      if (byDetector !== 0) return byDetector;
      return (a.ts ?? "").localeCompare(b.ts ?? "");
    });
    return phases;
  }, [data]);

  if (ranked.length === 0) {
    return (
      <Panel title="Signals">
        <p className="text-sm text-[var(--color-text-mid)]">
          No signals for this analysis — no detector fired.
        </p>
      </Panel>
    );
  }

  const page = ranked.slice(0, shown);
  const remaining = ranked.length - page.length;

  return (
    <Panel title="Signals">
      <p className="mb-3 text-xs text-[var(--color-text-lo)]">
        {ranked.length} detector firing{ranked.length === 1 ? "" : "s"}, highest confidence first
        {data?.truncated && " (the server capped this set)"}. Chronological order lives on the
        Events tab.
      </p>
      <ol className="flex flex-col divide-y divide-[var(--color-border)]">
        {page.map((phase, i) => (
          <SignalRow key={`${phase.detector_key}-${phase.ts}-${i}`} phase={phase} analysisId={analysisId} />
        ))}
      </ol>
      {remaining > 0 && (
        <button
          type="button"
          onClick={() => setShown((n) => n + PAGE_SIZE)}
          className="mt-4 w-full rounded-md border border-[var(--color-border)] px-3 py-2 text-xs font-medium text-[var(--color-text-hi)] transition-colors hover:bg-[var(--color-surface-2)]"
        >
          Load {Math.min(PAGE_SIZE, remaining)} more ({remaining} remaining)
        </button>
      )}
    </Panel>
  );
}

// Expanding a signal fetches at most this many of its events — a chatty detector can cite
// dozens of events per window, and the point of the expansion is "show me what fired this",
// not a second events table.
const MAX_EVENTS_SHOWN = 5;

function SignalRow({ phase, analysisId }: { phase: TimelinePhaseOut; analysisId: string }) {
  const hasConfidence = phase.confidence !== undefined && phase.confidence !== null;
  const [expanded, setExpanded] = useState(false);
  const shownEventIds = phase.event_ids.slice(0, MAX_EVENTS_SHOWN);
  return (
    <li className="flex flex-col gap-1 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        {/* `tactic_is_placeholder` means the tactic came from a lookup table, not an agent
            attribution — and "Unattributed" specifically means this signal carried no ATT&CK
            technique, or one outside the 13 proxy-observable techniques the allowlist permits. */}
        <Badge variant={phase.tactic_is_placeholder ? "outline" : "neutral"}>
          <span
            title={
              phase.tactic_is_placeholder
                ? "No ATT&CK technique on this signal, or one outside the proxy-observable allowlist"
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
        {hasConfidence &&
          (phase.calibrated ? (
            <span className="font-mono text-xs text-[var(--color-text-hi)]">
              {formatScore(phase.confidence)}
            </span>
          ) : (
            <span
              className="font-mono text-xs text-[var(--color-text-lo)]"
              title="No isotonic calibrator is fitted for this detector, so this is a raw score clamped to [0,1] — not a calibrated probability, and not comparable with a calibrated detector's confidence."
            >
              {formatScore(phase.confidence)} raw
            </span>
          ))}
        <span className="text-xs text-[var(--color-text-lo)]">
          {phase.ts ? formatDate(phase.ts) : "no timestamp"}
        </span>
      </div>
      <p className="text-sm text-[var(--color-text-hi)]">{phase.summary}</p>
      <span className="flex flex-wrap items-center gap-x-3 text-xs text-[var(--color-text-lo)]">
        {phase.detector_key && <span className="font-mono">{phase.detector_key}</span>}
        {phase.event_ids.length > 0 ? (
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
            className="rounded border border-[var(--color-border)] px-1.5 py-0.5 text-[11px] text-[var(--color-text-mid)] transition-colors hover:bg-[var(--color-surface-2)]"
          >
            {expanded ? "hide" : "show"} {phase.event_ids.length} event
            {phase.event_ids.length === 1 ? "" : "s"}
          </button>
        ) : (
          <span>0 events</span>
        )}
      </span>
      {expanded && (
        <div className="mt-1 flex flex-col gap-2">
          {shownEventIds.map((eventId) => (
            <EventInspector
              key={eventId}
              eventId={eventId}
              analysisId={analysisId}
              detectorKey={phase.detector_key ?? undefined}
            />
          ))}
          {phase.event_ids.length > MAX_EVENTS_SHOWN && (
            <p className="text-xs text-[var(--color-text-lo)]">
              Showing the first {MAX_EVENTS_SHOWN} of {phase.event_ids.length} events — the full
              set is on the Events tab, filtered by this signal&apos;s entity.
            </p>
          )}
        </div>
      )}
    </li>
  );
}
