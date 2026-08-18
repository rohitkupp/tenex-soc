"use client";

/**
 * The pipeline funnel — docs/10-FRONTEND.md: "counters count up per stage as SSE
 * events arrive... The funnel is the thesis of the architecture, so make it the hero."
 *
 * docs/v2_migration change 27 moved this from a dedicated `/upload` page onto
 * `/analyses/[id]` itself: that page renders it live while `status` is `queued` or
 * `running`, statically once `complete`, and with the failing stage marked once
 * `failed` — "no separate page, no navigation," and the funnel is now on the page the
 * analyst actually stays on.
 *
 * Stage list and scope (ingest..triage, excluding respond/tier2) carried over
 * unchanged from the inert M1 placeholder this originally replaced — see
 * `lib/api/stream.ts` for the terminal-status contract this reads.
 */
import { useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { useAnalysisStream } from "@/lib/api/stream";
import { numericCounters, type AnalysisDetail } from "@/lib/api/types";
import { AnimatedCounter } from "./AnimatedCounter";

const STAGES = [
  { key: "ingest", label: "Ingest" },
  { key: "parse", label: "Parse" },
  { key: "enrich", label: "Enrich" },
  { key: "anonymize", label: "Anonymize" },
  { key: "detect", label: "Detect" },
  { key: "correlate", label: "Correlate" },
  { key: "triage", label: "Triage" },
] as const;

const COUNTER_ORDER = ["events", "signals", "incidents", "needs_attention"];
const COUNTER_LABELS: Record<string, string> = {
  events: "Events",
  signals: "Signals",
  incidents: "Incidents",
  needs_attention: "Needs attention",
};

function counterLabel(key: string): string {
  return COUNTER_LABELS[key] ?? key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function orderCounters(counters: Record<string, number>): Array<[string, number]> {
  const entries = new Map(Object.entries(counters));
  const orderedKeys = [
    ...COUNTER_ORDER.filter((key) => entries.has(key)),
    ...[...entries.keys()].filter((key) => !COUNTER_ORDER.includes(key)).sort(),
  ];
  return orderedKeys.map((key): [string, number] => [key, entries.get(key) ?? 0]);
}

type StageState = "done" | "active" | "pending" | "failed";

const STAGE_BADGE_CLASS: Record<StageState, string> = {
  pending:
    "rounded-full border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1 text-xs text-[var(--color-text-lo)]",
  active:
    "rounded-full border border-[var(--color-text-hi)] bg-[var(--color-surface-2)] px-3 py-1 text-xs font-medium text-[var(--color-text-hi)]",
  done: "rounded-full border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-1 text-xs text-[var(--color-text-mid)]",
  // docs/v2_migration change 27: "`/analyses/[id]` renders the failure at the point in
  // the funnel where it occurred, so the analyst sees *which* stage died rather than a
  // generic error" — the one stage badge that gets severity-critical styling.
  failed:
    "rounded-full border border-[var(--color-severity-critical)] bg-[var(--color-surface-2)] px-3 py-1 text-xs font-medium text-[var(--color-severity-critical)]",
};

interface FunnelProgressProps {
  analysisId: string;
  /**
   * Server-fetched snapshot (`GET /api/analyses/{id}`) to render before, or instead of,
   * a live connection. The header drop zone on `/` has no snapshot — the analysis was
   * just created, so the funnel connects immediately once the analyst lands on
   * `/analyses/[id]`. That page always has one; when it reports the run as finished (or
   * failed), the funnel renders statically and never opens a stream that will never
   * emit again.
   */
  initial?: Pick<
    AnalysisDetail,
    "status" | "stage" | "progress" | "counters" | "error" | "finished_at"
  > | null;
}

export function FunnelProgress({ analysisId, initial = null }: FunnelProgressProps) {
  const isFinished = initial !== null && initial.finished_at !== null;
  const { event, connection, done } = useAnalysisStream(isFinished ? null : analysisId);

  const status = event?.status ?? initial?.status ?? null;
  const stage = event?.stage ?? initial?.stage ?? null;
  const progress = event?.progress ?? initial?.progress ?? 0;
  const rawCounters = event?.counters ?? initial?.counters ?? {};
  const counters = numericCounters(rawCounters);
  const currentIndex = stage ? STAGES.findIndex((s) => s.key === stage) : -1;
  const failed = status === "failed";
  const complete = (isFinished && !failed) || (done && status === "complete");
  const errorMessage = event?.message ?? initial?.error ?? null;

  // Pull the server-rendered halves of this page (overview, incidents, signals, narrative) once
  // the pipeline reaches a terminal state. The funnel's own counters came from SSE and updated
  // live, but every panel around it was fetched during the original server render and stayed
  // frozen at "0 incidents" until the analyst manually reloaded — the run finished and the page
  // said nothing had happened.
  //
  // `router.refresh()` re-runs the server components in place, preserving the active tab and
  // scroll position, which a full reload would discard. Guarded by a ref so a stream that emits
  // several terminal events does not refetch repeatedly.
  const router = useRouter();
  const refreshed = useRef(false);
  const reachedTerminal = status === "complete" || status === "failed";
  useEffect(() => {
    if (!reachedTerminal || refreshed.current) return;
    // Only meaningful when the page was rendered mid-run; an already-finished analysis was
    // server-rendered complete and has nothing to catch up on.
    if (isFinished) return;
    refreshed.current = true;
    router.refresh();
  }, [reachedTerminal, isFinished, router]);

  const statusLabel = failed
    ? "Failed"
    : complete
      ? "Complete"
      : connection === "connecting"
        ? "Connecting…"
        : connection === "reconnecting"
          ? "Reconnecting…"
          : "Live";

  // Nothing to show yet at all — true only in the earliest moment right after upload,
  // before the pipeline has reported anything and no snapshot exists to fall back on.
  // `/analyses/[id]`'s server-fetched snapshot means this essentially never applies
  // there once the row exists.
  const showSkeleton = currentIndex < 0 && Object.keys(counters).length === 0 && !complete && !failed;

  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-medium text-[var(--color-text-hi)]">Pipeline</h2>
        <span
          className={
            failed
              ? "text-xs font-medium text-[var(--color-severity-critical)]"
              : "text-xs text-[var(--color-text-lo)]"
          }
        >
          {statusLabel}
        </span>
      </div>

      <ol className="mt-4 flex flex-wrap items-center gap-x-2 gap-y-3">
        {STAGES.map((stageDef, index) => {
          const state: StageState =
            failed && index === currentIndex
              ? "failed"
              : complete
                ? "done"
                : index < currentIndex
                  ? "done"
                  : index === currentIndex
                    ? "active"
                    : "pending";
          return (
            <li key={stageDef.key} className="flex items-center gap-2">
              <span className={STAGE_BADGE_CLASS[state]} title={state === "failed" ? "This stage failed" : undefined}>
                {state === "done" ? "✓ " : ""}
                {state === "failed" ? "✕ " : ""}
                {stageDef.label}
                {state === "active" ? ` — ${Math.round(progress * 100)}%` : ""}
              </span>
              {index < STAGES.length - 1 && (
                <span aria-hidden="true" className="text-[var(--color-text-lo)]">
                  →
                </span>
              )}
            </li>
          );
        })}
      </ol>

      {failed && errorMessage && (
        <p role="alert" className="mt-3 text-xs text-[var(--color-severity-critical)]">
          {errorMessage}
        </p>
      )}
      {!failed && event?.message && (
        <p className="mt-3 text-xs text-[var(--color-text-mid)]">{event.message}</p>
      )}

      <dl className="mt-5 grid grid-cols-2 gap-4 sm:grid-cols-4">
        {showSkeleton
          ? Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="flex flex-col gap-1.5">
                <div className="h-3 w-16 animate-pulse rounded bg-[var(--color-surface-2)]" />
                <div className="h-6 w-12 animate-pulse rounded bg-[var(--color-surface-2)]" />
              </div>
            ))
          : orderCounters(counters).map(([name, value]) => (
              <div key={name} className="flex flex-col gap-0.5">
                <dt className="text-xs text-[var(--color-text-lo)]">{counterLabel(name)}</dt>
                <dd className="font-mono text-lg text-[var(--color-text-hi)]">
                  <AnimatedCounter value={value} />
                </dd>
              </div>
            ))}
      </dl>
    </div>
  );
}
