"use client";

/**
 * Expands one raw OCSF event inline, in mono — the signature interaction from docs/10:
 * "clicking one expands the raw OCSF event inline beneath the claim, in mono, without
 * navigating away." Fetches `GET /api/events/{event_id}` (docs/09: "Used by citation
 * expansion in the UI") on mount and renders every field as a labelled `key: value` row via
 * `flattenForDisplay` — never `JSON.stringify` (docs/13 M15's "no raw JSON" acceptance bar).
 * Used both by the case file's citation chips and by the `/events` row expansion, so the two
 * "look at one real event" interactions in the product are pixel-identical.
 *
 * M15: `EventOut` now also carries `signals[]` — the brief's "provide a brief explanation of
 * why the entry was flagged as anomalous". When present, a "Why flagged" section renders each
 * signal's `explanation` through the shared `ExplanationRenderer` (same detector-specific
 * views the case file uses), with its confidence and MITRE technique, ahead of the raw-field
 * dump below it.
 */
import { useEffect, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { EventOut } from "@/lib/api/types";
import { flattenForDisplay } from "@/lib/flatten";
import { formatDate, formatScore } from "@/lib/format";
import { ExplanationRenderer } from "@/components/explanations/ExplanationRenderer";

type LoadState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; event: EventOut };

export function EventInspector({ eventId }: { eventId: number }) {
  const [state, setState] = useState<LoadState>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    setState({ status: "loading" });
    apiFetch<EventOut>(`/api/events/${eventId}`)
      .then((event) => {
        if (!cancelled) setState({ status: "ready", event });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const message =
          err instanceof ApiError
            ? err.status === 404
              ? "Event not found."
              : err.message
            : "Could not reach the API.";
        setState({ status: "error", message });
      });
    return () => {
      cancelled = true;
    };
  }, [eventId]);

  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-0)] p-3">
      {state.status === "loading" && (
        <div className="flex flex-col gap-1.5">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-3 w-full animate-pulse rounded bg-[var(--color-surface-2)]" />
          ))}
        </div>
      )}

      {state.status === "error" && (
        <p role="alert" className="text-xs text-[var(--color-severity-high)]">
          {state.message}
        </p>
      )}

      {state.status === "ready" && (
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--color-border)] pb-2">
            <span className="font-mono text-xs text-[var(--color-text-hi)]">event #{state.event.id}</span>
            <span className="text-xs text-[var(--color-text-lo)]">
              {formatDate(state.event.ts)} · line {state.event.raw_line_no} · {state.event.source_type}
            </span>
          </div>

          {state.event.signals.length > 0 && (
            <div className="flex flex-col gap-2">
              <h3 className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-lo)]">
                Why flagged ({state.event.signals.length})
              </h3>
              <div className="flex flex-col gap-2">
                {state.event.signals.map((signal) => (
                  <details
                    key={signal.id}
                    className="group rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)]"
                  >
                    <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-3 p-3 marker:content-none">
                      <span className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs text-[var(--color-text-hi)]">{signal.detector_key}</span>
                        <span className="rounded border border-[var(--color-border)] px-1.5 py-0.5 text-xs text-[var(--color-text-lo)]">
                          {signal.detector_layer}
                        </span>
                        {signal.mitre_technique && (
                          <span className="rounded border border-[var(--color-border)] px-1.5 py-0.5 font-mono text-xs text-[var(--color-text-mid)]">
                            {signal.mitre_technique}
                          </span>
                        )}
                      </span>
                      <span className="flex items-center gap-3 text-xs text-[var(--color-text-mid)]">
                        <span>confidence {formatScore(signal.confidence)}</span>
                        <span
                          aria-hidden="true"
                          className="text-[var(--color-text-lo)] transition-transform group-open:rotate-90"
                        >
                          ›
                        </span>
                      </span>
                    </summary>
                    <div className="border-t border-[var(--color-border)] p-3">
                      <ExplanationRenderer signal={signal} />
                    </div>
                  </details>
                ))}
              </div>
            </div>
          )}

          <div className="flex flex-col gap-2">
            {state.event.signals.length > 0 && (
              <h3 className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-lo)]">Raw event</h3>
            )}
            <dl className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-2">
              {/* `signals` is rendered above through ExplanationRenderer, not flattened here —
                  dumping it again as generic key/value rows would just be a noisier, less
                  legible duplicate of the "Why flagged" section. */}
              {flattenForDisplay(state.event)
                .filter((entry) => entry.key !== "signals" && !entry.key.startsWith("signals["))
                .map((entry, i) => (
                <div key={`${entry.key}-${i}`} className="flex items-baseline justify-between gap-3 text-xs">
                  <dt className="shrink-0 text-[var(--color-text-lo)]" title={entry.key}>
                    {entry.key}
                  </dt>
                  <dd className="truncate text-right font-mono text-[var(--color-text-hi)]" title={entry.value}>
                    {entry.value}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      )}
    </div>
  );
}
