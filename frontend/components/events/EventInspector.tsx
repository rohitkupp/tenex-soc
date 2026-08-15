"use client";

/**
 * Expands one raw OCSF event inline, in mono — the signature interaction from docs/10:
 * "clicking one expands the raw OCSF event inline beneath the claim, in mono, without
 * navigating away." Fetches `GET /api/events/{event_id}` (docs/09: "Used by citation
 * expansion in the UI") on mount and renders every field as a labelled `key: value` row via
 * `flattenForDisplay` — never `JSON.stringify` (docs/13 M15's "no raw JSON" acceptance bar).
 * Used both by the case file's citation chips and by the `/events` row expansion, so the two
 * "look at one real event" interactions in the product are pixel-identical.
 */
import { useEffect, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { EventOut } from "@/lib/api/types";
import { flattenForDisplay } from "@/lib/flatten";
import { formatDate } from "@/lib/format";

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
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--color-border)] pb-2">
            <span className="font-mono text-xs text-[var(--color-text-hi)]">event #{state.event.id}</span>
            <span className="text-xs text-[var(--color-text-lo)]">
              {formatDate(state.event.ts)} · line {state.event.raw_line_no} · {state.event.source_type}
            </span>
          </div>
          <dl className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-2">
            {flattenForDisplay(state.event).map((entry, i) => (
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
      )}
    </div>
  );
}
