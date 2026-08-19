"use client";

/**
 * Expands one raw OCSF event inline, in mono — the signature interaction from docs/10:
 * "clicking one expands the raw OCSF event inline beneath the claim, in mono, without
 * navigating away." Fetches `GET /api/events/{event_id}` (docs/09: "Used by citation
 * expansion in the UI") on mount and renders every field via the shared `EventDetailView`.
 * Used both by the case file's `LOG-n` citation chips (via `LogLineInspector`, its sibling
 * below) and by the `/events` row expansion, so every "look at one real event" interaction in
 * the product is pixel-identical.
 */
import { useEffect, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { AnalysisEvidenceResponse, EventOut } from "@/lib/api/types";
import { EvidenceCard } from "@/components/evidence/EvidenceCard";
import { flattenForDisplay } from "@/lib/flatten";
import { formatDate, formatScore } from "@/lib/format";
import { ExplanationRenderer } from "@/components/explanations/ExplanationRenderer";

type LoadState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; event: EventOut };

/**
 * The "ready" rendering body, shared by `EventInspector` (fetch by `events.id`) and
 * `LogLineInspector` (fetch by `(analysis_id, raw_line_no)`, docs/v2_migration change 16) — the
 * two differ only in *how* they resolve an `EventOut`, never in how one is displayed.
 *
 * M15: `EventOut` carries `signals[]` — the brief's "provide a brief explanation of why the
 * entry was flagged as anomalous". When present, a "Why flagged" section renders each signal's
 * `explanation` through the shared `ExplanationRenderer`, with its confidence and MITRE
 * technique, ahead of the raw-field dump below it — never `JSON.stringify` (docs/13 M15's "no
 * raw JSON" acceptance bar).
 */
export function EventDetailView({ event }: { event: EventOut }) {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--color-border)] pb-2">
        <span className="font-mono text-xs text-[var(--color-text-hi)]">event #{event.id}</span>
        <span className="text-xs text-[var(--color-text-lo)]">
          {formatDate(event.ts)} · line {event.raw_line_no} · {event.source_type}
        </span>
      </div>

      {event.signals.length > 0 && (
        <div className="flex flex-col gap-2">
          <h3 className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-lo)]">
            Why flagged ({event.signals.length})
          </h3>
          <div className="flex flex-col gap-2">
            {event.signals.map((signal) => (
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
        {event.signals.length > 0 && (
          <h3 className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-lo)]">Raw event</h3>
        )}
        <dl className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-2">
          {/* `signals` is rendered above through ExplanationRenderer, not flattened here —
              dumping it again as generic key/value rows would just be a noisier, less
              legible duplicate of the "Why flagged" section. */}
          {flattenForDisplay(event)
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
  );
}

/** Shared loading/error chrome around `EventDetailView`, parameterised by the fetch itself so
 * `EventInspector`/`LogLineInspector` only differ in the URL they hit. */
export function EventFetchFrame({
  path,
  notFoundMessage,
  analysisId,
}: {
  path: string;
  notFoundMessage: string;
  /** When set, the frame also loads the evidence payloads citing this event's raw line —
   * the Evidence tab's content, folded into the row expansion it always belonged to. */
  analysisId?: string;
}) {
  const [state, setState] = useState<LoadState>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    setState({ status: "loading" });
    apiFetch<EventOut>(path)
      .then((event) => {
        if (!cancelled) setState({ status: "ready", event });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const message =
          err instanceof ApiError
            ? err.status === 404
              ? notFoundMessage
              : err.message
            : "Could not reach the API.";
        setState({ status: "error", message });
      });
    return () => {
      cancelled = true;
    };
  }, [path, notFoundMessage]);

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
        <>
          <EventDetailView event={state.event} />
          {analysisId && (
            <EventEvidence analysisId={analysisId} rawLineNo={state.event.raw_line_no} />
          )}
        </>
      )}
    </div>
  );
}

type EvidenceState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; items: AnalysisEvidenceResponse["items"] };

/**
 * The evidence payloads citing one event's raw log line, rendered beneath its detail view.
 *
 * This replaces the standalone Evidence tab: the tab listed every payload for the analysis and
 * left the analyst to join payload → line → event by eye, when the question is always asked the
 * other way around — "I am looking at this event; what did the extractors make of it?". The
 * join is `line_no` (events carry `raw_line_no`, payloads carry `contributing_line_numbers`) —
 * the same join the case file's LOG-n citation chips make in the other direction, done
 * server-side by the `line_no` filter on `GET /api/analyses/{id}/evidence`.
 */
function EventEvidence({ analysisId, rawLineNo }: { analysisId: string; rawLineNo: number }) {
  const [state, setState] = useState<EvidenceState>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    setState({ status: "loading" });
    apiFetch<AnalysisEvidenceResponse>(`/api/analyses/${analysisId}/evidence?line_no=${rawLineNo}`)
      .then((res) => {
        if (!cancelled) setState({ status: "ready", items: res.items });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const message = err instanceof ApiError ? err.message : "Could not reach the API.";
        setState({ status: "error", message });
      });
    return () => {
      cancelled = true;
    };
  }, [analysisId, rawLineNo]);

  if (state.status === "loading") {
    return <div className="mt-3 h-3 w-40 animate-pulse rounded bg-[var(--color-surface-2)]" />;
  }
  if (state.status === "error") {
    return (
      <p role="alert" className="mt-3 text-xs text-[var(--color-severity-high)]">
        Evidence failed to load: {state.message}
      </p>
    );
  }
  if (state.items.length === 0) {
    // A real, common answer: most benign events contribute to no extractor's evidence.
    return (
      <p className="mt-3 text-xs text-[var(--color-text-lo)]">
        No evidence payload cites this event&apos;s log line.
      </p>
    );
  }
  return (
    <div className="mt-3 flex flex-col gap-2">
      <h3 className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-lo)]">
        Evidence citing line {rawLineNo} ({state.items.length})
      </h3>
      {state.items.map((item) => (
        <EvidenceCard key={item.evidence_id} evidence={item} analysisId={analysisId} />
      ))}
    </div>
  );
}

export function EventInspector({
  eventId,
  analysisId,
}: {
  eventId: number;
  analysisId?: string;
}) {
  return (
    <EventFetchFrame
      path={`/api/events/${eventId}`}
      notFoundMessage="Event not found."
      analysisId={analysisId}
    />
  );
}
