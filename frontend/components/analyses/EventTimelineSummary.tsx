"use client";

/**
 * The Events tab's plain-language account of the traffic, above the event table.
 *
 * The windows are cut deterministically in SQL (`app.api.events._window_aggregates`) — equal
 * buckets across the file's span, each carrying its own event/user/domain counts, allowed-blocked
 * split, bytes, top domains and a few citable log ids. One LLM call writes prose per window and
 * an overview; it never sees a raw log line and never counts anything itself.
 *
 * A button rather than an automatic fetch, and a POST rather than a GET, because it spends
 * tokens. A GET that quietly costs money on every page load is the exact mistake `/overview` was
 * making before its findings were persisted — it took 14s and billed per visit. Once generated
 * the result is stored on `analyses.event_timeline_summary`, so it renders on later visits for
 * free; this component shows the stored copy when one exists.
 */
import { useCallback, useEffect, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import { formatUsd } from "@/lib/format";

interface WindowSummary {
  window_index: number;
  summary: string;
  cited_log_ids: string[];
}

interface SummaryResponse {
  overview: string;
  windows: WindowSummary[];
  citation_valid: boolean;
  invalid_citation_count: number;
  model: string;
  cost_usd: number | string;
  latency_ms: number;
}

export function EventTimelineSummary({
  analysisId,
  stored,
}: {
  analysisId: string;
  stored: SummaryResponse | null;
}) {
  const [result, setResult] = useState<SummaryResponse | null>(stored);

  // `useState(stored)` captures the prop once, at mount. The pipeline now writes the summary
  // during triage, so the value arrives on a *later* server render — after `router.refresh()`
  // or a tab switch — and the initial `null` stuck, leaving the "Summarise" button up until a
  // hard reload remounted the component. Sync the prop in whenever it becomes available, and
  // never clobber a result this component generated itself.
  useEffect(() => {
    if (stored) setResult((current) => current ?? stored);
  }, [stored]);
  const [state, setState] = useState<"idle" | "loading" | "error">("idle");
  const [message, setMessage] = useState<string | null>(null);

  const generate = useCallback(async () => {
    setState("loading");
    setMessage(null);
    try {
      setResult(
        await apiFetch<SummaryResponse>(`/api/analyses/${analysisId}/event-timeline/summary`, {
          method: "POST",
        }),
      );
      setState("idle");
    } catch (err: unknown) {
      setState("error");
      setMessage(
        err instanceof ApiError
          ? err.status === 503
            ? "The summariser is not configured (no Anthropic API key set)."
            : err.message
          : "Could not reach the API.",
      );
    }
  }, [analysisId]);

  if (!result) {
    return (
      <div className="flex flex-col items-start gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-5">
        <p className="text-sm text-[var(--color-text-mid)]">
          Summarise this file&apos;s traffic window by window — one LLM call over counts computed
          in SQL.
        </p>
        <button
          type="button"
          onClick={generate}
          disabled={state === "loading"}
          className="rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-hi)] transition-colors hover:bg-[var(--color-surface-2)] disabled:opacity-50"
        >
          {state === "loading" ? "Summarising…" : "Summarise timeline"}
        </button>
        {state === "error" && message && (
          <p role="alert" className="text-xs text-[var(--color-severity-high)]">
            {message}
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-5">
      <p className="max-w-[68ch] font-serif text-[17px] leading-[1.65] text-[var(--color-text-hi)]">
        {result.overview}
      </p>

      <ol className="flex flex-col gap-2">
        {result.windows.map((w) => (
          <li key={w.window_index} className="flex gap-3 text-sm">
            <span className="mt-0.5 shrink-0 font-mono text-xs text-[var(--color-text-lo)]">
              {String(w.window_index + 1).padStart(2, "0")}
            </span>
            <span className="text-[var(--color-text-hi)]">
              {w.summary}
              {w.cited_log_ids.length > 0 && (
                <span className="ml-2 font-mono text-xs text-[var(--color-text-lo)]">
                  {w.cited_log_ids.join(" ")}
                </span>
              )}
            </span>
          </li>
        ))}
      </ol>

      <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--color-text-lo)]">
        {!result.citation_valid && (
          <span className="text-[var(--color-severity-high)]">
            {result.invalid_citation_count} number
            {result.invalid_citation_count === 1 ? "" : "s"} did not match the window described
          </span>
        )}
        <span>{result.model}</span>
        <span>{formatUsd(result.cost_usd)}</span>
        <span>{result.latency_ms}ms</span>
      </div>
    </div>
  );
}
