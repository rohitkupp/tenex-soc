"use client";

/**
 * change 10 Level 1 ("what happened"): the executive summary, over change 9's deterministic
 * overview stats — "an analyst should understand the file in ten seconds." Path A (change 14),
 * `POST /api/analyses/{id}/narrate`, one LLM call.
 *
 * Deliberately a click, not an automatic fetch on page load: `NarrationResult` is not persisted
 * server-side (`backend/app/schemas/overview.py`'s own module docstring — no schema for it
 * exists yet, out of this milestone's ownership to add), so every call is a real, unrepeated
 * spend (CLAUDE.md: "cost is real per upload"). An automatic call here would re-spend on every
 * navigation back to this page; a button, mirroring `RetryButton`'s pattern, spends exactly
 * once per analyst click.
 */
import { useCallback, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { AnalysisNarrateResponse } from "@/lib/api/types";
import { formatUsd } from "@/lib/format";

export function ExecutiveSummary({ analysisId }: { analysisId: string }) {
  const [state, setState] = useState<"idle" | "loading" | "error">("idle");
  const [result, setResult] = useState<AnalysisNarrateResponse | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const generate = useCallback(async () => {
    setState("loading");
    setMessage(null);
    try {
      const res = await apiFetch<AnalysisNarrateResponse>(`/api/analyses/${analysisId}/narrate`, {
        method: "POST",
      });
      setResult(res);
      setState("idle");
    } catch (err: unknown) {
      setState("error");
      setMessage(
        err instanceof ApiError
          ? err.status === 503
            ? "The Narrator is not configured (no Anthropic API key set)."
            : err.message
          : "Could not reach the API.",
      );
    }
  }, [analysisId]);

  if (result) {
    return (
      <div className="flex flex-col gap-2">
        <p className="max-w-[68ch] font-serif text-[17px] leading-[1.65] text-[var(--color-text-hi)]">
          {result.executive_summary}
        </p>
        <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--color-text-lo)]">
          {!result.citation_valid && (
            <span className="text-[var(--color-severity-high)]">
              {result.invalid_citations.length} claim{result.invalid_citations.length === 1 ? "" : "s"} failed
              citation verification.
            </span>
          )}
          <span>{result.model}</span>
          <span>{formatUsd(result.cost_usd)}</span>
          <span>{result.latency_ms}ms</span>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-start gap-2">
      <button
        type="button"
        onClick={generate}
        disabled={state === "loading"}
        className="rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-hi)] transition-colors hover:bg-[var(--color-surface-2)] disabled:opacity-50"
      >
        {state === "loading" ? "Generating…" : "Generate executive summary"}
      </button>
      {state === "error" && message && (
        <p role="alert" className="text-xs text-[var(--color-severity-high)]">
          {message}
        </p>
      )}
    </div>
  );
}
