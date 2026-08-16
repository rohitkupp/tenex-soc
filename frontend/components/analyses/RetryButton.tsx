"use client";

import { useCallback, useState } from "react";
import { useRouter } from "next/navigation";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { AnalysisRetryResponse } from "@/lib/api/types";

/**
 * `POST /api/analyses/{id}/retry` — docs/v2_migration change 27's replacement for the
 * deleted `/ops` console's retry action. Rendered next to the failed stage's error
 * message on `/analyses/[id]` (see that page) rather than in an operator-only surface,
 * since the analyst looking at the failure is now the only person who can see it at
 * all. `router.refresh()` re-fetches the server-rendered snapshot (`analysis.status`
 * flips back to `running`) so the funnel resumes without a full page reload.
 */
export function RetryButton({ analysisId }: { analysisId: string }) {
  const router = useRouter();
  const [state, setState] = useState<"idle" | "retrying" | "error">("idle");
  const [message, setMessage] = useState<string | null>(null);

  const retry = useCallback(async () => {
    setState("retrying");
    setMessage(null);
    try {
      await apiFetch<AnalysisRetryResponse>(`/api/analyses/${analysisId}/retry`, {
        method: "POST",
      });
      setState("idle");
      router.refresh();
    } catch (err: unknown) {
      setState("error");
      setMessage(err instanceof ApiError ? err.message : "Retry failed — try again.");
    }
  }, [analysisId, router]);

  return (
    <div className="flex flex-col items-start gap-1">
      <button
        type="button"
        onClick={retry}
        disabled={state === "retrying"}
        className="rounded-md border border-[var(--color-severity-critical)] px-3 py-1.5 text-xs font-medium text-[var(--color-severity-critical)] transition-opacity hover:opacity-80 disabled:opacity-50"
      >
        {state === "retrying" ? "Retrying…" : "Retry from failed stage"}
      </button>
      {state === "error" && message && (
        <p role="alert" className="text-xs text-[var(--color-severity-critical)]">
          {message}
        </p>
      )}
    </div>
  );
}
