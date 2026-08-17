"use client";

/**
 * Free-text analyst feedback on one incident. `POST /api/incidents/{id}/feedback` stores it as a
 * text file in object storage alongside the incident's own raw upload, and nothing reads it back.
 *
 * This replaces the structured feedback controls that used to sit here (thumbs per claim,
 * disposition agree/disagree, suppression proposals) and fed the 15-mechanism learning loop. That
 * loop is deleted. The tradeoff is deliberate: structured feedback is only worth collecting if
 * something measurably improves from it, and none of those mechanisms was ever measured against
 * the labeled eval set. An analyst's own sentences are a more honest record than a thumbs-down
 * that silently retuned a detector weight nobody validated.
 */
import { useCallback, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";

const MAX_CHARS = 8000;

interface FeedbackResponse {
  incident_id: string;
  storage_key: string;
  submitted_at: string;
}

export function IncidentFeedback({ incidentId }: { incidentId: string }) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [state, setState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [message, setMessage] = useState<string | null>(null);

  const submit = useCallback(async () => {
    const body = text.trim();
    if (!body) return;
    setState("saving");
    setMessage(null);
    try {
      const res = await apiFetch<FeedbackResponse>(`/api/incidents/${incidentId}/feedback`, {
        method: "POST",
        body: JSON.stringify({ text: body }),
      });
      setState("saved");
      setMessage(res.storage_key);
      setText("");
    } catch (err: unknown) {
      setState("error");
      setMessage(err instanceof ApiError ? err.message : "Could not reach the API.");
    }
  }, [incidentId, text]);

  if (!open) {
    return (
      <div className="flex flex-col items-start gap-2">
        <button
          type="button"
          onClick={() => {
            setOpen(true);
            setState("idle");
            setMessage(null);
          }}
          className="rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-hi)] transition-colors hover:bg-[var(--color-surface-2)]"
        >
          Add feedback
        </button>
        {state === "saved" && (
          <p className="text-xs text-[var(--color-text-lo)]">
            Saved to <span className="font-mono">{message}</span>
          </p>
        )}
      </div>
    );
  }

  const remaining = MAX_CHARS - text.length;

  return (
    <div className="flex flex-col gap-2">
      <label htmlFor="incident-feedback" className="text-xs text-[var(--color-text-mid)]">
        What did the analysis get right or wrong? Plain English — it is stored as written.
      </label>
      <textarea
        id="incident-feedback"
        value={text}
        onChange={(e) => setText(e.target.value.slice(0, MAX_CHARS))}
        rows={5}
        disabled={state === "saving"}
        className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)] px-3 py-2 text-sm text-[var(--color-text-hi)] disabled:opacity-50"
      />
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={submit}
          disabled={state === "saving" || text.trim().length === 0}
          className="rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-hi)] transition-colors hover:bg-[var(--color-surface-2)] disabled:opacity-50"
        >
          {state === "saving" ? "Saving…" : "Submit feedback"}
        </button>
        <button
          type="button"
          onClick={() => setOpen(false)}
          disabled={state === "saving"}
          className="text-xs text-[var(--color-text-mid)] transition-colors hover:text-[var(--color-text-hi)] disabled:opacity-50"
        >
          Cancel
        </button>
        <span className="text-xs text-[var(--color-text-lo)]">{remaining} characters left</span>
      </div>
      {state === "error" && message && (
        <p role="alert" className="text-xs text-[var(--color-severity-high)]">
          {message}
        </p>
      )}
      {state === "saved" && message && (
        <p className="text-xs text-[var(--color-text-lo)]">
          Saved to <span className="font-mono">{message}</span>
        </p>
      )}
    </div>
  );
}
