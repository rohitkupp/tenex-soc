"use client";

/**
 * Change 22: "Per-claim thumbs on narrative claims, hover-revealed." Independent of the primary
 * Confirm/Override/Dismiss bar (`FeedbackControls`) — an analyst can flag one claim in an
 * otherwise-confirmed incident. Posts to `POST /api/incidents/{id}/claims/{step}/feedback`
 * (`app.learning.feedback.record_claim_feedback`), which feeds mechanism 14 (verifier rule
 * induction, change 21) once enough similar thumbs-down notes cluster.
 *
 * Hover-revealed: invisible until the parent `<li>` (or this element itself, on touch/keyboard
 * devices) is hovered or focused — `group-hover:opacity-100`/`focus-within:opacity-100` on a
 * `opacity-0` base, so the narrative reads clean by default and the control is still keyboard-
 * reachable without a mouse.
 */
import { useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { ClaimFeedbackResponse } from "@/lib/api/types";

export function ClaimThumbs({ incidentId, step }: { incidentId: string; step: number }) {
  const [sent, setSent] = useState<"helpful" | "unhelpful" | null>(null);
  const [note, setNote] = useState("");
  const [showNote, setShowNote] = useState(false);
  const [proposed, setProposed] = useState(false);
  const [busy, setBusy] = useState(false);

  async function send(helpful: boolean) {
    setBusy(true);
    try {
      const res = await apiFetch<ClaimFeedbackResponse>(
        `/api/incidents/${incidentId}/claims/${step}/feedback`,
        { method: "POST", body: JSON.stringify({ helpful, note: note || undefined }) },
      );
      setSent(helpful ? "helpful" : "unhelpful");
      setProposed(res.verifier_rule_proposed);
      setShowNote(false);
    } catch (err) {
      if (!(err instanceof ApiError)) throw err;
    } finally {
      setBusy(false);
    }
  }

  if (sent) {
    return (
      <span className="text-[11px] text-[var(--color-text-lo)]">
        {sent === "helpful" ? "Marked helpful." : "Marked unhelpful."}
        {proposed && " A verifier-rule proposal was staged for review on /learning."}
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5 opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100 focus-within:opacity-100">
      <button
        type="button"
        disabled={busy}
        onClick={() => send(true)}
        aria-label="This claim is accurate"
        title="This claim is accurate"
        className="rounded px-1 py-0.5 text-xs text-[var(--color-text-lo)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text-hi)]"
      >
        👍
      </button>
      <button
        type="button"
        disabled={busy}
        onClick={() => (showNote ? send(false) : setShowNote(true))}
        aria-label="This claim has a factual error"
        title="This claim has a factual error"
        className="rounded px-1 py-0.5 text-xs text-[var(--color-text-lo)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text-hi)]"
      >
        👎
      </button>
      {showNote && (
        <span className="inline-flex items-center gap-1">
          <input
            autoFocus
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="What's wrong? (optional)"
            className="w-40 rounded border border-[var(--color-border)] bg-[var(--color-surface-1)] px-1.5 py-0.5 text-[11px] text-[var(--color-text-hi)]"
          />
          <button
            type="button"
            disabled={busy}
            onClick={() => send(false)}
            className="rounded bg-[var(--color-text-hi)] px-1.5 py-0.5 text-[11px] font-medium text-[var(--color-surface-0)] hover:opacity-90"
          >
            Send
          </button>
        </span>
      )}
    </span>
  );
}
