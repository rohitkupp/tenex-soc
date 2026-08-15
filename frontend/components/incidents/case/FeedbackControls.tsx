"use client";

/**
 * 10. Feedback — docs/10: "agree / override / dismiss with reason." The single entry point
 * into the learning loop (docs/08 Part 2) — `POST /api/incidents/{id}/feedback`.
 */
import { useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { FeedbackRequest, FeedbackResponse } from "@/lib/api/types";

type Mode = "idle" | "override" | "dismiss";

const DISMISSAL_REASONS = [
  "benign_and_expected",
  "known_false_positive_pattern",
  "sanctioned_activity",
  "duplicate_of_another_incident",
  "insufficient_evidence",
];

export function FeedbackControls({ incidentId }: { incidentId: string }) {
  const [mode, setMode] = useState<Mode>("idle");
  const [note, setNote] = useState("");
  const [correctedDisposition, setCorrectedDisposition] = useState("false_positive");
  const [correctedTechnique, setCorrectedTechnique] = useState("");
  const [dismissalReason, setDismissalReason] = useState(DISMISSAL_REASONS[0]);
  const [markBenignBaseline, setMarkBenignBaseline] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<FeedbackResponse | null>(null);

  async function submit(body: FeedbackRequest) {
    setBusy(true);
    setError(null);
    try {
      const res = await apiFetch<FeedbackResponse>(`/api/incidents/${incidentId}/feedback`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      setResult(res);
      setMode("idle");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reach the API.");
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    const changed = result.detector_weight_changes.filter((c) => c.changed).length;
    return (
      <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] p-4 text-sm text-[var(--color-text-hi)]">
        <p>Feedback recorded.</p>
        <ul className="mt-2 flex flex-col gap-0.5 text-xs text-[var(--color-text-mid)]">
          {changed > 0 && <li>{changed} detector weight{changed === 1 ? "" : "s"} updated.</li>}
          {result.calibration_refit_triggered && <li>Calibration refit triggered.</li>}
          {result.suppression_candidates_generated.length > 0 && (
            <li>
              {result.suppression_candidates_generated.length} suppression candidate
              {result.suppression_candidates_generated.length === 1 ? "" : "s"} generated for review —{" "}
              <a href="/learning" className="underline underline-offset-2">
                see /learning
              </a>
              .
            </li>
          )}
          {result.benign_baseline_entries_created > 0 && (
            <li>{result.benign_baseline_entries_created} entity-window(s) added to the benign baseline.</li>
          )}
          {result.retrain_attempt && (
            <li>Retrain attempt: {result.retrain_attempt.promoted ? "promoted" : "not promoted"}.</li>
          )}
        </ul>
      </div>
    );
  }

  const inputClass =
    "rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)] px-2 py-1.5 text-sm text-[var(--color-text-hi)]";

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={busy}
          onClick={() => submit({ agrees: true, note: note || undefined })}
          className="rounded-md bg-[var(--color-text-hi)] px-4 py-2 text-sm font-medium text-[var(--color-surface-0)] transition-opacity hover:opacity-90 disabled:opacity-50"
        >
          Agree
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => setMode(mode === "override" ? "idle" : "override")}
          className="rounded-md border border-[var(--color-border)] px-4 py-2 text-sm text-[var(--color-text-hi)] transition-colors hover:bg-[var(--color-surface-2)]"
        >
          Override
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => setMode(mode === "dismiss" ? "idle" : "dismiss")}
          className="rounded-md border border-[var(--color-border)] px-4 py-2 text-sm text-[var(--color-text-hi)] transition-colors hover:bg-[var(--color-surface-2)]"
        >
          Dismiss
        </button>
      </div>

      {mode === "override" && (
        <div className="flex flex-col gap-2 rounded-md border border-[var(--color-border)] p-3">
          <label className="flex flex-col gap-1 text-xs text-[var(--color-text-mid)]">
            Corrected disposition
            <select
              value={correctedDisposition}
              onChange={(e) => setCorrectedDisposition(e.target.value)}
              className={inputClass}
            >
              <option value="true_positive">True positive</option>
              <option value="false_positive">False positive</option>
              <option value="benign">Benign</option>
              <option value="needs_review">Needs review</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs text-[var(--color-text-mid)]">
            Corrected technique (optional, e.g. T1071.001)
            <input
              value={correctedTechnique}
              onChange={(e) => setCorrectedTechnique(e.target.value)}
              className={inputClass}
              placeholder="T1071.001"
            />
          </label>
          <FeedbackNote note={note} setNote={setNote} />
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              submit({
                agrees: false,
                corrected_disposition: correctedDisposition,
                corrected_technique: correctedTechnique || undefined,
                note: note || undefined,
              })
            }
            className="w-fit rounded-md bg-[var(--color-text-hi)] px-3 py-1.5 text-xs font-medium text-[var(--color-surface-0)] hover:opacity-90 disabled:opacity-50"
          >
            Submit override
          </button>
        </div>
      )}

      {mode === "dismiss" && (
        <div className="flex flex-col gap-2 rounded-md border border-[var(--color-border)] p-3">
          <label className="flex flex-col gap-1 text-xs text-[var(--color-text-mid)]">
            Reason
            <select value={dismissalReason} onChange={(e) => setDismissalReason(e.target.value)} className={inputClass}>
              {DISMISSAL_REASONS.map((r) => (
                <option key={r} value={r}>
                  {r.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2 text-xs text-[var(--color-text-mid)]">
            <input
              type="checkbox"
              checked={markBenignBaseline}
              onChange={(e) => setMarkBenignBaseline(e.target.checked)}
            />
            Add this incident&apos;s entity-windows to the benign baseline
          </label>
          <FeedbackNote note={note} setNote={setNote} />
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              submit({
                agrees: false,
                dismissal_reason: dismissalReason,
                mark_benign_baseline: markBenignBaseline,
                note: note || undefined,
              })
            }
            className="w-fit rounded-md bg-[var(--color-text-hi)] px-3 py-1.5 text-xs font-medium text-[var(--color-surface-0)] hover:opacity-90 disabled:opacity-50"
          >
            Submit dismissal
          </button>
        </div>
      )}

      {error && (
        <p role="alert" className="text-xs text-[var(--color-severity-high)]">
          {error}
        </p>
      )}
    </div>
  );
}

function FeedbackNote({ note, setNote }: { note: string; setNote: (v: string) => void }) {
  return (
    <label className="flex flex-col gap-1 text-xs text-[var(--color-text-mid)]">
      Note (optional)
      <textarea
        value={note}
        onChange={(e) => setNote(e.target.value)}
        rows={2}
        className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)] px-2 py-1.5 text-sm text-[var(--color-text-hi)]"
      />
    </label>
  );
}
