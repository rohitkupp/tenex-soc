"use client";

/**
 * 10. Feedback — docs/v2_migration change 22. The primary bar is always visible: Confirm ·
 * Override · Dismiss, one click each. `POST /api/incidents/{id}/feedback` is the single entry
 * point into the learning loop (change 21).
 *
 * - **Confirm** — agrees, no sub-form, submits immediately.
 * - **Override** — corrected disposition; corrected technique, a dropdown limited to this
 *   verdict's own retrieved candidates plus `NO_KNOWN_MAPPING` (never free text — the whole
 *   point of change 5's "do not select a technique solely because it is the closest retrieved
 *   result" applies just as much to an analyst's correction as to the model's own answer); free
 *   text.
 * - **Dismiss** — reason category (one of five, change 22's own vocabulary); free text; "mark
 *   entity baseline" checkbox.
 *
 * The confirmation toast names the effect (change 22: "The analyst must see that feedback did
 * something") rather than a generic "recorded" — `describeEffect` below is the single place that
 * mapping lives, driven by `FeedbackResponse.reference_set_mechanism` (mechanisms 4/5) and the
 * gated-proposal flags (mechanisms 6/10/11/12), not guessed from the request body.
 */
import { useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import {
  DISMISSAL_REASON_CATEGORIES,
  NO_KNOWN_MAPPING,
  type DismissalReasonCategory,
  type FeedbackRequest,
  type FeedbackResponse,
  type MitreTechniqueRef,
} from "@/lib/api/types";

type Mode = "idle" | "override" | "dismiss";

const DISMISSAL_REASON_LABELS: Record<DismissalReasonCategory, string> = {
  sanctioned_automation: "Sanctioned automation",
  known_business_process: "Known business process",
  expected_for_this_entity: "Expected for this entity",
  insufficient_evidence: "Insufficient evidence",
  other: "Other",
};

function describeEffect(result: FeedbackResponse): string[] {
  const effects: string[] = [];
  if (result.reference_set_mechanism === 4) {
    effects.push("Added to benign reference set — similar activity will score lower.");
  } else if (result.reference_set_mechanism === 5) {
    effects.push(
      "Excluded from the reference set as a confirmed attack — similar activity will no longer score as normal.",
    );
  }
  if (result.baseline_expansion_proposed) {
    effects.push("A baseline-expansion candidate was proposed for review on /learning.");
  }
  if (result.exemplar_proposed) {
    effects.push("This correction was proposed as a curated exemplar for review on /learning.");
  }
  const changed = result.detector_weight_changes.filter((c) => c.changed).length;
  if (changed > 0) {
    effects.push(`${changed} detector weight${changed === 1 ? "" : "s"} updated.`);
  }
  if (result.calibration_refit_triggered) effects.push("Calibration refit triggered.");
  if (result.suppression_candidates_generated.length > 0) {
    effects.push(
      `${result.suppression_candidates_generated.length} suppression candidate${
        result.suppression_candidates_generated.length === 1 ? "" : "s"
      } generated for review on /learning.`,
    );
  }
  if (result.benign_baseline_entries_created > 0) {
    effects.push(
      `${result.benign_baseline_entries_created} entity-window(s) flagged for the benign baseline.`,
    );
  }
  if (result.retrain_attempt) {
    effects.push(`Retrain attempt: ${result.retrain_attempt.promoted ? "promoted" : "not promoted"}.`);
  }
  return effects.length > 0 ? effects : ["Feedback recorded."];
}

export function FeedbackControls({
  incidentId,
  retrievedTechniques = [],
}: {
  incidentId: string;
  /** The verdict's own retrieved candidate set (docs/v2_migration change 5) — the Override
   * technique dropdown is limited to these plus `NO_KNOWN_MAPPING`, never free text. */
  retrievedTechniques?: MitreTechniqueRef[];
}) {
  const [mode, setMode] = useState<Mode>("idle");
  const [note, setNote] = useState("");
  const [correctedDisposition, setCorrectedDisposition] = useState("false_positive");
  const [correctedTechnique, setCorrectedTechnique] = useState(NO_KNOWN_MAPPING);
  const [dismissalReason, setDismissalReason] = useState<DismissalReasonCategory>(
    DISMISSAL_REASON_CATEGORIES[0],
  );
  const [markEntityBaseline, setMarkEntityBaseline] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string[] | null>(null);

  async function submit(body: FeedbackRequest) {
    setBusy(true);
    setError(null);
    try {
      const res = await apiFetch<FeedbackResponse>(`/api/incidents/${incidentId}/feedback`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      setToast(describeEffect(res));
      setMode("idle");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reach the API.");
    } finally {
      setBusy(false);
    }
  }

  if (toast) {
    return (
      <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] p-4 text-sm text-[var(--color-text-hi)]">
        <ul className="flex flex-col gap-1">
          {toast.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
        <button
          type="button"
          onClick={() => setToast(null)}
          className="mt-3 text-xs text-[var(--color-text-lo)] underline underline-offset-2 hover:text-[var(--color-text-mid)]"
        >
          Give more feedback
        </button>
      </div>
    );
  }

  const inputClass =
    "rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)] px-2 py-1.5 text-sm text-[var(--color-text-hi)]";

  return (
    <div className="flex flex-col gap-3">
      {/* Primary bar — always visible, one click each (change 22). */}
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={busy}
          onClick={() => submit({ agrees: true, note: note || undefined })}
          className="rounded-md bg-[var(--color-text-hi)] px-4 py-2 text-sm font-medium text-[var(--color-surface-0)] transition-opacity hover:opacity-90 disabled:opacity-50"
        >
          Confirm
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => setMode(mode === "override" ? "idle" : "override")}
          aria-expanded={mode === "override"}
          className="rounded-md border border-[var(--color-border)] px-4 py-2 text-sm text-[var(--color-text-hi)] transition-colors hover:bg-[var(--color-surface-2)]"
        >
          Override
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => setMode(mode === "dismiss" ? "idle" : "dismiss")}
          aria-expanded={mode === "dismiss"}
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
            Corrected technique
            <select
              value={correctedTechnique}
              onChange={(e) => setCorrectedTechnique(e.target.value)}
              className={inputClass}
            >
              {retrievedTechniques.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.id} — {t.name}
                </option>
              ))}
              <option value={NO_KNOWN_MAPPING}>No known mapping</option>
            </select>
          </label>
          <FeedbackNote note={note} setNote={setNote} />
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              submit({
                agrees: false,
                corrected_disposition: correctedDisposition,
                corrected_technique: correctedTechnique,
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
            <select
              value={dismissalReason}
              onChange={(e) => setDismissalReason(e.target.value as DismissalReasonCategory)}
              className={inputClass}
            >
              {DISMISSAL_REASON_CATEGORIES.map((r) => (
                <option key={r} value={r}>
                  {DISMISSAL_REASON_LABELS[r]}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2 text-xs text-[var(--color-text-mid)]">
            <input
              type="checkbox"
              checked={markEntityBaseline}
              onChange={(e) => setMarkEntityBaseline(e.target.checked)}
            />
            Mark entity baseline
          </label>
          <FeedbackNote note={note} setNote={setNote} />
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              submit({
                agrees: false,
                dismissal_reason: dismissalReason,
                mark_benign_baseline: markEntityBaseline,
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
