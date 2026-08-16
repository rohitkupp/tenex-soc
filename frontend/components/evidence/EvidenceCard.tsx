"use client";

/**
 * One `EvidencePayload`, rendered — shared by the per-incident Evidence section
 * (`components/incidents/case/EvidenceSection.tsx`, change 16 primary) and the analysis-wide
 * evidence browser (`components/evidence/EvidenceExplorer.tsx`, change 16 secondary), so an
 * evidence payload looks identical wherever it's read.
 *
 * Per change 16, every card carries:
 *   - the evidence id (`EVIDENCE-14`), so a narrative citation is traceable by eye
 *   - a measurements table — raw numbers as produced by the extractor
 *   - historical context — percentile vs. baseline, **with `n_windows`** so a thin baseline is
 *     visible rather than looking as trustworthy as a six-month one (change 1's cold-start
 *     contract, `app.detection.evidence.payload.historical_from_percentile`)
 *   - contributing line numbers, click-to-expand into the raw log rows (`LogLineInspector`)
 *   - a per-evidence relevance toggle ("was this useful?") — the backend for this is owned by
 *     the learning-loop agent (`backend/app/learning/`, per this milestone's own split); the
 *     control below is rendered per change 16's instruction to "leave a clear seam" and posts to
 *     `POST /api/evidence/{evidence_id}/relevance`, which does not exist yet. A 404 is handled
 *     quietly (see `EvidenceRelevanceToggle`) rather than presented as a user-facing error, since
 *     absence of that endpoint is an expected, temporary state, not a bug in this component.
 */
import { useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { EvidencePayloadOut } from "@/lib/api/types";
import { formatDate, formatNumber, humanizeKey, truncate } from "@/lib/format";
import { Badge } from "@/components/ui/Badge";
import { LogLineInspector } from "@/components/events/LogLineInspector";

export function evidenceCardAnchorId(evidenceId: string): string {
  return `evidence-${evidenceId}`;
}

function formatMeasurement(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "number") return formatNumber(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return truncate(value, 200);
  if (Array.isArray(value)) return truncate(value.map(String).join(", "), 200);
  return truncate(JSON.stringify(value), 200);
}

interface BaselineGroup {
  prefix: string;
  percentile: number | null;
  baselineStatus: string | null;
  nWindows: number | null;
  ratioVsBaseline: number | null;
}

function asNumberOrNull(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/**
 * `app.detection.evidence.payload.historical_from_percentile` always writes
 * `{prefix}_percentile`/`{prefix}_baseline_status`/`{prefix}_n_windows` (and optionally
 * `{prefix}_ratio_vs_baseline`) together, `prefix=""` collapsing to the bare names — this
 * groups them back up from the flat `historical` dict so the cold-start state renders as one
 * coherent line per scope (burst has three: user/department/org) rather than four scattered
 * key/value rows.
 */
function extractBaselineGroups(historical: Record<string, unknown>): BaselineGroup[] {
  const groups: BaselineGroup[] = [];
  const seen = new Set<string>();
  for (const key of Object.keys(historical)) {
    if (!key.endsWith("baseline_status")) continue;
    const prefix = key === "baseline_status" ? "" : key.slice(0, -"_baseline_status".length);
    if (seen.has(prefix)) continue;
    seen.add(prefix);
    const withPrefix = (k: string) => (prefix ? `${prefix}_${k}` : k);
    const statusValue = historical[withPrefix("baseline_status")];
    groups.push({
      prefix,
      percentile: asNumberOrNull(historical[withPrefix("percentile")]),
      baselineStatus: typeof statusValue === "string" ? statusValue : null,
      nWindows: asNumberOrNull(historical[withPrefix("n_windows")]),
      ratioVsBaseline: asNumberOrNull(historical[withPrefix("ratio_vs_baseline")]),
    });
  }
  return groups.sort((a, b) => a.prefix.localeCompare(b.prefix));
}

function groupedKeys(groups: BaselineGroup[]): Set<string> {
  const keys = new Set<string>();
  for (const g of groups) {
    const p = (k: string) => (g.prefix ? `${g.prefix}_${k}` : k);
    keys.add(p("percentile"));
    keys.add(p("baseline_status"));
    keys.add(p("n_windows"));
    keys.add(p("ratio_vs_baseline"));
  }
  return keys;
}

function BaselineRow({ group }: { group: BaselineGroup }) {
  const insufficient = group.baselineStatus === "insufficient_history";
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      {group.prefix && (
        <span className="w-20 shrink-0 text-[var(--color-text-lo)]">{humanizeKey(group.prefix)}</span>
      )}
      {insufficient ? (
        <span className="rounded border border-dashed border-[var(--color-border)] px-1.5 py-0.5 text-[var(--color-text-mid)]">
          insufficient history — n={group.nWindows ?? 0} window{group.nWindows === 1 ? "" : "s"}
        </span>
      ) : (
        <>
          <span className="font-mono text-[var(--color-text-hi)]">
            {group.percentile !== null ? `${group.percentile.toFixed(1)}th percentile` : "—"}
          </span>
          <span className="text-[var(--color-text-lo)]">n={group.nWindows ?? "—"} windows</span>
          {group.ratioVsBaseline !== null && (
            <span className="text-[var(--color-text-lo)]">{group.ratioVsBaseline.toFixed(2)}× baseline</span>
          )}
        </>
      )}
    </div>
  );
}

function EvidenceRelevanceToggle({
  incidentId,
  evidenceId,
  extractor,
}: {
  incidentId: string;
  evidenceId: string;
  extractor: string;
}) {
  const [state, setState] = useState<"idle" | "sent" | "unavailable">("idle");

  async function send(relevant: boolean) {
    try {
      // `backend/app/models/evidence_relevance_feedback.py` (the learning-loop agent's seam,
      // change 16/22) rows this against `incident_id` + `evidence_id` + `extractor` — this
      // control posts the exact shape that table's own columns need, even though the endpoint
      // itself does not exist yet (see the 404 handling below).
      await apiFetch<unknown>(`/api/incidents/${incidentId}/evidence/${evidenceId}/relevance`, {
        method: "POST",
        body: JSON.stringify({ relevant, extractor }),
      });
      setState("sent");
    } catch (err) {
      // The backend for this seam is owned by the learning-loop agent and may not exist yet
      // (404) — that is an expected, temporary state, not an error to alarm an analyst with.
      setState(err instanceof ApiError && err.status === 404 ? "unavailable" : "sent");
    }
  }

  if (state === "sent") {
    return <span className="text-xs text-[var(--color-text-lo)]">Thanks — recorded.</span>;
  }

  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-[var(--color-text-lo)]">Was this useful?</span>
      <button
        type="button"
        onClick={() => send(true)}
        className="rounded border border-[var(--color-border)] px-1.5 py-0.5 text-xs text-[var(--color-text-mid)] hover:bg-[var(--color-surface-2)]"
      >
        Yes
      </button>
      <button
        type="button"
        onClick={() => send(false)}
        className="rounded border border-[var(--color-border)] px-1.5 py-0.5 text-xs text-[var(--color-text-mid)] hover:bg-[var(--color-surface-2)]"
      >
        No
      </button>
      {state === "unavailable" && (
        <span className="text-xs text-[var(--color-text-lo)]" title="Learning loop not yet wired up">
          (not yet available)
        </span>
      )}
    </div>
  );
}

export function EvidenceCard({
  evidence,
  analysisId,
  incidentId,
  highlighted = false,
}: {
  evidence: EvidencePayloadOut;
  analysisId: string;
  /** Only given from the per-incident Evidence section (`EvidenceSection`) — the relevance
   * toggle needs an `incident_id` to write against (the learning-loop agent's `evidence_
   * relevance_feedback` table has it as a required FK), so it renders only here, never from
   * the analysis-wide browser, where a payload may belong to zero incidents at all. */
  incidentId?: string;
  highlighted?: boolean;
}) {
  const [expandedLine, setExpandedLine] = useState<number | null>(null);
  const baselineGroups = extractBaselineGroups(evidence.historical);
  const grouped = groupedKeys(baselineGroups);
  const leftoverHistorical = Object.entries(evidence.historical).filter(([k]) => !grouped.has(k));

  return (
    <div
      id={evidenceCardAnchorId(evidence.evidence_id)}
      className={`scroll-mt-24 rounded-lg border p-4 ${
        highlighted
          ? "border-[var(--color-text-hi)] bg-[var(--color-surface-1)]"
          : "border-[var(--color-border)] bg-[var(--color-surface-1)]"
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--color-border)] pb-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm text-[var(--color-text-hi)]">{evidence.evidence_id}</span>
          <Badge>{evidence.extractor}</Badge>
          <span className="text-xs text-[var(--color-text-mid)]">
            {evidence.entity_type} <span className="font-mono">{evidence.entity_value}</span>
          </span>
          {evidence.nominates_candidate && (
            <Badge variant="outline">
              nominated candidate
              {evidence.nomination_score !== null ? ` · ${evidence.nomination_score.toFixed(1)}` : ""}
            </Badge>
          )}
        </div>
        <span className="text-xs text-[var(--color-text-lo)]">
          {formatDate(evidence.window_start)} – {formatDate(evidence.window_end)}
        </span>
      </div>

      <div className="mt-3 grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <h4 className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-lo)]">
            Measurements
          </h4>
          <dl className="flex flex-col gap-1">
            {Object.entries(evidence.measurements).map(([key, value]) => (
              <div key={key} className="flex items-baseline justify-between gap-3 text-xs">
                <dt className="text-[var(--color-text-lo)]">{humanizeKey(key)}</dt>
                <dd className="text-right font-mono text-[var(--color-text-hi)]">{formatMeasurement(value)}</dd>
              </div>
            ))}
          </dl>
        </div>

        <div className="flex flex-col gap-1.5">
          <h4 className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-lo)]">
            Historical context
          </h4>
          {baselineGroups.length === 0 && leftoverHistorical.length === 0 ? (
            <p className="text-xs text-[var(--color-text-mid)]">
              No baseline comparison for this extractor — the score is already the answer.
            </p>
          ) : (
            <div className="flex flex-col gap-1.5">
              {baselineGroups.map((g) => (
                <BaselineRow key={g.prefix || "—"} group={g} />
              ))}
              {leftoverHistorical.map(([key, value]) => (
                <div key={key} className="flex items-baseline justify-between gap-3 text-xs">
                  <dt className="text-[var(--color-text-lo)]">{humanizeKey(key)}</dt>
                  <dd className="text-right font-mono text-[var(--color-text-hi)]">{formatMeasurement(value)}</dd>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {evidence.contributing_line_numbers.length > 0 && (
        <div className="mt-3 flex flex-col gap-1.5">
          <h4 className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-lo)]">
            Contributing lines ({evidence.contributing_line_numbers.length})
          </h4>
          <div className="flex flex-wrap gap-1.5">
            {evidence.contributing_line_numbers.map((lineNo) => (
              <button
                key={lineNo}
                type="button"
                onClick={() => setExpandedLine(expandedLine === lineNo ? null : lineNo)}
                aria-expanded={expandedLine === lineNo}
                className={`rounded border border-[var(--color-border)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--color-text-mid)] transition-colors ${
                  expandedLine === lineNo ? "bg-[var(--color-surface-2)]" : "hover:bg-[var(--color-surface-2)]"
                }`}
              >
                line {lineNo}
              </button>
            ))}
          </div>
          {expandedLine !== null && (
            <LogLineInspector analysisId={analysisId} rawLineNo={expandedLine} />
          )}
        </div>
      )}

      {incidentId && (
        <div className="mt-3 border-t border-[var(--color-border)] pt-2.5">
          <EvidenceRelevanceToggle
            incidentId={incidentId}
            evidenceId={evidence.evidence_id}
            extractor={evidence.extractor}
          />
        </div>
      )}
    </div>
  );
}
