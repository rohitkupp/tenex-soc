"use client";

/**
 * The queue — docs/10: "Dense table sorted by fused_score. Columns: severity bar, title,
 * techniques, signal count, disposition, citation-verified marker, recurrence indicator.
 * Filters: severity, disposition, technique, needs_attention only. Row click opens the case
 * file. Keyboard: j/k to move, Enter to open."
 *
 * The list arrives already sorted by `fused_score` desc (docs/09) — filtering here is
 * client-side over that order, never a re-sort, so the queue's primary ranking is never
 * second-guessed by the UI.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import type { Disposition, IncidentListItem, Severity } from "@/lib/api/types";
import { SEVERITY_ORDER, dispositionLabel, severityLabel } from "@/lib/severity";
import { SeverityBar } from "@/components/severity/SeverityBar";
import { Badge } from "@/components/ui/Badge";
import { formatScore } from "@/lib/format";

const DISPOSITIONS: Disposition[] = ["true_positive", "false_positive", "benign", "needs_review"];

/** Best-effort derivation for incidents the backend hasn't tagged `needs_attention` on
 * directly (see `lib/api/types.ts`'s `IncidentListItem` docstring for why the field is
 * optional): untriaged, explicitly flagged for review, or carrying an unverified citation —
 * every case where a human's judgment is the missing ingredient. */
function needsAttention(incident: IncidentListItem): boolean {
  if (incident.needs_attention !== undefined) return incident.needs_attention;
  return (
    incident.disposition === null ||
    incident.disposition === "needs_review" ||
    incident.citation_valid === false
  );
}

interface IncidentQueueProps {
  analysisId: string;
  incidents: IncidentListItem[];
}

export function IncidentQueue({ analysisId, incidents }: IncidentQueueProps) {
  const router = useRouter();
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(new Set());
  const [dispositionFilter, setDispositionFilter] = useState<string>("all");
  const [techniqueFilter, setTechniqueFilter] = useState<string>("all");
  const [attentionOnly, setAttentionOnly] = useState(false);
  const [focusedIndex, setFocusedIndex] = useState(0);
  const rowRefs = useRef<Array<HTMLAnchorElement | null>>([]);

  const techniques = useMemo(() => {
    const set = new Set<string>();
    incidents.forEach((i) => i.mitre_techniques.forEach((t) => set.add(t)));
    return [...set].sort();
  }, [incidents]);

  const filtered = useMemo(() => {
    return incidents.filter((incident) => {
      if (severityFilter.size > 0 && !severityFilter.has(incident.severity)) return false;
      if (dispositionFilter === "untriaged" && incident.disposition !== null) return false;
      if (
        dispositionFilter !== "all" &&
        dispositionFilter !== "untriaged" &&
        incident.disposition !== dispositionFilter
      )
        return false;
      if (techniqueFilter !== "all" && !incident.mitre_techniques.includes(techniqueFilter)) return false;
      if (attentionOnly && !needsAttention(incident)) return false;
      return true;
    });
  }, [incidents, severityFilter, dispositionFilter, techniqueFilter, attentionOnly]);

  useEffect(() => {
    setFocusedIndex(0);
  }, [filtered.length]);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      const target = e.target as HTMLElement | null;
      if (target && ["INPUT", "SELECT", "TEXTAREA"].includes(target.tagName)) return;
      if (filtered.length === 0) return;

      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        setFocusedIndex((i) => Math.min(i + 1, filtered.length - 1));
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        setFocusedIndex((i) => Math.max(i - 1, 0));
      } else if (e.key === "Enter") {
        const incident = filtered[focusedIndex];
        if (incident) router.push(`/analyses/${analysisId}/incidents/${incident.id}`);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [filtered, focusedIndex, analysisId, router]);

  useEffect(() => {
    rowRefs.current[focusedIndex]?.scrollIntoView({ block: "nearest" });
  }, [focusedIndex]);

  function toggleSeverity(s: Severity) {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  }

  const filterButton = (active: boolean) =>
    `rounded-full border px-2.5 py-1 text-xs transition-colors ${
      active
        ? "border-[var(--color-text-hi)] text-[var(--color-text-hi)]"
        : "border-[var(--color-border)] text-[var(--color-text-mid)] hover:text-[var(--color-text-hi)]"
    }`;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="mr-1 text-xs text-[var(--color-text-lo)]">Severity</span>
        {SEVERITY_ORDER.map((s) => (
          <button key={s} type="button" onClick={() => toggleSeverity(s)} className={filterButton(severityFilter.has(s))}>
            {severityLabel(s)}
          </button>
        ))}

        <span className="ml-3 mr-1 text-xs text-[var(--color-text-lo)]">Disposition</span>
        <select
          value={dispositionFilter}
          onChange={(e) => setDispositionFilter(e.target.value)}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)] px-2 py-1 text-xs text-[var(--color-text-hi)]"
        >
          <option value="all">All</option>
          <option value="untriaged">Untriaged</option>
          {DISPOSITIONS.map((d) => (
            <option key={d} value={d}>
              {dispositionLabel(d)}
            </option>
          ))}
        </select>

        {techniques.length > 0 && (
          <>
            <span className="ml-3 mr-1 text-xs text-[var(--color-text-lo)]">Technique</span>
            <select
              value={techniqueFilter}
              onChange={(e) => setTechniqueFilter(e.target.value)}
              className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)] px-2 py-1 font-mono text-xs text-[var(--color-text-hi)]"
            >
              <option value="all">All</option>
              {techniques.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </>
        )}

        <button
          type="button"
          onClick={() => setAttentionOnly((v) => !v)}
          className={`ml-3 ${filterButton(attentionOnly)}`}
        >
          Needs attention only
        </button>

        <span className="ml-auto text-xs text-[var(--color-text-lo)]">
          {filtered.length} of {incidents.length} · j/k to move, enter to open
        </span>
      </div>

      {filtered.length === 0 ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-14 text-center">
          <p className="text-sm text-[var(--color-text-mid)]">
            {incidents.length === 0 ? "No incidents yet — this analysis found nothing worth a human's time." : "No incidents match these filters."}
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-[var(--color-border)]">
          <div className="grid grid-cols-[auto_1fr_auto_auto_auto_auto_auto] items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface-1)] px-3 py-2 text-xs text-[var(--color-text-lo)]">
            <span className="w-1" aria-hidden="true" />
            <span>Title</span>
            <span>Techniques</span>
            <span className="text-right">Score</span>
            <span className="text-right">Signals</span>
            <span>Disposition</span>
            <span>Citations</span>
          </div>
          <ul>
            {filtered.map((incident, index) => (
              <li key={incident.id}>
                <Link
                  ref={(el) => {
                    rowRefs.current[index] = el;
                  }}
                  href={`/analyses/${analysisId}/incidents/${incident.id}`}
                  onMouseEnter={() => setFocusedIndex(index)}
                  aria-current={index === focusedIndex ? "true" : undefined}
                  className={`grid grid-cols-[auto_1fr_auto_auto_auto_auto_auto] items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface-1)] px-3 py-2.5 text-sm transition-colors last:border-b-0 hover:bg-[var(--color-surface-2)] ${
                    index === focusedIndex ? "bg-[var(--color-surface-2)] outline outline-1 outline-[var(--color-text-mid)] -outline-offset-1" : ""
                  }`}
                >
                  <SeverityBar severity={incident.severity} />
                  <span className="flex min-w-0 items-center gap-2">
                    <span className="truncate text-[var(--color-text-hi)]">{incident.title}</span>
                    {incident.recurrence_of && (
                      <span
                        title={`Recurrence of incident ${incident.recurrence_of}`}
                        className="shrink-0 text-xs text-[var(--color-text-lo)]"
                        aria-label="Recurring incident"
                      >
                        ↻
                      </span>
                    )}
                    {needsAttention(incident) && <Badge variant="outline">needs attention</Badge>}
                  </span>
                  <span className="hidden gap-1 sm:flex">
                    {incident.mitre_techniques.slice(0, 2).map((t) => (
                      <span key={t} className="rounded border border-[var(--color-border)] px-1.5 py-0.5 font-mono text-xs text-[var(--color-text-mid)]">
                        {t}
                      </span>
                    ))}
                    {incident.mitre_techniques.length > 2 && (
                      <span className="text-xs text-[var(--color-text-lo)]">+{incident.mitre_techniques.length - 2}</span>
                    )}
                  </span>
                  <span className="text-right font-mono text-xs text-[var(--color-text-hi)]">
                    {formatScore(incident.fused_score)}
                  </span>
                  <span className="text-right font-mono text-xs text-[var(--color-text-mid)]">
                    {incident.signal_count}
                  </span>
                  <span className="hidden text-xs text-[var(--color-text-mid)] sm:inline">
                    {dispositionLabel(incident.disposition)}
                  </span>
                  <span
                    className="text-xs"
                    style={{
                      color:
                        incident.citation_valid === true
                          ? "var(--color-accent-verified)"
                          : incident.citation_valid === false
                            ? "var(--color-severity-high)"
                            : "var(--color-text-lo)",
                    }}
                    title={
                      incident.citation_valid === true
                        ? "Every citation verified"
                        : incident.citation_valid === false
                          ? "One or more citations failed verification"
                          : "Not yet triaged"
                    }
                  >
                    {incident.citation_valid === true ? "✓" : incident.citation_valid === false ? "!" : "—"}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
