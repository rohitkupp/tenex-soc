import Link from "next/link";
import type { IncidentDetail } from "@/lib/api/types";
import { SeverityBar } from "@/components/severity/SeverityBar";
import { Badge } from "@/components/ui/Badge";
import { dispositionLabel, threatConfidenceLabel } from "@/lib/severity";
import { formatDate, formatScore } from "@/lib/format";
import { parseTag } from "@/lib/tags";

// 1. Header — docs/10: "title, severity, fused score, disposition, techniques, recurrence link."
export function CaseHeader({ incident, analysisId }: { incident: IncidentDetail; analysisId: string }) {
  const techniques = incident.verdict?.mitre_techniques ?? [];
  return (
    <header className="flex flex-col gap-3 border-b border-[var(--color-border)] pb-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex flex-col gap-2">
          <h1 className="text-2xl font-semibold tracking-tight text-[var(--color-text-hi)]">{incident.title}</h1>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBar severity={incident.severity} size="md" />
            <span className="font-mono text-xs text-[var(--color-text-mid)]">
              fused score {formatScore(incident.fused_score)}
            </span>
            <Badge variant="outline">{dispositionLabel(incident.verdict?.disposition ?? null)}</Badge>
            {incident.status !== "open" && <Badge variant="outline">{incident.status}</Badge>}
          </div>
          {/* docs/v2_migration change 3's UI contract: both confidences rendered, labelled, and
              never phrased as a probability of malice. anomaly_confidence is "how unusual", not
              "how likely to be an attack" — that judgement is threat_confidence, the LLM's own,
              paired with its disposition above. */}
          <div className="flex flex-col gap-0.5 text-xs text-[var(--color-text-mid)]">
            <span>
              Anomaly confidence:{" "}
              <span className="font-mono text-[var(--color-text-hi)]">
                {Math.round(incident.anomaly_confidence)}/100
              </span>
            </span>
            <span>
              Threat assessment:{" "}
              <span className="text-[var(--color-text-hi)]">
                {dispositionLabel(incident.verdict?.disposition ?? null)} —{" "}
                {threatConfidenceLabel(incident.verdict?.threat_confidence ?? null)}
              </span>
            </span>
          </div>
        </div>
        <span className="text-xs text-[var(--color-text-lo)]">Opened {formatDate(incident.created_at)}</span>
      </div>

      {/* Deterministic tags — `app.graph.tags`, computed at correlate time for every incident,
          separate provenance from the LLM's own `verdict.mitre_techniques` below (CLAUDE.md:
          "these are separate fields with separate provenance, and the distinction must be
          legible"). Rendered first and labelled "Detected" so a reader never mistakes a
          rule/signal/ml hit for an LLM's own hypothesis evaluation. */}
      {incident.tags.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-[var(--color-text-lo)]">Detected:</span>
          {incident.tags.map((tag) => {
            const parsed = parseTag(tag);
            return (
              <span
                key={tag}
                title={tag}
                className="rounded border border-[var(--color-border)] px-2 py-0.5 font-mono text-xs text-[var(--color-text-mid)]"
              >
                {parsed.label}
              </span>
            );
          })}
        </div>
      )}

      {techniques.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-[var(--color-text-lo)]">LLM assessment:</span>
          {techniques.map((t) => (
            <span
              key={t.id}
              title={t.rationale}
              className="rounded border border-[var(--color-border)] px-2 py-0.5 font-mono text-xs text-[var(--color-text-mid)]"
            >
              {t.id} · {t.name}
            </span>
          ))}
        </div>
      )}

      {incident.recurrence_of && (
        <Link
          href={`/analyses/${analysisId}/incidents/${incident.recurrence_of}`}
          className="w-fit text-xs text-[var(--color-text-mid)] underline underline-offset-2 transition-colors hover:text-[var(--color-text-hi)]"
        >
          Recurrence of incident {incident.recurrence_of.slice(0, 8)}
          {incident.recurrence_similarity !== null && ` · similarity ${formatScore(incident.recurrence_similarity)}`}
        </Link>
      )}
    </header>
  );
}
