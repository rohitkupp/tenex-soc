import Link from "next/link";
import type { IncidentDetail } from "@/lib/api/types";
import { SeverityBar } from "@/components/severity/SeverityBar";
import { Badge } from "@/components/ui/Badge";
import { dispositionLabel } from "@/lib/severity";
import { formatDate, formatScore } from "@/lib/format";

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
        </div>
        <span className="text-xs text-[var(--color-text-lo)]">Opened {formatDate(incident.created_at)}</span>
      </div>

      {techniques.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
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
