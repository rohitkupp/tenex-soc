import type { EvidenceConfidenceBand, IncidentDetail, TriageVerdict } from "@/lib/api/types";
import { SeverityBar } from "@/components/severity/SeverityBar";
import { Badge } from "@/components/ui/Badge";
import { dispositionLabel, threatConfidenceLabel } from "@/lib/severity";
import { formatDate, formatScore } from "@/lib/format";
import { parseTag } from "@/lib/tags";

// Shared with the Anomalies queue's own cell (`EvidenceConfidenceCell`), deliberately by
// convention rather than by extracting a component: the queue renders a bare colour-coded number
// in a fixed-width grid track, this renders a labelled sentence in a prose stack, and forcing one
// component to do both would mean a props flag for every difference.
const EVIDENCE_BAND_COLOR: Record<EvidenceConfidenceBand, string> = {
  high: "var(--color-accent-verified)",
  moderate: "var(--color-text-hi)",
  low: "var(--color-severity-medium)",
  very_low: "var(--color-severity-high)",
};

const EVIDENCE_BAND_LABEL: Record<EvidenceConfidenceBand, string> = {
  high: "high",
  moderate: "moderate",
  low: "low",
  very_low: "very low",
};

function resolveBand(band: EvidenceConfidenceBand | null | undefined, score: number): EvidenceConfidenceBand {
  if (band) return band;
  // Mirrors app.agent.confidence._BANDS. Only reached if a verdict predates the band column.
  return score >= 0.75 ? "high" : score >= 0.5 ? "moderate" : score >= 0.25 ? "low" : "very_low";
}

function evidenceBandColor(band: EvidenceConfidenceBand | null | undefined): string {
  return EVIDENCE_BAND_COLOR[band ?? "moderate"];
}

function evidenceBandLabel(band: EvidenceConfidenceBand | null | undefined): string {
  return EVIDENCE_BAND_LABEL[band ?? "moderate"];
}

/** The decomposition, on hover: which of the Judge's ten rubric items this finding failed, and
 *  whether one of them capped the score. This is the whole reason the basis is persisted — a
 *  confidence an analyst cannot interrogate is one they are asked to take on faith. */
function evidenceConfidenceTitle(verdict: TriageVerdict): string {
  const basis = verdict.evidence_confidence_basis;
  const failed = basis?.failed_items ?? [];
  if (failed.length === 0) {
    return "Computed from the Judge's ten-item evidentiary rubric — every item satisfied.";
  }
  const lines = failed.map((f) => `• ${f.item}. ${f.text}`).join("\n");
  const capped =
    basis?.capped_by != null
      ? `\n\nCapped by item ${basis.capped_by}: a failure that cannot be explained away.`
      : "";
  return `Computed from the Judge's ten-item evidentiary rubric. Items not satisfied:\n${lines}${capped}`;
}

// 1. Header — docs/10: "title, severity, fused score, disposition, techniques, recurrence link."
// `analysisId` was only needed to link to a recurrence parent; recurrence detection is gone.
export function CaseHeader({ incident }: { incident: IncidentDetail }) {
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
            {/* The third confidence, directly under the machine's own. `app.agent.confidence`
                scores the Judge's ten-item rubric in code — no model writes it — so it measures
                the *triage*, where anomaly confidence above measures the *traffic*. Rendered
                with the failed rubric items on hover, because a number an analyst cannot
                interrogate is a number they are asked to take on faith. `null` when triage never
                reached the Judge, shown as "not assessed" rather than as a zero. */}
            <span>
              Evidence confidence:{" "}
              {incident.verdict?.evidence_confidence != null ? (
                <span
                  className="font-mono"
                  style={{ color: evidenceBandColor(resolveBand(incident.verdict.evidence_confidence_band, incident.verdict.evidence_confidence)) }}
                  title={evidenceConfidenceTitle(incident.verdict)}
                >
                  {incident.verdict.evidence_confidence.toFixed(2)} —{" "}
                  {evidenceBandLabel(resolveBand(incident.verdict.evidence_confidence_band, incident.verdict.evidence_confidence))}
                </span>
              ) : (
                <span
                  className="text-[var(--color-text-lo)]"
                  title="Triage did not reach the Judge, so no rubric assessment exists for this incident"
                >
                  not assessed
                </span>
              )}
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

    </header>
  );
}
