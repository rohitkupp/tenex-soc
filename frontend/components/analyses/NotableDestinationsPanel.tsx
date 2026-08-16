/**
 * change 9/10: "Notable destinations" — first-observed flag, distinct users, DGA score,
 * connection count, periodicity. `dga_score` is the ML/statistical pipeline's own finding
 * (`MLAnomalyBadge`) — never relabelled as an "Analyst insight", the distinction change 8
 * exists to protect.
 */
import type { NotableDestination } from "@/lib/api/types";
import { formatNumber, formatScore } from "@/lib/format";
import { Panel } from "@/components/ui/Panel";
import { Badge } from "@/components/ui/Badge";
import { MLAnomalyBadge } from "@/components/ui/SemanticFindingBadge";

export function NotableDestinationsPanel({ destinations }: { destinations: NotableDestination[] }) {
  return (
    <Panel title="Notable destinations" padding="tight">
      {destinations.length === 0 ? (
        <p className="px-1 py-4 text-sm text-[var(--color-text-mid)]">
          Nothing notable — no destination in this analysis stood out by volume or anomaly score.
        </p>
      ) : (
        <div className="flex flex-col divide-y divide-[var(--color-border)]">
          {destinations.map((dest) => (
            <div key={dest.value} className="flex flex-col gap-1.5 px-1 py-2.5 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[var(--color-text-hi)]">{dest.value}</span>
                {dest.first_observed && <Badge variant="outline">first observed</Badge>}
                {dest.dga_score !== null && <MLAnomalyBadge />}
              </div>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[var(--color-text-mid)]">
                <span>
                  distinct users{" "}
                  <span className="font-mono text-[var(--color-text-hi)]">{formatNumber(dest.distinct_users)}</span>
                </span>
                <span>
                  connections{" "}
                  <span className="font-mono text-[var(--color-text-hi)]">{formatNumber(dest.connection_count)}</span>
                </span>
                {dest.dga_score !== null && (
                  <span>
                    DGA score <span className="font-mono text-[var(--color-text-hi)]">{formatScore(dest.dga_score)}</span>
                  </span>
                )}
                {dest.periodicity && (
                  <span>
                    periodicity{" "}
                    <span className="font-mono text-[var(--color-text-hi)]">
                      every {Math.round(dest.periodicity.dominant_period_s)}s
                    </span>{" "}
                    (strength {formatScore(dest.periodicity.spectral_strength)})
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
