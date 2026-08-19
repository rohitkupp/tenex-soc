/**
 * change 9/10: "Notable users" — anomalous windows, first-seen domain count, top anomaly
 * score. Every field here is deterministic (`GET /api/analyses/{id}/overview`, computed from
 * `entities`/`signals`/`entity_edges`/the baseline store) — no LLM involvement, so nothing
 * here needs the `SemanticFindingBadge` treatment.
 *
 * `volume_vs_baseline` is still on the wire (the API contract is unchanged) but no longer
 * rendered — removed by request. Its cold-start honesty rule now applies to the evidence
 * layer's percentile annotations instead, which read the same baseline store.
 */
import type { NotableUser } from "@/lib/api/types";
import { formatNumber, formatScore } from "@/lib/format";
import { Panel } from "@/components/ui/Panel";

export function NotableUsersPanel({ users }: { users: NotableUser[] }) {
  return (
    <Panel title="Notable users" padding="tight">
      {users.length === 0 ? (
        <p className="px-1 py-4 text-sm text-[var(--color-text-mid)]">
          Nothing notable — no user in this analysis stood out by volume or anomaly score.
        </p>
      ) : (
        <div className="flex flex-col divide-y divide-[var(--color-border)]">
          {users.map((user) => (
            <div key={user.value} className="flex flex-wrap items-center justify-between gap-3 px-1 py-2.5 text-sm">
              <span className="font-mono text-[var(--color-text-hi)]">{user.value}</span>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[var(--color-text-mid)]">
                <span>
                  top anomaly score{" "}
                  <span className="font-mono text-[var(--color-text-hi)]">{formatScore(user.top_anomaly_score)}</span>
                </span>
                <span>
                  anomalous windows{" "}
                  <span className="font-mono text-[var(--color-text-hi)]">{formatNumber(user.anomalous_windows)}</span>
                </span>
                <span>
                  first-seen domains{" "}
                  <span className="font-mono text-[var(--color-text-hi)]">
                    {formatNumber(user.first_seen_domain_count)}
                  </span>
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
