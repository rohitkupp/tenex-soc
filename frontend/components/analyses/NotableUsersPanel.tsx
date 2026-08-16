/**
 * change 9/10: "Notable users" — anomalous windows, volume vs. baseline, first-seen domain
 * count, top anomaly score. Every field here is deterministic (`GET /api/analyses/{id}/
 * overview`, computed from `entities`/`signals`/`entity_edges`/the baseline store) — no LLM
 * involvement, so nothing here needs the `SemanticFindingBadge` treatment.
 *
 * Cold start must stay visible (CLAUDE.md/change 1): a user whose `volume_vs_baseline.
 * baseline_status !== "ok"` shows "insufficient history", never a percentile computed from a
 * handful of windows dressed up to look trustworthy.
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
                <span title={`n=${user.volume_vs_baseline.n_windows} baseline windows`}>
                  volume vs. baseline{" "}
                  {user.volume_vs_baseline.baseline_status === "ok" ? (
                    <span className="font-mono text-[var(--color-text-hi)]">
                      {user.volume_vs_baseline.percentile?.toFixed(1)}th pct
                    </span>
                  ) : (
                    <span className="rounded border border-dashed border-[var(--color-border)] px-1 py-0.5">
                      insufficient history (n={user.volume_vs_baseline.n_windows})
                    </span>
                  )}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
