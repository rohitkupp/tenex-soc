/**
 * change 9/10: "Traffic statistics" — the deterministic overview stats, always produced,
 * computed in SQL (`GET /api/analyses/{id}/overview`). Rendered through the same `StatGrid`
 * the pipeline-stage stats on this page already use.
 */
import type { LogOverview } from "@/lib/api/types";
import { formatBytes, formatDate, formatNumber, formatPercent } from "@/lib/format";
import { Panel } from "@/components/ui/Panel";
import { StatGrid } from "@/components/ui/StatGrid";

export function TrafficStatsPanel({ overview }: { overview: LogOverview }) {
  return (
    <Panel title="Traffic statistics" padding="tight">
      <div className="p-1">
        <StatGrid
          stats={[
            { label: "Events", value: formatNumber(overview.events), mono: true },
            { label: "Users", value: formatNumber(overview.users), mono: true },
            { label: "Source IPs", value: formatNumber(overview.src_ips), mono: true },
            { label: "Unique domains", value: formatNumber(overview.unique_domains), mono: true },
            { label: "Allowed", value: formatNumber(overview.allowed), mono: true },
            { label: "Blocked", value: formatNumber(overview.blocked), mono: true },
            { label: "Bytes out", value: formatBytes(overview.bytes_out), mono: true },
            { label: "Bytes in", value: formatBytes(overview.bytes_in), mono: true },
            { label: "Parse failure rate", value: formatPercent(overview.parse_failure_rate), mono: true },
            {
              label: "Period",
              value:
                overview.period_start && overview.period_end
                  ? `${formatDate(overview.period_start)} – ${formatDate(overview.period_end)}`
                  : "—",
            },
          ]}
        />
      </div>
    </Panel>
  );
}
