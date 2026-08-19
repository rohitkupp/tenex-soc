import type { FirstSeenResponse } from "@/lib/api/tier2-charts";
import { InsufficientCrossTenantData } from "./InsufficientCrossTenantData";

const MS_PER_DAY = 24 * 60 * 60 * 1000;
const ROW_HEIGHT = 34;
const AXIS_WIDTH = 560;
const LABEL_WIDTH = 130;

interface DayGroup {
  /** Calendar days since the chart's global earliest observation. */
  dayIndex: number;
  tenantHashes: string[];
  firstObservedAt: string;
}

/** Midnight of the viewer's local calendar day for an instant — the same day boundary every
 * rendered date on this page uses (`formatDate`/`formatCompactDate` format in local time). */
function startOfLocalDay(iso: string): number {
  const d = new Date(iso);
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
}

function shortDay(epochMs: number): string {
  return new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric" }).format(
    new Date(epochMs)
  );
}

function groupByDay(
  observations: FirstSeenResponse["items"][number]["observations"],
  chartStartDay: number
): DayGroup[] {
  const byDay = new Map<number, DayGroup>();
  const sorted = [...observations].sort((a, b) =>
    a.first_observed_at.localeCompare(b.first_observed_at)
  );
  for (const obs of sorted) {
    const dayIndex = Math.round((startOfLocalDay(obs.first_observed_at) - chartStartDay) / MS_PER_DAY);
    const existing = byDay.get(dayIndex);
    if (existing) {
      existing.tenantHashes.push(obs.tenant_hash);
    } else {
      byDay.set(dayIndex, {
        dayIndex,
        tenantHashes: [obs.tenant_hash],
        firstObservedAt: obs.first_observed_at,
      });
    }
  }
  return [...byDay.values()].sort((a, b) => a.dayIndex - b.dayIndex);
}

// docs/09/CLAUDE.md chart 4: for indicators seen by 2+ tenants, when did each tenant first
// see it — the early-warning story ("tenant A on day 1, tenant B on day 4"). Tenant identity
// is never a raw name here, only a truncated `tenant_hash` (docs/06's shared-salt indicator
// scheme), same anonymization discipline as `IndicatorOverlapTable`.
//
// **One absolute date axis shared by every row — not a per-row "day 0".** The first version
// anchored each indicator to its own first sighting, which read coherently when campaigns
// propagated over weeks but collapsed once propagation compressed to hours: every row showed
// "day 0, +1d" while the Indicator-overlap table directly above showed the same campaigns
// staggered across a week of real dates — the chart and the table appeared to disagree, and
// the one thing a relative axis structurally cannot show (that different campaigns *started*
// on different days) was exactly the story the data had. Real dates on a shared axis make the
// two panels corroborate each other by construction.
export function FirstSeenChart({ data }: { data: FirstSeenResponse }) {
  if (data.items.length === 0) {
    return (
      <InsufficientCrossTenantData
        tenantCount={0}
        detail="No indicator has been seen by 2 or more tenants yet — first-seen propagation only exists for indicators that already cleared that bar."
      />
    );
  }

  const allObservations = data.items.flatMap((i) => i.observations);
  const chartStartDay = Math.min(...allObservations.map((o) => startOfLocalDay(o.first_observed_at)));
  const chartEndDay = Math.max(...allObservations.map((o) => startOfLocalDay(o.first_observed_at)));
  const totalDays = Math.max(1, Math.round((chartEndDay - chartStartDay) / MS_PER_DAY));

  const rows = data.items.map((item) => ({
    item,
    groups: groupByDay(item.observations, chartStartDay),
  }));
  const totalHeight = rows.length * ROW_HEIGHT + 34;
  const xFor = (dayIndex: number) => LABEL_WIDTH + AXIS_WIDTH * (dayIndex / totalDays);
  // Label every day up to two weeks; past that, thin the ticks rather than the data.
  const tickStep = totalDays <= 14 ? 1 : Math.ceil(totalDays / 10);
  const ticks = [];
  for (let d = 0; d <= totalDays; d += tickStep) ticks.push(d);
  if (ticks[ticks.length - 1] !== totalDays) ticks.push(totalDays);

  return (
    <div className="flex flex-col gap-4">
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${LABEL_WIDTH + AXIS_WIDTH + 20} ${totalHeight}`}
          width="100%"
          height={totalHeight}
          role="img"
          aria-label="First-seen propagation across tenants, by calendar date of each tenant's first observation"
        >
          {/* axis line + day ticks */}
          <line
            x1={LABEL_WIDTH}
            y1={totalHeight - 28}
            x2={LABEL_WIDTH + AXIS_WIDTH}
            y2={totalHeight - 28}
            stroke="var(--color-border)"
            strokeWidth={1}
          />
          {ticks.map((d) => (
            <g key={d}>
              <line
                x1={xFor(d)}
                y1={totalHeight - 32}
                x2={xFor(d)}
                y2={totalHeight - 24}
                stroke="var(--color-border)"
                strokeWidth={1}
              />
              <text
                x={xFor(d)}
                y={totalHeight - 12}
                fontSize="9"
                fill="var(--color-text-lo)"
                textAnchor="middle"
              >
                {shortDay(chartStartDay + d * MS_PER_DAY)}
              </text>
            </g>
          ))}

          {rows.map(({ item, groups }, rowIndex) => {
            const y = rowIndex * ROW_HEIGHT + ROW_HEIGHT / 2;
            const first = groups[0]!;
            const last = groups[groups.length - 1]!;
            return (
              <g key={item.indicator_hash}>
                <text x={0} y={y + 4} fontSize="10" fontFamily="var(--font-mono)" fill="var(--color-text-hi)">
                  {item.indicator_hash.slice(0, 12)}…
                </text>
                <text x={0} y={y + 16} fontSize="9" fill="var(--color-text-lo)">
                  {item.tenant_count} tenants
                </text>
                {groups.length > 1 && (
                  <line
                    x1={xFor(first.dayIndex)}
                    y1={y}
                    x2={xFor(last.dayIndex)}
                    y2={y}
                    stroke="var(--color-border)"
                    strokeWidth={2}
                  />
                )}
                {groups.map((group) => {
                  const x = xFor(group.dayIndex);
                  const count = group.tenantHashes.length;
                  return (
                    <g key={group.dayIndex}>
                      <circle
                        cx={x}
                        cy={y}
                        r={count > 1 ? 7 : 5}
                        fill="var(--color-surface-1)"
                        stroke="var(--color-text-hi)"
                        strokeWidth={2}
                      >
                        <title>
                          {count > 1 ? `${count} tenants` : group.tenantHashes[0]} — first observed{" "}
                          {shortDay(chartStartDay + group.dayIndex * MS_PER_DAY)}
                        </title>
                      </circle>
                      {count > 1 && (
                        <text
                          x={x}
                          y={y + 3}
                          fontSize="8"
                          textAnchor="middle"
                          fill="var(--color-text-hi)"
                          fontFamily="var(--font-mono)"
                        >
                          {count}
                        </text>
                      )}
                    </g>
                  );
                })}
              </g>
            );
          })}
        </svg>
      </div>
      <p className="text-xs text-[var(--color-text-lo)]">
        Each marker is the calendar day a distinct tenant first observed the indicator — the same
        dates the Indicator-overlap table reports. A campaign whose markers sit further right was
        first seen later; markers stacked on one day mean several tenants saw it within hours of
        each other.
      </p>
    </div>
  );
}
