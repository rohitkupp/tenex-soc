import type { FirstSeenResponse } from "@/lib/api/tier2-charts";
import { InsufficientCrossTenantData } from "./InsufficientCrossTenantData";

const MS_PER_DAY = 24 * 60 * 60 * 1000;
const ROW_HEIGHT = 34;
const AXIS_WIDTH = 560;
const LABEL_WIDTH = 130;

interface DayGroup {
  dayOffset: number;
  tenantHashes: string[];
  firstObservedAt: string;
}

/** Midnight of the viewer's local calendar day for an instant — the same day boundary every
 * rendered date on this page uses (`formatDate`/`formatCompactDate` format in local time). */
function startOfLocalDay(iso: string): number {
  const d = new Date(iso);
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
}

function groupByDay(observations: FirstSeenResponse["items"][number]["observations"]): {
  groups: DayGroup[];
  maxDayOffset: number;
} {
  // Sort locally rather than trusting response order: Day 0 must anchor to the true earliest
  // observation, and the wire format does not promise sorted observations.
  const sorted = [...observations].sort((a, b) =>
    a.first_observed_at.localeCompare(b.first_observed_at)
  );
  // Calendar-day offsets, not elapsed-hours rounding. `Math.round(deltaMs / DAY)` bucketed by
  // 24-hour spans from the anchor's clock time: a tenant first seen at 13:00 on the *same
  // calendar day* as the anchor rounded to "+1d", while one seen just after midnight the next
  // day could land on day 0. The Indicator-overlap table right above this chart renders
  // calendar dates, so the two visibly disagreed about when the same indicator was seen.
  // Diffing local-midnight epochs makes "day" mean the same thing a rendered date means.
  const earliestDay = startOfLocalDay(sorted[0]!.first_observed_at);
  const byDay = new Map<number, DayGroup>();
  for (const obs of sorted) {
    const dayOffset = Math.round((startOfLocalDay(obs.first_observed_at) - earliestDay) / MS_PER_DAY);
    const existing = byDay.get(dayOffset);
    if (existing) {
      existing.tenantHashes.push(obs.tenant_hash);
    } else {
      byDay.set(dayOffset, {
        dayOffset,
        tenantHashes: [obs.tenant_hash],
        firstObservedAt: obs.first_observed_at,
      });
    }
  }
  const groups = [...byDay.values()].sort((a, b) => a.dayOffset - b.dayOffset);
  return { groups, maxDayOffset: Math.max(...groups.map((g) => g.dayOffset), 0) };
}

// docs/09/CLAUDE.md chart 4: for indicators seen by 2+ tenants, when did each tenant first
// see it — the early-warning story ("tenant A on day 1, tenant B on day 4"). Tenant identity
// is never a raw name here, only a truncated `tenant_hash` (docs/06's shared-salt indicator
// scheme), same anonymization discipline as `IndicatorOverlapTable`.
export function FirstSeenChart({ data }: { data: FirstSeenResponse }) {
  if (data.items.length === 0) {
    return (
      <InsufficientCrossTenantData
        tenantCount={0}
        detail="No indicator has been seen by 2 or more tenants yet — first-seen propagation only exists for indicators that already cleared that bar."
      />
    );
  }

  const rows = data.items.map((item) => ({ item, ...groupByDay(item.observations) }));
  const sharedMaxDay = Math.max(...rows.map((r) => r.maxDayOffset), 0);
  const allSameDay = sharedMaxDay === 0;
  // A zero-width axis (every tenant saw it the same day, across every row) would collapse
  // every marker onto a single point at x=0 with nothing to compare — treat the axis as
  // spanning at least one day so a real, if uneventful, timeline still renders.
  const axisMaxDay = Math.max(sharedMaxDay, 1);
  const totalHeight = rows.length * ROW_HEIGHT + 24;

  return (
    <div className="flex flex-col gap-4">
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${LABEL_WIDTH + AXIS_WIDTH + 20} ${totalHeight}`}
          width="100%"
          height={totalHeight}
          role="img"
          aria-label="First-seen propagation across tenants, by day offset from first sighting"
        >
          {/* axis line */}
          <line
            x1={LABEL_WIDTH}
            y1={totalHeight - 18}
            x2={LABEL_WIDTH + AXIS_WIDTH}
            y2={totalHeight - 18}
            stroke="var(--color-border)"
            strokeWidth={1}
          />
          <text x={LABEL_WIDTH} y={totalHeight - 4} fontSize="9" fill="var(--color-text-lo)">
            Day 0 (first sighting)
          </text>
          <text
            x={LABEL_WIDTH + AXIS_WIDTH}
            y={totalHeight - 4}
            fontSize="9"
            fill="var(--color-text-lo)"
            textAnchor="end"
          >
            +{axisMaxDay}d
          </text>

          {rows.map(({ item, groups }, rowIndex) => {
            const y = rowIndex * ROW_HEIGHT + ROW_HEIGHT / 2;
            return (
              <g key={item.indicator_hash}>
                <text x={0} y={y + 4} fontSize="10" fontFamily="var(--font-mono)" fill="var(--color-text-hi)">
                  {item.indicator_hash.slice(0, 12)}…
                </text>
                <text x={0} y={y + 16} fontSize="9" fill="var(--color-text-lo)">
                  {item.tenant_count} tenants
                </text>
                <line
                  x1={LABEL_WIDTH}
                  y1={y}
                  x2={LABEL_WIDTH + AXIS_WIDTH * (groups[groups.length - 1]!.dayOffset / axisMaxDay)}
                  y2={y}
                  stroke="var(--color-border)"
                  strokeWidth={2}
                />
                {groups.map((group) => {
                  const x = LABEL_WIDTH + AXIS_WIDTH * (group.dayOffset / axisMaxDay);
                  const count = group.tenantHashes.length;
                  return (
                    <g key={group.dayOffset}>
                      <circle
                        cx={x}
                        cy={y}
                        r={count > 1 ? 7 : 5}
                        fill="var(--color-surface-1)"
                        stroke="var(--color-text-hi)"
                        strokeWidth={2}
                      >
                        <title>
                          {count > 1 ? `${count} tenants` : group.tenantHashes[0]} — day {group.dayOffset} (
                          {new Date(group.firstObservedAt).toLocaleDateString()})
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
      {allSameDay ? (
        <p className="text-xs text-[var(--color-text-lo)]">
          Every qualifying indicator so far was first observed by all of its tenants on the same day — there
          is not yet enough day-level spread in the data to show a staggered early-warning timeline. The
          mechanism (comparing each tenant&apos;s own first-observed timestamp) is real; the current dataset is
          just thin.
        </p>
      ) : (
        <p className="text-xs text-[var(--color-text-lo)]">
          Each marker is the earliest day a distinct tenant observed this indicator, relative to whichever
          tenant saw it first.
        </p>
      )}
    </div>
  );
}
