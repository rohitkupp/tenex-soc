import type { GraphEdge, GraphNode, IncidentGraph } from "@/lib/api/types";
import { severityColor } from "@/lib/severity";

/**
 * 7. Entity graph — docs/10 names cytoscape; cytoscape is not in CLAUDE.md's stack table
 * (Next.js/TS/Tailwind/shadcn only) and this task's ownership is `frontend/**` under that
 * table's constraint ("do not add libraries not listed ... without asking"), so this is a
 * small hand-rolled SVG layout instead — deterministic (no client-side force simulation to
 * settle, so it's server-renderable and stable across reloads) rather than a lesser version
 * of the same idea. Seeds (docs/05: entities carrying >= 1 signal directly) sit on an inner
 * ring, their 1-hop neighborhood on an outer ring — the same two-tier structure incident
 * formation itself builds, made visible. Node color reuses the severity scale keyed off
 * `risk_score` (docs/10 asks for "severity-colored nodes"; entities have no severity field of
 * their own, docs/02, so this is the natural reading, not a new use of color).
 */
function riskSeverity(riskScore: number): "critical" | "high" | "medium" | "low" {
  if (riskScore >= 0.85) return "critical";
  if (riskScore >= 0.6) return "high";
  if (riskScore >= 0.35) return "medium";
  return "low";
}

const WIDTH = 640;
const HEIGHT = 420;
const CENTER_X = WIDTH / 2;
const CENTER_Y = HEIGHT / 2;
const INNER_R = 90;
const OUTER_R = 180;

interface Positioned extends GraphNode {
  x: number;
  y: number;
}

function layout(nodes: GraphNode[]): Positioned[] {
  const seeds = nodes.filter((n) => n.is_seed);
  const others = nodes.filter((n) => !n.is_seed);
  const place = (list: GraphNode[], radius: number): Positioned[] =>
    list.map((n, i) => {
      const angle = (2 * Math.PI * i) / Math.max(list.length, 1) - Math.PI / 2;
      return { ...n, x: CENTER_X + radius * Math.cos(angle), y: CENTER_Y + radius * Math.sin(angle) };
    });
  // A graph with no explicit seeds (every field the same tier) still lays out sensibly on one ring.
  if (seeds.length === 0) return place(others, OUTER_R);
  return [...place(seeds, INNER_R), ...place(others, OUTER_R)];
}

export function EntityGraph({ graph }: { graph: IncidentGraph }) {
  if (graph.nodes.length === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No graph data for this incident.</p>;
  }
  const positioned = layout(graph.nodes);
  const byId = new Map(positioned.map((n) => [n.id, n]));
  const maxEventCount = Math.max(1, ...graph.nodes.map((n) => n.event_count));
  const maxWeight = Math.max(1, ...graph.edges.map((e) => e.weight));

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="min-w-[480px]" role="img" aria-label="Incident entity graph">
        {graph.edges.map((edge: GraphEdge, i: number) => {
          const source = byId.get(edge.source);
          const target = byId.get(edge.target);
          if (!source || !target) return null;
          return (
            <line
              key={i}
              x1={source.x}
              y1={source.y}
              x2={target.x}
              y2={target.y}
              stroke="var(--color-border)"
              strokeWidth={Math.max(1, (edge.weight / maxWeight) * 3)}
            >
              <title>
                {edge.relation}: {source.value} → {target.value} ({edge.event_count} events)
              </title>
            </line>
          );
        })}
        {positioned.map((node) => {
          const radius = 6 + (node.event_count / maxEventCount) * 14;
          const color = severityColor(riskSeverity(node.risk_score));
          return (
            <g key={node.id}>
              <circle
                cx={node.x}
                cy={node.y}
                r={radius}
                fill="var(--color-surface-1)"
                stroke={color}
                strokeWidth={2}
              >
                <title>
                  {node.type}: {node.value} · risk {node.risk_score.toFixed(2)} · {node.event_count} events
                </title>
              </circle>
              <text
                x={node.x}
                y={node.y + radius + 12}
                textAnchor="middle"
                fontSize={10}
                fontFamily="var(--font-mono)"
                fill="var(--color-text-mid)"
              >
                {node.value.length > 16 ? `${node.value.slice(0, 15)}…` : node.value}
              </text>
            </g>
          );
        })}
      </svg>
      <p className="mt-2 text-xs text-[var(--color-text-lo)]">
        Inner ring: seed entities carrying a signal directly. Outer ring: their one-hop neighborhood. Node size ∝
        event count; node color ∝ risk score.
      </p>
    </div>
  );
}
