"use client";

/**
 * Overview · Incidents · Events · Evidence as tabs on the analysis page.
 *
 * These were four routes (`/analyses/[id]`, `.../incidents`, `.../events`, `.../evidence`).
 * Every switch between them was a full server navigation, which on this app meant a fresh
 * server render against a database a region away — seconds of blank page for what is
 * conceptually one screen with four views of the same analysis. Worse, each of those pages
 * carried its own "← Analysis" link, so moving between views built a browser history stack
 * whose Back entries went to pages the analyst had not meaningfully "come from".
 *
 * All four panels are rendered server-side by the parent page and handed here as `children`;
 * this component only chooses which one is visible. No fetching, no navigation, no Suspense
 * boundary — switching tabs is a `useState` update and is instant.
 *
 * The active tab is mirrored into the URL with `history.replaceState`, deliberately **not**
 * `pushState` and not `router.replace`. Deep links (`?tab=events`) work and a reload keeps
 * the analyst where they were, but Back leaves the analysis entirely rather than walking
 * backwards through tab changes — which is what "I don't want it navigating to a new webpage"
 * asks for, and it is the behaviour that makes Back predictable again.
 *
 * Hidden panels stay mounted (`hidden`, not unmounted) so client state inside each explorer —
 * filters, sort order, scroll position — survives a round trip through another tab.
 */
import { useCallback, useEffect, useState, type ReactNode } from "react";

export type AnalysisTabKey = "overview" | "incidents" | "events" | "evidence";

const TABS: { key: AnalysisTabKey; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "incidents", label: "Incidents" },
  { key: "events", label: "Events" },
  { key: "evidence", label: "Evidence" },
];

function isTabKey(value: string | null): value is AnalysisTabKey {
  return TABS.some((tab) => tab.key === value);
}

export function AnalysisTabs({
  overview,
  incidents,
  events,
  evidence,
  counts,
}: {
  overview: ReactNode;
  incidents: ReactNode;
  events: ReactNode;
  evidence: (active: boolean) => ReactNode;
  counts?: Partial<Record<AnalysisTabKey, number>>;
}) {
  const [active, setActive] = useState<AnalysisTabKey>("overview");

  // Read `?tab=` after mount rather than during render: the parent is a server component, so
  // reading search params during render would opt the whole page into dynamic rendering for a
  // purely client-side concern.
  useEffect(() => {
    const requested = new URLSearchParams(window.location.search).get("tab");
    if (isTabKey(requested)) setActive(requested);
  }, []);

  const select = useCallback((key: AnalysisTabKey) => {
    setActive(key);
    const url = new URL(window.location.href);
    if (key === "overview") url.searchParams.delete("tab");
    else url.searchParams.set("tab", key);
    window.history.replaceState(null, "", url);
  }, []);

  const panels: Record<AnalysisTabKey, ReactNode> = {
    overview,
    incidents,
    events,
    // A render prop, not a node: the Evidence panel fetches its own (large, slow) payload and
    // must not start until the analyst actually opens the tab.
    evidence: evidence(active === "evidence"),
  };

  return (
    <div className="flex flex-col gap-6">
      <div role="tablist" aria-label="Analysis views" className="flex items-center gap-4 border-b border-[var(--color-border)] text-sm">
        {TABS.map((tab) => {
          const selected = tab.key === active;
          const count = counts?.[tab.key];
          return (
            <button
              key={tab.key}
              type="button"
              role="tab"
              id={`analysis-tab-${tab.key}`}
              aria-selected={selected}
              aria-controls={`analysis-panel-${tab.key}`}
              onClick={() => select(tab.key)}
              className={
                selected
                  ? "-mb-px border-b-2 border-[var(--color-text-hi)] pb-2 font-medium text-[var(--color-text-hi)]"
                  : "-mb-px border-b-2 border-transparent pb-2 text-[var(--color-text-mid)] transition-colors hover:border-[var(--color-border)] hover:text-[var(--color-text-hi)]"
              }
            >
              {tab.label}
              {count !== undefined && (
                <span className="ml-1.5 font-mono text-xs text-[var(--color-text-lo)]">{count}</span>
              )}
            </button>
          );
        })}
      </div>

      {TABS.map((tab) => (
        <div
          key={tab.key}
          role="tabpanel"
          id={`analysis-panel-${tab.key}`}
          aria-labelledby={`analysis-tab-${tab.key}`}
          hidden={tab.key !== active}
          className={tab.key === active ? "flex flex-col gap-6" : undefined}
        >
          {panels[tab.key]}
        </div>
      ))}
    </div>
  );
}
