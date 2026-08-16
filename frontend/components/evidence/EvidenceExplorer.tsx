"use client";

/**
 * `/analyses/[id]/evidence` — change 16's secondary evidence view: "every payload produced for
 * the analysis, filterable by extractor, entity and percentile, including evidence that never
 * formed an incident. That residue is exactly what an analyst wants when they suspect the
 * pipeline missed something."
 *
 * Same server-fetches-initial / client-manages-filters split as `EventExplorer`
 * (`components/events/EventExplorer.tsx`): the page component fetches the first, unfiltered
 * page server-side; every filter change after that re-fetches directly against the API from
 * the browser.
 */
import { useCallback, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { AnalysisEvidenceResponse, EvidencePayloadOut } from "@/lib/api/types";
import { EvidenceCard } from "@/components/evidence/EvidenceCard";

interface Filters {
  extractor: string;
  entity_type: string;
  entity_value: string;
  min_percentile: string;
}

const EMPTY_FILTERS: Filters = { extractor: "", entity_type: "", entity_value: "", min_percentile: "" };

const EXTRACTORS = ["beaconing", "dga", "burst", "rarity", "stl", "url_entropy"];

function buildQuery(analysisId: string, filters: Filters): string {
  const params = new URLSearchParams();
  if (filters.extractor) params.set("extractor", filters.extractor);
  if (filters.entity_type) params.set("entity_type", filters.entity_type);
  if (filters.entity_value) params.set("entity_value", filters.entity_value);
  if (filters.min_percentile) params.set("min_percentile", filters.min_percentile);
  return `/api/analyses/${analysisId}/evidence?${params.toString()}`;
}

export function EvidenceExplorer({
  analysisId,
  initial,
}: {
  analysisId: string;
  initial: AnalysisEvidenceResponse | null;
}) {
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [items, setItems] = useState<EvidencePayloadOut[]>(initial?.items ?? []);
  const [total, setTotal] = useState<number>(initial?.total ?? 0);
  const [truncated, setTruncated] = useState<boolean>(initial?.truncated ?? false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refetch = useCallback(
    async (next: Filters) => {
      setLoading(true);
      setError(null);
      try {
        const res = await apiFetch<AnalysisEvidenceResponse>(buildQuery(analysisId, next));
        setItems(res.items);
        setTotal(res.total);
        setTruncated(res.truncated);
      } catch (err: unknown) {
        setError(err instanceof ApiError ? err.message : "Could not reach the API.");
      } finally {
        setLoading(false);
      }
    },
    [analysisId],
  );

  function update<K extends keyof Filters>(key: K, value: Filters[K]) {
    const next = { ...filters, [key]: value };
    setFilters(next);
    void refetch(next);
  }

  const inputClass =
    "rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)] px-2 py-1.5 text-sm text-[var(--color-text-hi)]";

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] p-3">
        <label className="flex flex-col gap-1 text-xs text-[var(--color-text-mid)]">
          Extractor
          <select
            value={filters.extractor}
            onChange={(e) => update("extractor", e.target.value)}
            className={inputClass}
          >
            <option value="">all</option>
            {EXTRACTORS.map((e) => (
              <option key={e} value={e}>
                {e}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-[var(--color-text-mid)]">
          Entity type
          <input
            value={filters.entity_type}
            onChange={(e) => update("entity_type", e.target.value)}
            placeholder="user, domain, src_ip…"
            className={inputClass}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-[var(--color-text-mid)]">
          Entity value
          <input
            value={filters.entity_value}
            onChange={(e) => update("entity_value", e.target.value)}
            placeholder="exact match"
            className={inputClass}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-[var(--color-text-mid)]">
          Min percentile
          <input
            type="number"
            min={0}
            max={100}
            value={filters.min_percentile}
            onChange={(e) => update("min_percentile", e.target.value)}
            placeholder="0–100"
            className={`${inputClass} w-24`}
          />
        </label>
      </div>

      <div className="flex items-center justify-between text-xs text-[var(--color-text-lo)]">
        <span>
          {loading
            ? "Loading…"
            : `${items.length} of ${total} evidence payload${total === 1 ? "" : "s"} shown${
                truncated ? " (truncated — narrow the filters to see the rest)" : ""
              }`}
        </span>
      </div>

      {error && (
        <p role="alert" className="text-xs text-[var(--color-severity-high)]">
          {error}
        </p>
      )}

      {!loading && items.length === 0 ? (
        <p className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] px-6 py-10 text-center text-sm text-[var(--color-text-mid)]">
          No evidence payloads match these filters.
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          {items.map((item) => (
            <div key={item.evidence_id} className="flex flex-col gap-1">
              <EvidenceCard evidence={item} analysisId={analysisId} />
              {item.incident_ids.length === 0 && (
                <span className="pl-1 text-xs text-[var(--color-text-lo)]">
                  Never formed an incident.
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
