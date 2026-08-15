"use client";

/**
 * docs/06 "Text-to-SQL safety": every question, malicious or not, gets a real SQL-generation
 * attempt and the UI shows that SQL before anything else — including, especially, when the
 * query was rejected. That ordering (SQL first, always) is the transparency property this
 * component exists to guarantee; it is not something a caller can opt out of by checking
 * `rejected` first.
 */
import { useState } from "react";
import { apiFetch, ApiError } from "@/lib/api/client";
import type { Tier2QueryResponse } from "@/lib/api/types";
import { SqlDisclosure } from "./SqlDisclosure";

const EXAMPLES = [
  "Which incident types have appeared across the most tenants?",
  "Show indicator overlap for command-and-control incidents.",
];

export function NLQueryBox() {
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Tier2QueryResponse | null>(null);

  async function submit(q: string) {
    if (!q.trim()) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const res = await apiFetch<Tier2QueryResponse>("/api/tier2/query", {
        method: "POST",
        body: JSON.stringify({ question: q }),
      });
      setResult(res);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reach the API.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit(question);
        }}
        className="flex flex-col gap-2"
      >
        <textarea
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          rows={2}
          placeholder="Ask a question about cross-tenant indicators and incident types…"
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-1)] px-3 py-2 text-sm text-[var(--color-text-hi)]"
        />
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="submit"
            disabled={busy || !question.trim()}
            className="rounded-md bg-[var(--color-text-hi)] px-4 py-2 text-sm font-medium text-[var(--color-surface-0)] hover:opacity-90 disabled:opacity-50"
          >
            {busy ? "Asking…" : "Ask"}
          </button>
          {EXAMPLES.map((ex) => (
            <button
              key={ex}
              type="button"
              onClick={() => {
                setQuestion(ex);
                void submit(ex);
              }}
              className="text-xs text-[var(--color-text-lo)] underline underline-offset-2 hover:text-[var(--color-text-mid)]"
            >
              {ex}
            </button>
          ))}
        </div>
      </form>

      {error && (
        <p role="alert" className="text-xs text-[var(--color-severity-high)]">
          {error}
        </p>
      )}

      {result && (
        <div className="flex flex-col gap-3">
          <SqlDisclosure sql={result.sql} rejected={result.rejected} />
          <p className="text-xs text-[var(--color-text-mid)]">{result.explanation}</p>

          {result.rejected ? (
            <p role="alert" className="rounded-md border border-[var(--color-severity-high)] p-3 text-xs text-[var(--color-severity-high)]">
              Rejected: {result.rejection_reason ?? "did not pass validation."}
            </p>
          ) : (
            <QueryResultView response={result} />
          )}
        </div>
      )}
    </div>
  );
}

function QueryResultView({ response }: { response: Tier2QueryResponse }) {
  if (response.rows.length === 0) {
    return <p className="text-sm text-[var(--color-text-mid)]">No rows returned.</p>;
  }

  if (response.chart_hint === "number" && response.rows[0]) {
    return <p className="font-mono text-2xl text-[var(--color-text-hi)]">{String(response.rows[0][0])}</p>;
  }

  if (response.chart_hint === "bar" || response.chart_hint === "line") {
    const maxVal = Math.max(...response.rows.map((r) => Number(r[1]) || 0), 1);
    return (
      <div className="flex flex-col gap-2">
        {response.rows.slice(0, 20).map((row, i) => {
          const value = Number(row[1]) || 0;
          return (
            <div key={i} className="flex items-center gap-2 text-xs">
              <span className="w-32 shrink-0 truncate text-[var(--color-text-mid)]">{String(row[0])}</span>
              <div className="h-2 flex-1 rounded-full bg-[var(--color-surface-2)]">
                <div
                  className="h-2 rounded-full bg-[var(--color-text-hi)]"
                  style={{ width: `${(value / maxVal) * 100}%` }}
                />
              </div>
              <span className="w-12 shrink-0 text-right font-mono text-[var(--color-text-hi)]">{value}</span>
            </div>
          );
        })}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-md border border-[var(--color-border)]">
      <table className="w-full min-w-[420px] border-collapse text-xs">
        <thead>
          <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface-1)] text-left text-[var(--color-text-lo)]">
            {response.columns.map((col) => (
              <th key={col} className="px-3 py-2 font-normal">
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {response.rows.map((row, i) => (
            <tr key={i} className="border-b border-[var(--color-border)] bg-[var(--color-surface-1)] last:border-b-0">
              {row.map((cell, j) => (
                <td key={j} className="px-3 py-2 font-mono text-[var(--color-text-hi)]">
                  {String(cell)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
