/**
 * Turns an arbitrary JSON-ish value into a flat, ordered list of `key: value` pairs for a
 * labelled mono display — the shared mechanism behind both `EventInspector`'s raw-OCSF-event
 * view and `FallbackExplanation`'s unrecognized-shape view. Neither ever hands a reader
 * `JSON.stringify`'d text (docs/13 M15: "No raw JSON rendered anywhere in the UI") — this is
 * the same data, laid out as rows a human can scan, exactly the way a log line is read.
 */
export interface FlatEntry {
  key: string;
  value: string;
  depth: number;
}

const MAX_ARRAY_ITEMS = 25;
const MAX_STRING_LEN = 500;

function formatScalar(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) return "—";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : String(value);
  if (typeof value === "string") {
    return value.length > MAX_STRING_LEN ? `${value.slice(0, MAX_STRING_LEN)}…` : value;
  }
  return String(value);
}

export function flattenForDisplay(
  value: unknown,
  prefix = "",
  depth = 0,
): FlatEntry[] {
  if (value === null || value === undefined || typeof value !== "object") {
    return prefix ? [{ key: prefix, value: formatScalar(value), depth }] : [];
  }

  if (Array.isArray(value)) {
    if (value.length === 0) return [{ key: prefix || "value", value: "(empty)", depth }];
    const isAllScalar = value.every((v) => v === null || typeof v !== "object");
    if (isAllScalar) {
      const shown = value.slice(0, MAX_ARRAY_ITEMS).map(formatScalar).join(", ");
      const suffix = value.length > MAX_ARRAY_ITEMS ? ` … (+${value.length - MAX_ARRAY_ITEMS} more)` : "";
      return [{ key: prefix || "value", value: shown + suffix, depth }];
    }
    return value.slice(0, MAX_ARRAY_ITEMS).flatMap((item, i) =>
      flattenForDisplay(item, prefix ? `${prefix}[${i}]` : `[${i}]`, depth),
    );
  }

  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length === 0) return [{ key: prefix || "value", value: "(empty)", depth }];
  return entries.flatMap(([k, v]) => {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === "object") {
      return flattenForDisplay(v, key, depth + 1);
    }
    return [{ key, value: formatScalar(v), depth }];
  });
}
