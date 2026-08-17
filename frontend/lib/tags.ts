/**
 * `IncidentListItem.tags` / `IncidentDetail.tags` — deterministic, namespaced tag strings
 * (`app.graph.tags`, backend). Parsed here rather than rendered raw so the queue and the case
 * file agree on one presentation for `technique:T1090` / `layer:rule` /
 * `detector:sigma.blocked_then_allowed` / bare derived tags (`multi-layer`, `recurring`).
 */

export type TagKind = "technique" | "layer" | "detector" | "derived";

export interface ParsedTag {
  kind: TagKind;
  /** The tag with its namespace prefix stripped — `"T1090"`, `"rule"`,
   * `"sigma.blocked_then_allowed"` — or, for a derived tag, the tag itself unchanged. */
  label: string;
  raw: string;
}

const PREFIXES: Record<string, TagKind> = {
  "technique:": "technique",
  "layer:": "layer",
  "detector:": "detector",
};

export function parseTag(raw: string): ParsedTag {
  for (const [prefix, kind] of Object.entries(PREFIXES)) {
    if (raw.startsWith(prefix)) {
      return { kind, label: raw.slice(prefix.length), raw };
    }
  }
  return { kind: "derived", label: raw, raw };
}

export function techniqueIdsFromTags(tags: string[]): string[] {
  return tags.filter((t) => t.startsWith("technique:")).map((t) => t.slice("technique:".length));
}
