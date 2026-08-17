/**
 * `IncidentListItem.tags` / `IncidentDetail.tags` — deterministic, namespaced tag strings.
 * Two independently-computed families share this one flat list (`app.pipeline.stages.correlate`
 * unions them): `app.graph.tags` (`technique:`/`layer:`/`detector:`/derived `multi-layer`/
 * `recurring`) and `app.graph.asset_tags` (`device:`/`os:`/`os_version:`/`dept:`/`location:`/
 * `app:`/`risk:`/`flow:`/derived `bypassed-client-connector`/`shared-device`) — the asset-tag
 * family exists for Tier 2 asset-centric pivoting ("every issue tied to device X"), see that
 * module's own docstring for the full per-tag justification. Parsed here rather than rendered
 * raw so the queue and the case file agree on one presentation for every namespace.
 */

export type TagKind =
  | "technique"
  | "layer"
  | "detector"
  | "device"
  | "os"
  | "os_version"
  | "dept"
  | "location"
  | "app"
  | "risk"
  | "flow"
  | "derived";

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
  "device:": "device",
  "os_version:": "os_version", // checked before "os:" — both start with "os"
  "os:": "os",
  "dept:": "dept",
  "location:": "location",
  "app:": "app",
  "risk:": "risk",
  "flow:": "flow",
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
