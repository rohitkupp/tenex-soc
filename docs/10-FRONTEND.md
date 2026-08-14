# 10 — Frontend

Next.js 15 App Router, TypeScript strict, Tailwind, shadcn/ui. Server Components by default.
API types generated from the OpenAPI schema — never hand-written.

## Design direction

The default answer for a security tool is a near-black NOC wall with an acid-green accent and
monospace everything. Skip it — it is the templated look, and this product is not a monitoring
wall.

**The concept is a case file, not a dashboard.** This is an investigation tool. An analyst opens
one incident and reads a reasoned argument with evidence attached. That framing drives the whole
design.

**Palette.** Dark surface, because analysts work in dark tooling and fighting that is
contrarianism rather than design. But the discipline is: *color is reserved exclusively for
severity encoding.* Chrome, type, borders, and backgrounds are neutral. Nothing else on screen is
saturated. When something is colored, it means something.

```
--surface-0   #0E1116   page
--surface-1   #161A21   cards
--surface-2   #1F242D   raised / hover
--border      #2A303B
--text-hi     #E6E9EF
--text-mid    #9BA3B0
--text-lo     #6B7280
severity-critical  #E5484D
severity-high      #E5822D
severity-medium    #D4A72C
severity-low       #4B7BA8
accent-verified    #3FA37A   -- citation verified only
```

**Type.** IBM Plex, all three cuts — it was designed for technical documentation, gives a
coherent system from one family, and reads as infrastructure software without the terminal
cliché.
- `IBM Plex Sans` — UI chrome, headings
- `IBM Plex Mono` — log data, IDs, IPs, domains, generated SQL
- `IBM Plex Serif` — **narrative body only**, 17px/1.65, measure capped at 68ch

That serif is the deliberate risk. The incident narrative is prose an analyst reads and reasons
about, and setting it as a document rather than as UI text is the single choice that makes this
feel unlike every other security tool. It appears in exactly one place.

**Signature element: the evidence-linked narrative.** Each claim in the incident narrative is
followed by its citation chips. Clicking one expands the raw OCSF event inline beneath the claim,
in mono, without navigating away. Verified citations get a hairline `accent-verified` underline;
unverified ones get a warning marker and stay visible. This is the product thesis made physical —
grounded AI reasoning you can audit at the sentence level.

Density contrast is the structural idea: the queue is tight and scannable, the case view is
generous and readable. Moving between them should feel like moving from an index to a document.

**Motion.** One orchestrated moment: the pipeline funnel on the upload page, where counters
count up per stage as SSE events arrive. Everything else is instant. Respect
`prefers-reduced-motion`.

**Copy.** Active voice, sentence case, plain verbs. Buttons name what happens: "Approve plan"
produces "Plan approved." Empty states direct rather than apologize: "No incidents yet — upload a
log file to start." Errors say what broke and what to do.

## Routes

| Route | Purpose |
|---|---|
| `/login` | Credentials. Nothing else. |
| `/` | Analysis list + aggregate funnel |
| `/upload` | Drop zone, format detection preview, live SSE stage progress |
| `/analyses/[id]` | Overview: funnel, event volume over time with anomaly overlay, top entities, severity distribution, parse quality |
| `/analyses/[id]/incidents` | The queue. Primary working view. |
| `/analyses/[id]/incidents/[iid]` | The case file. The most important screen in the product. |
| `/analyses/[id]/events` | Raw event explorer, filterable, signal-bearing rows marked |
| `/models` | Benchmark tables, calibration diagram, version history |
| `/learning` | Alignment trend, per-detector precision, containment rate, pending suppressions |
| `/tier2` | Cross-tenant analytics + NL query |
| `/ops` | Queue depths, dead letters with retry |

## Key screens

### `/upload`
Drop zone → immediate format sniff showing detected sources and a 5-line parse preview before
committing. Then the funnel: stages as a horizontal sequence, current stage active, counters
incrementing from SSE. The funnel is the thesis of the architecture, so make it the hero.

### `/analyses/[id]/incidents`
Dense table, sorted by `fused_score`. Columns: severity bar, title, techniques, source-type
badges, signal count, disposition, citation-verified marker, recurrence indicator.
Filters: severity, disposition, source type, technique, `needs_attention` only.
Row click opens the case file. Keyboard: `j`/`k` to move, `Enter` to open.

### `/analyses/[id]/incidents/[iid]` — the case file
Vertical document, not a grid of widgets:

1. **Header** — title, severity, fused score, disposition, techniques, recurrence link
2. **Summary** — two or three sentences, serif
3. **Narrative** — numbered claims, serif, with expandable citation chips. The signature element.
4. **Contradicting evidence** — visually distinct block. The devil's advocate output belongs
   above the fold, not hidden; it is what makes the verdict credible.
5. **Timeline** — deterministic phases with ATT&CK tactic labels
6. **Signals** — each with its structured `explanation` rendered by detector type: per-feature
   reconstruction bars for the autoencoder, interval statistics for beaconing, surprising
   transitions for the sequence model, SHAP bars for tree models. Never render raw JSON.
7. **Entity graph** — cytoscape, incident subgraph, severity-colored nodes
8. **Response plan** — ordered steps with preconditions, blast-radius warnings, verification
   result, approve button. After execution: state diff and containment outcome.
9. **Agent trace** — collapsed by default. Tool calls, arguments, results, tokens, cost, latency.
10. **Feedback** — agree / override / dismiss with reason

### `/models`
Comparison tables with the winner marked, per detection layer. Reliability diagram. Version
history with the eval scores that gated each promotion. This page exists so the benchmarking
discipline is visible rather than buried in a README.

## Components

`FunnelProgress`, `SeverityBar`, `IncidentTable`, `NarrativeBlock`, `CitationChip`,
`EventInspector`, `ExplanationRenderer` (dispatches by detector type), `EntityGraph`,
`TimelinePhases`, `ResponsePlanStepper`, `StateDiff`, `AgentTrace`, `FeedbackControls`,
`CalibrationChart`, `SqlDisclosure`.

`ExplanationRenderer` is the one to get right — it is what makes the ML legible, and legibility
is the whole point.

## Quality floor

Responsive to mobile. Visible keyboard focus everywhere. `prefers-reduced-motion` respected.
Loading skeletons, never spinners on full pages. Every list has a designed empty state.
