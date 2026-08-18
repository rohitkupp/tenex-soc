/**
 * PLACEHOLDER — hand-written temporary types.
 *
 * CLAUDE.md requires API types to be generated from the OpenAPI schema
 * (`npm run gen:api`, which writes `lib/api/schema.d.ts`). That target needs
 * the backend running at NEXT_PUBLIC_API_URL, and it was not reachable while
 * this milestone was built. These interfaces are hand-derived from
 * docs/09-API-CONTRACT.md so the app has no `any` in the meantime.
 *
 * TODO(replace): once the backend is up, run `npm run gen:api` and swap the
 * imports below for the generated `components["schemas"][...]` types. Fields
 * marked "best-effort" are not explicitly specified in docs/09 and should be
 * checked against the generated schema first.
 */

export interface ApiErrorBody {
  detail: string;
  code: string;
}

export function isApiErrorBody(value: unknown): value is ApiErrorBody {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as Record<string, unknown>).detail === "string" &&
    typeof (value as Record<string, unknown>).code === "string"
  );
}

// docs/09 documents auth responses as `{user}` / `{user, tenant}` without
// listing user/tenant fields. id + email are the minimum the UI needs.
export interface AuthUser {
  id: string;
  email: string;
}

export interface AuthTenant {
  id: string;
  name: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  user: AuthUser;
}

// ---- Signup & email verification ----
//
// Not yet in docs/09 (its Auth section only lists login/logout/me) — hand-derived from the
// signup flow contract this milestone was built against, same PLACEHOLDER caveat as the rest
// of this file. The 201 on signup is deliberately identical whether or not the email is
// already registered (an API that disclosed account existence would be a privacy leak), so
// `SignupResponse` carries no "created" vs. "already existed" distinction — the UI must not
// invent one either.

export interface SignupRequest {
  email: string;
  password: string;
  org_name: string;
}

export interface SignupResponse {
  status: "verification_sent";
  email: string;
}

export interface ResendVerificationRequest {
  email: string;
}

// Same shape as `SignupResponse` (202 instead of 201) — kept as a distinct alias so call
// sites read by intent rather than by reused type name.
export type ResendVerificationResponse = SignupResponse;

export interface MeResponse {
  user: AuthUser;
  tenant: AuthTenant;
}

export interface UploadResponse {
  upload_id: string;
  detected_sources: string[];
  analysis_id: string;
}

/**
 * Best-effort: docs/09 only spells out the fields for
 * `GET /api/analyses/{id}` (status, stage, progress, counters, cost,
 * parse_failure_rate), not the flat list-item shape returned by
 * `GET /api/analyses`. Consumers should treat every field but `id` and
 * `created_at` as possibly absent until the generated schema confirms them.
 */
export interface AnalysisListItem {
  id: string;
  created_at: string;
  status?: string;
  stage?: string | null;
  progress?: number | null;
  detected_sources?: string[];
}

// Pagination shape is documented generically in docs/09's conventions.
export interface AnalysesListResponse {
  items: AnalysisListItem[];
  next_cursor: string | null;
}

// ---- Analysis detail + pipeline streaming (M4) ----

/**
 * Full analysis resource — `GET /api/analyses/{id}`. Read directly off
 * `backend/app/schemas/uploads.py::AnalysisOut` since the OpenAPI generator
 * has nothing to point at yet (see the PLACEHOLDER note above); swap for
 * the generated `components["schemas"]["AnalysisOut"]` once `npm run
 * gen:api` is runnable.
 */
export interface AnalysisDetail {
  /** The Timeline tab's stored windowed summary, or null until an analyst asks for one. */
  event_timeline_summary?: unknown;
  id: string;
  upload_id: string;
  status: string;
  stage: string | null;
  progress: number;
  pending_parsers: number;
  counters: Record<string, unknown>;
  parse_failure_rate: number | null;
  llm_cost_usd: number | string | null;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
}

/**
 * SSE payload from `GET /api/analyses/{id}/stream` — docs/01-ARCHITECTURE.md's
 * "Terminal contract" (added alongside M4): every event carries `status`, one of
 * `queued | running | complete | failed`, mirroring `analyses.status` — specified
 * precisely so a client never has to *infer* terminality by guessing which `stage`
 * name is last (see `backend/app/pipeline/progress.py`'s docstring for the exact wire
 * example this type matches). `status` is also how a client tells a normal finish
 * (`complete`) apart from a dead-lettered one (`failed`) — see `lib/api/stream.ts` and
 * `FunnelProgress`, docs/v2_migration change 27's "failures surface on the analysis."
 */
export type AnalysisStatus = "queued" | "running" | "complete" | "failed";

export interface AnalysisStreamEvent {
  stage: string;
  progress: number;
  status: AnalysisStatus;
  message: string;
  counters: Record<string, unknown>;
}

export function isAnalysisStreamEvent(value: unknown): value is AnalysisStreamEvent {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.stage === "string" &&
    typeof v.progress === "number" &&
    typeof v.status === "string" &&
    typeof v.message === "string" &&
    typeof v.counters === "object" &&
    v.counters !== null
  );
}

/**
 * Pulls out only the numeric entries of a counters payload. docs' examples
 * are all-numeric, but the wire type is loose (`dict[str, object]` on the
 * backend model), so this guards `AnimatedCounter` against ever being handed
 * a non-numeric value instead of trusting the payload blindly.
 */
export function numericCounters(counters: Record<string, unknown>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(counters)) {
    if (typeof value === "number") out[key] = value;
  }
  return out;
}

// ---- Analysis retry (docs/v2_migration change 27) ----
//
// `/api/ops/*` (queue depth, dead-letter console) was deleted whole — "queue depth
// monitoring belongs in Cloud Monitoring, not in the product" — except for retry,
// which moved to the analysis itself: `POST /api/analyses/{id}/retry`, matching
// `backend/app/schemas/uploads.py::AnalysisRetryResponse` verbatim.

export interface AnalysisRetryResponse {
  analysis_id: string;
  republished_to: string;
  retried_at: string;
}

// ---- Incidents & signals (M15) ----
//
// `/api/analyses/{id}/incidents`, `/api/incidents/{id}`, `/api/incidents/{id}/graph`,
// `/api/incidents/{id}/timeline`, `/api/incidents/{id}/feedback` are all documented in
// docs/09 but **not implemented server-side in this checkout** — there is no
// `app/api/incidents.py` (confirmed: `app/api/learning.py`'s own module docstring says so
// explicitly, and `app/agent/` contains only `__init__.py` — M10's incident-formation logic
// exists in `app/graph/**` but nothing persists incidents/signals through an HTTP surface
// yet, and M11's agent has not been built at all). These types are therefore hand-derived
// from docs/09 + docs/02 + docs/05 + docs/07, exactly like the M1 PLACEHOLDER types above —
// swap for the generated schema once the backend ships this milestone's API layer. Until
// then every fetch against these paths will resolve through the same
// null-on-non-2xx/unreachable path `fetchServer`/`apiFetch` already define, which is the
// correct behavior for a route the backend doesn't serve yet, not a bug in this file.

export type Severity = "critical" | "high" | "medium" | "low";
export type Disposition = "true_positive" | "false_positive" | "benign" | "needs_review";

/**
 * `GET /api/analyses/{id}/incidents` list-item — docs/09's shape verbatim, plus
 * `needs_attention` (best-effort). docs/10 lists `needs_attention` as one of exactly four
 * queue filters, but docs/09's own "keep it flat" example of this exact shape does not
 * include such a field — SSE's `counters.needs_attention` (docs/09's Uploads section) is an
 * aggregate *count*, not a per-incident flag, so it cannot be the same field reused. Rather
 * than invent a field the backend may never send, this is optional and `IncidentQueue`
 * derives it client-side when absent (see that component for the derivation and why).
 */
export type EvidenceConfidenceBand = "high" | "moderate" | "low" | "very_low";

export interface IncidentListItem {
  id: string;
  title: string;
  severity: Severity;
  fused_score: number;
  /** docs/v2_migration change 3: `fused_score` rescaled to 0-100 — "how unusual vs. history",
   * never a probability of malice. Distinct from the verdict's own `threat_confidence`. */
  anomaly_confidence: number;
  disposition: Disposition | null;
  citation_valid: boolean | null;
  /**
   * `app.agent.confidence`: the Judge's ten rubric grades weighted into one 0–1 score. No model
   * emits this — the LLM grades the evidence, code does the arithmetic — which is why it can be
   * compared across incidents at all. `null` when the incident was never triaged or triage never
   * reached the Judge; render that as an em dash, never as a zero.
   *
   * Not interchangeable with `anomaly_confidence` above: that one measures how unusual the
   * traffic was, this one measures how well the evidence supported the conclusion drawn from it.
   * A high-anomaly / low-evidence incident is precisely the row an analyst should look at first.
   */
  evidence_confidence: number | null;
  /** Band for `evidence_confidence`: high ≥0.75, moderate ≥0.50, low ≥0.25, else very_low. */
  evidence_confidence_band: EvidenceConfidenceBand | null;
  mitre_techniques: string[];
  /**
   * Deterministic, always-populated pipeline output — two unioned families, both computed at
   * correlate time, zero LLM cost — distinct from `mitre_techniques` above, which stays the
   * LLM's own contribution and is empty until the incident is triaged.
   * `app.graph.tags`: `technique:<id>` (MITRE-allowlist-filtered), `layer:<detector_layer>`,
   * `detector:<detector_key>`, plus unprefixed derived tags `multi-layer`/`recurring`.
   * `app.graph.asset_tags` (Tier 2 asset-centric pivoting — "every issue tied to device X"):
   * `device:<hostname>`, `os:<type>`, `os_version:<major.minor>`, `dept:<department>`,
   * `location:<location>`, `app:<appname>`, `risk:<band>`, `flow:<type>`, plus unprefixed
   * derived tags `bypassed-client-connector`/`shared-device`. Parsed via `lib/tags.ts`'s
   * `parseTag`, never rendered raw. Verified against the regenerated `lib/api/schema.d.ts`
   * (`npm run gen:api`) — not a guess.
   */
  tags: string[];
  entity_count: number;
  signal_count: number;
  created_at: string;
  needs_attention?: boolean;
}

export interface IncidentsListResponse {
  items: IncidentListItem[];
  next_cursor: string | null;
}

// ---- Explanation payloads ----
//
// Read directly off `backend/app/detection/**/*.py` (each interface below cites its exact
// source) rather than guessed from docs/04's prose. `ExplanationRenderer` dispatches on
// `detector_key` first, then on shape, and never falls through to a JSON dump (docs/13 M15:
// "No raw JSON rendered anywhere in the UI").

export interface PerFeatureContribution {
  feature: string;
  contribution: number;
}

/** Shared by `ml.iforest`, `ml.mahalanobis`, `ml.ecod`, `ml.peer_group` (LOF) — each
 * `explain_row()` in `app/detection/ml/{iforest,mahalanobis,ecod,lof}.py` returns this exact
 * shape (SHAP for iforest; each model's own natural per-feature decomposition for the other
 * three). The L5 technique classifier's SHAP payload (`app/graph/classifier.py`'s
 * `TechniqueClassifierArtifact.predict`) is byte-identical to this shape too. */
export interface PerFeatureContributionExplanation {
  total_score: number;
  per_feature: PerFeatureContribution[];
}

/** `app/detection/ml/autoencoder.py::explain_row` — "the exact shape docs/04 specifies". */
export interface AutoencoderPerFeature {
  feature: string;
  error: number;
  threshold: number;
  exceeded: boolean;
}
export interface AutoencoderExplanationPayload {
  total_recon_error: number;
  per_feature: AutoencoderPerFeature[];
}

/** `app/detection/signal/beaconing.py::detect_beaconing` */
export interface BeaconingExplanationPayload {
  mean_interval: number;
  cv: number;
  mad_jitter: number;
  n_events: number;
  duration_h: number;
  dominant_period_s: number;
  fft_peak_power_ratio: number;
  src_ip: string;
  domain: string;
  regularity: number;
  fft_has_dominant_peak: boolean;
  fft_power_ratio_threshold: number;
  fft_bucket_width_s: number;
  fft_n_buckets: number;
  score_threshold: number;
  evidence_truncated: boolean;
}

/** `app/detection/signal/stl.py` — three scoring paths (`model` distinguishes them); the
 * fallback path's decomposition fields are `null` because no MSTL decomposition ran. Note
 * this is one flagged *hour's* decomposition (scalars), not a time series — there is no
 * multi-point series in this payload to chart. */
export interface STLExplanationPayload {
  model: "stl_daily_weekly" | "stl_daily_only" | "fallback_robust_z";
  trend: number | null;
  seasonal_component: number | null;
  seasonal_daily: number | null;
  seasonal_weekly: number | null;
  residual: number | null;
  residual_z: number | null;
  residual_z_is_infinite: boolean;
  period_used: number[];
  entity_type: string;
  entity_value: string;
  hourly_count: number;
  span_hours?: number;
  n_active_hours?: number;
  reason?: string;
  evidence_truncated: boolean;
}

/** `app/detection/signal/dga.py::detect_dga` */
export interface DGAExplanationPayload {
  domain: string;
  second_level_label: string;
  tld: string;
  hostnames: string[];
  shannon_entropy: number;
  neg_ngram_log_likelihood: number;
  digit_ratio: number;
  max_consonant_run: number;
  len_norm: number;
  score: number;
  decision_threshold: number;
  weights: Record<string, number>;
  intercept: number;
  n_events: number;
  evidence_truncated: boolean;
}

/** `app/detection/signal/burst.py::detect_burst` */
export interface BurstExplanationPayload {
  entity_type: string;
  entity_value: string;
  bucket_start: string;
  bucket_end: string;
  count: number;
  median: number;
  mad: number;
  z: number | null;
  z_is_infinite: boolean;
  threshold: number;
  n_active_buckets: number;
  evidence_truncated: boolean;
}

/** `app/detection/signal/rarity.py::detect_rarity` */
export interface RarityExplanationPayload {
  principal: string;
  domain: string;
  domain_rarity: number;
  org_wide_event_count: number;
  user_novelty: boolean;
  first_seen: string;
  n_events_by_principal: number;
  rare_count_threshold: number;
  evidence_truncated: boolean;
}

/** `app/detection/signal/url_path.py::detect_url_path` — detector_key `signal.url_path_entropy` */
export interface UrlPathExplanationPayload {
  mean_path_entropy: number;
  segment_random_ratio: number;
  sample_paths: string[];
  src_ip: string;
  domain: string;
  entropy_cutoff_p995: number;
  segment_random_cutoff_p995: number;
  flagged_on_entropy: boolean;
  flagged_on_segment_random: boolean;
  n_requests: number;
  n_pairs_in_domain_population: number;
  evidence_truncated: boolean;
}

/** `app/detection/sigma/runner.py::_build_explanation` — every Sigma (L1) rule match.
 * `calibrated` is always `false` today (module docstring: isotonic calibration is M10's job,
 * not built for L1 yet) — rendered honestly, not hidden. */
export interface SigmaExplanationPayload {
  rule_id: string;
  title: string;
  description: string;
  condition: string;
  level: string;
  logsource: { product: string; service: string };
  tags: string[];
  match: Record<string, unknown>;
  calibrated: boolean;
}

export type SignalExplanation =
  | AutoencoderExplanationPayload
  | BeaconingExplanationPayload
  | STLExplanationPayload
  | DGAExplanationPayload
  | BurstExplanationPayload
  | RarityExplanationPayload
  | UrlPathExplanationPayload
  | SigmaExplanationPayload
  | PerFeatureContributionExplanation
  | Record<string, unknown>; // unrecognized shape — ExplanationRenderer falls back to a
  // labelled key/value view (never `JSON.stringify`), see components/explanations/Fallback.tsx

export interface SignalOut {
  id: number;
  detector_key: string;
  detector_layer: "rule" | "signal" | "ml" | "graph" | string;
  raw_score: number;
  confidence: number;
  entity_type: string;
  entity_value: string;
  window_start: string | null;
  window_end: string | null;
  mitre_technique: string | null;
  evidence_event_ids: number[];
  explanation: SignalExplanation;
  created_at: string;
}

/** docs/02 `entities` table. */
export interface EntityOut {
  id: number;
  type: string;
  value: string;
  first_seen: string | null;
  last_seen: string | null;
  event_count: number;
  risk_score: number;
  attrs: Record<string, unknown>;
}

/** docs/07's output schema, `mitre_techniques[]` */
export interface MitreTechniqueRef {
  id: string;
  name: string;
  rationale: string;
}

/**
 * `triage_verdicts.narrative` — `app/agent/schemas.py::NarrativeStep`, matched exactly.
 * `evidence_ids` (not the pre-migration `evidence_event_ids: number[]`) is docs/v2_migration
 * change 7's dual-citation-namespace scheme: each entry is a citation *string*, one of
 * `EVIDENCE-14` / `BASELINE-3` / `LOG-1291` / `MITRE-T1567.002` / `ZSCALER-KB-threat-cat` — never
 * a bare event id. `NarrativeBlock` dispatches on the prefix: an `EVIDENCE-` chip scrolls to that
 * card in the incident's Evidence section (change 16); everything else renders as a plain,
 * non-interactive citation chip.
 */
export interface NarrativeStep {
  step: number;
  claim: string;
  evidence_ids: string[];
}

/**
 * `app/agent/verifier.py::ClaimCheck.as_dict()` — one entry per narrative claim the verifier
 * checked, not one per citation. `evidence_ids` is the claim's own citation list; `missing_ids`/
 * `out_of_scope_ids` name specifically which of those citations failed which check.
 * `NarrativeBlock` treats a citation as invalid when it appears in any of the three id arrays on
 * an entry whose own checks did not all pass — tolerant of older recorded fixtures that may only
 * carry a subset of these fields.
 */
export interface InvalidCitation {
  claim?: string;
  evidence_ids?: string[];
  existence_ok?: boolean;
  numeric_ok?: boolean;
  retrieval_ok?: boolean;
  scope_ok?: boolean | null;
  missing_ids?: string[];
  mismatched_numbers?: string[];
  unretrieved_techniques?: string[];
  out_of_scope_ids?: string[];
  reason?: string;
}

/** docs/07 "Tools" — one entry per tool call in a triage run. */
export interface ToolTraceEntry {
  tool: string;
  arguments: Record<string, unknown>;
  result: unknown;
}

/** docs/02 `triage_verdicts` table, as amended by docs/v2_migration change 3 ("two confidences,
 * never mixed"): the old single `confidence: number` is gone, replaced by the LLM's own
 * low/moderate/high hypothesis-evaluation judgement (plus a mandatory reason). This is never the
 * same thing as `IncidentDetail.anomaly_confidence` / `IncidentListItem.anomaly_confidence` —
 * that one lives on the incident, is calibrated (not the LLM's opinion), and must never be
 * phrased as a probability of malice. */
export interface EvidenceConfidenceBasis {
  score: number;
  band: EvidenceConfidenceBand;
  capped_by: number | null;
  graded_items: number;
  /** Rubric *text* is stored alongside the index, not just the index: item wording can change
   * (it already has once, for polarity) and a stored basis saying only "item 7" would silently
   * start meaning something else. */
  failed_items: { item: number; text: string }[];
}

/** Alias so components can name the verdict shape without importing the `Out` suffix. */
export type TriageVerdict = TriageVerdictOut;

export interface TriageVerdictOut {
  id: string;
  incident_id: string;
  disposition: Disposition;
  threat_confidence: "low" | "moderate" | "high";
  threat_confidence_reason: string;
  /** `app.agent.confidence`: the Judge's ten rubric grades weighted into one 0–1 score. No model
   * writes it — the LLM grades the evidence, code does the arithmetic. `null` when triage never
   * reached the Judge, which is distinct from a graded-and-low score. */
  evidence_confidence: number | null;
  evidence_confidence_band: EvidenceConfidenceBand | null;
  /** The decomposition behind the score, persisted so a value stays explainable without
   * re-running triage. Rendered on hover in the case file. */
  evidence_confidence_basis: EvidenceConfidenceBasis | null;
  llm_severity_opinion: Severity | null;
  mitre_techniques: MitreTechniqueRef[];
  summary: string;
  narrative: NarrativeStep[];
  contradicting_evidence: string;
  /** Free-text investigation guidance for a human analyst (docs/v2_migration change 20) —
   * not action IDs from a catalog. */
  recommended_actions: string[];
  tool_trace: ToolTraceEntry[];
  citation_valid: boolean;
  invalid_citations: InvalidCitation[];
  model: string;
  tokens_in: number | null;
  tokens_out: number | null;
  cost_usd: number | string | null;
  latency_ms: number | null;
  created_at: string;
}

/** `GET /api/incidents/{id}` — docs/09: "Full detail: signals with explanations, entities,
 * timeline, verdict." `verdict` is `null` for an incident not yet triaged (recurrences
 * inherit their parent's verdict per docs/05, so this can still be non-null there). */
export interface IncidentDetail {
  id: string;
  analysis_id: string;
  title: string;
  severity: Severity;
  fused_score: number;
  /** docs/v2_migration change 3 — see `IncidentListItem.anomaly_confidence`'s comment above. */
  anomaly_confidence: number;
  status: string;
  entity_ids: number[];
  signal_ids: number[];
  /** Deterministic, always-present pipeline output — see `IncidentListItem.tags`'s comment. */
  tags: string[];
  /**
   * Deterministic, always-present summary (`app.graph.summary`, computed at correlate time —
   * zero LLM cost). Never overwritten by `verdict.summary` (the LLM's own, richer narrative,
   * present only once triaged) — the case file renders both, labelled, per docs/v2_migration
   * change 3's "two confidences, never mixed" precedent applied to prose.
   */
  summary: string;
  created_at: string;
  entities: EntityOut[];
  signals: SignalOut[];
  verdict: TriageVerdictOut | null;
}

/** `GET /api/incidents/{id}/timeline` — docs/05 "Timeline", output shape verbatim, plus the
 * extra context fields `app/graph/timeline.py::TimelinePhase` actually carries. Also reused by
 * the analysis-wide `GET /api/analyses/{id}/timeline` (M15, see `AnalysisTimelineResponse`
 * below) — that endpoint's contract adds `detector_layer`, `confidence`, and `mitre_technique`
 * on the same phase shape, so they're folded in here (optional, best-effort like the rest of
 * this type) rather than duplicated into a parallel interface. */
export interface TimelinePhaseOut {
  ts: string | null;
  tactic: string;
  tactic_is_placeholder?: boolean;
  event_ids: number[];
  summary: string;
  detector_key?: string;
  detector_layer?: string;
  entity_type?: string;
  entity_value?: string;
  confidence?: number | null;
  /** False when no isotonic calibrator was fitted for this detector, so `confidence` is
   * `clamp01(raw_score)` — a raw detector score, not a probability. Rendering an uncalibrated
   * score as "confidence N%" is misleading: a raw score at or above 1 pins to exactly 1.0, so
   * the UI shows "raw score / uncalibrated" instead. See `AnalysisTimeline.tsx`. */
  calibrated?: boolean;
  mitre_technique?: string | null;
}

/**
 * `GET /api/analyses/{id}/timeline` (new, M15) — the analysis-wide "summarized timeline of
 * events" the brief calls for, surfaced on the overview rather than nested inside one
 * incident's case file. `truncated` marks that the backend capped the phase list to its
 * highest-confidence subset; the contract does not send a total-phase count alongside it, so
 * the UI can say a cap was applied but must not fabricate "of N" — see
 * `components/analyses/AnalysisTimeline.tsx`.
 */
/** `GET /api/incidents/{id}/timeline` — the per-incident phase list. Same envelope as the
 * analysis-wide route: an object with `phases`, never a bare array. The case file typed this as
 * `TimelinePhaseOut[]`, which type-checked and then threw `phases.map is not a function` at
 * render time. */
export interface TimelineResponse {
  phases: TimelinePhaseOut[];
}

export interface AnalysisTimelineResponse {
  phases: TimelinePhaseOut[];
  truncated: boolean;
}

/** `GET /api/incidents/{id}/graph` — docs/09: `{nodes: [], edges: []}`, shaped from docs/02's
 * `entities`/`entity_edges` tables. */
export interface GraphNode {
  id: string; // `${type}:${value}`
  type: string;
  value: string;
  risk_score: number;
  event_count: number;
  is_seed?: boolean;
}
export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
  weight: number;
  event_count: number;
}
export interface IncidentGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// ---- Feedback (learning loop entry point — router IS implemented, app/api/learning.py) ----

/**
 * docs/v2_migration change 22's five Dismiss reason categories, verbatim
 * (`app.learning.feedback.DISMISSAL_REASON_CATEGORIES`) — the dropdown's own vocabulary, not
 * free text. `analyst_feedback.dismissal_reason` (docs/02) stores whichever of these five was
 * picked; the accompanying free-text elaboration goes in `note`, a separate field.
 */
export const DISMISSAL_REASON_CATEGORIES = [
  "sanctioned_automation",
  "known_business_process",
  "expected_for_this_entity",
  "insufficient_evidence",
  "other",
] as const;
export type DismissalReasonCategory = (typeof DISMISSAL_REASON_CATEGORIES)[number];

/** Change 5's mandatory "no forced attribution" value — always offered on top of a verdict's
 * own retrieved candidates in the Override technique dropdown (change 22). */
export const NO_KNOWN_MAPPING = "NO_KNOWN_MAPPING";

export interface DomainLabelCorrectionIn {
  domain: string;
  is_dga: boolean;
}

export interface FeedbackRequest {
  agrees: boolean;
  corrected_disposition?: string;
  corrected_technique?: string;
  dismissal_reason?: string;
  mark_benign_baseline?: boolean;
  note?: string;
  corrected_domain_labels?: DomainLabelCorrectionIn[];
}
export interface DetectorWeightChangeOut {
  detector_key: string;
  true_positives: number;
  false_positives: number;
  precision: number | null;
  weight_before: number;
  weight_after: number;
  changed: boolean;
}
export interface RetrainGateComparisonOut {
  metric: string;
  baseline: number;
  candidate: number;
  delta: number;
  regressed: boolean;
}
export interface RetrainAttemptOut {
  attempted_at: string;
  skipped: boolean;
  skip_reason: string | null;
  n_training_rows: number;
  version: number | null;
  promoted: boolean;
  baseline_version: number | null;
  gate_passed: boolean | null;
  gate_reason: string | null;
  gate_comparisons: RetrainGateComparisonOut[];
}
export interface FeedbackResponse {
  feedback_id: string;
  detector_weight_changes: DetectorWeightChangeOut[];
  calibration_refit_triggered: boolean;
  suppression_candidates_generated: string[];
  benign_baseline_entries_created: number;
  retrain_attempt: RetrainAttemptOut | null;
  /** `4` (added to the kNN/LOF reference set), `5` (excluded as a confirmed true positive), or
   * `null` — what the confirmation toast names (change 22). */
  reference_set_mechanism: number | null;
  baseline_expansion_proposed: boolean;
  exemplar_proposed: boolean;
}

// Response plans (formerly M15, `backend/app/schemas/plans.py`) were removed in
// docs/v2_migration change 20 along with the response action graph and enforcement plane.

// ---- Models & calibration (real schemas, `backend/app/schemas/learning.py` verbatim) ----

export interface ReliabilityBinOut {
  bin_lo: number;
  bin_hi: number;
  predicted_mean: number | null;
  observed_precision: number | null;
  n: number;
}
export interface DetectorCalibrationOut {
  detector_key: string;
  n_samples: number;
  n_positive: number;
  fitted: boolean;
  skip_reason: string | null;
  brier_before: number | null;
  brier_after: number | null;
  brier_improvement: number | null;
  reliability_before: ReliabilityBinOut[];
  reliability_after: ReliabilityBinOut[];
}
export interface CalibrationResponse {
  refit_at: string;
  n_feedback_events: number;
  n_synthetic_feedback_events: number;
  synthetic: boolean;
  overall_brier_before: number | null;
  overall_brier_after: number | null;
  detectors: DetectorCalibrationOut[];
}
export interface ModelVersionOut {
  id: string;
  model_key: string;
  version: number;
  artifact_ref: string;
  trained_at: string;
  eval_scores: Record<string, unknown>;
  promoted: boolean;
}
export interface ModelVersionsResponse {
  items: ModelVersionOut[];
}

/**
 * PLACEHOLDER — `GET /api/models`, docs/09: "Benchmark comparison tables, current promoted
 * versions." `app/api/models.py`'s own module docstring says this route is explicitly M16's
 * job (`evals/`) and is not built in this checkout. Shape hand-derived from
 * `backend/evals/results.md`'s actual table structure (per-layer contenders, mean F1/AUC-PR/
 * recall/precision, a marked winner, scenarios-detected count) — used only to type this
 * page's fetch honestly (it will 404/return null against the current backend and the page
 * renders that as a real empty state, not fabricated numbers). Swap for the generated schema
 * once M16 ships the endpoint.
 */
export interface ModelComparisonRow {
  model_key: string;
  mean_f1: number;
  mean_auc_pr: number;
  mean_recall: number;
  mean_precision: number;
  scenarios_detected: number;
  scenarios_total: number;
  is_winner: boolean;
}
export interface ModelComparisonTable {
  layer: string;
  metric_note?: string;
  contenders: ModelComparisonRow[];
}
export interface ModelsOverviewResponse {
  tables: ModelComparisonTable[];
  promoted_versions: Record<string, number>;
}

// ---- Learning (real schemas, `backend/app/schemas/learning.py` verbatim) ----

export interface AlignmentPointOut {
  period_start: string;
  period_end: string;
  alignment_pct: number;
  n: number;
  synthetic: boolean;
}
export interface DetectorPrecisionPointOut {
  detector_key: string;
  period_start: string;
  period_end: string;
  precision: number | null;
  n: number;
  synthetic: boolean;
}
export interface LearningMetricsResponse {
  computed_at: string;
  n_feedback_events: number;
  n_synthetic_feedback_events: number;
  synthetic: boolean;
  alignment_pct: number | null;
  alignment_trend: AlignmentPointOut[];
  detector_precision_trend: DetectorPrecisionPointOut[];
}
export interface SuppressionCandidateOut {
  id: string;
  detector_key: string;
  entity_type: string;
  entity_value: string;
  reason: string;
  rule_yaml: string;
  status: string;
  synthetic: boolean;
  created_at: string;
  reviewed_at: string | null;
  written_path: string | null;
}
export interface SuppressionListResponse {
  items: SuppressionCandidateOut[];
}
export interface SuppressionAcceptResponse {
  id: string;
  status: string;
  written_path: string;
}

// ---- Continuous learning (docs/v2_migration changes 21/22, `backend/app/schemas/learning.py`) ----

/** Change 22: "Per-claim thumbs on narrative claims, hover-revealed." */
export interface ClaimFeedbackRequest {
  helpful: boolean;
  note?: string;
}
export interface ClaimFeedbackResponse {
  id: number;
  incident_id: string;
  step: number;
  helpful: boolean;
  /** True the moment this thumbs-down completed a cluster of >= 3 similar corrections and
   * mechanism 14 (verifier rule induction) staged a proposal — surfaced so the UI can name the
   * effect, per change 22's toast requirement. */
  verifier_rule_proposed: boolean;
}

/** Change 16/22's "per-evidence relevance toggle" — rendered inside the evidence section (a
 * different milestone's ownership); this is the seam it POSTs through. */
export interface EvidenceRelevanceRequest {
  extractor: string;
  relevant: boolean;
}
export interface EvidenceRelevanceResponse {
  id: number;
  incident_id: string;
  evidence_id: string;
  relevant: boolean;
  /** True the moment this toggle completed mechanism 15's (evidence profile widening) sample
   * threshold and a widening proposal was staged. */
  widening_proposed: boolean;
}

/** The 15 mechanisms, `app.learning.mechanisms.MECHANISMS` mirrored — auto-apply ones log
 * directly; gated ones only ever log through a reviewed `LearningProposalOut`. */
export interface LearningEventOut {
  id: number;
  mechanism: number;
  mechanism_name: string;
  trigger_feedback_id: string | null;
  applied: boolean;
  before_state: Record<string, unknown> | null;
  after_state: Record<string, unknown> | null;
  metric_delta: Record<string, unknown> | null;
  created_at: string;
}
export interface LearningEventsResponse {
  items: LearningEventOut[];
}

export interface LearningProposalOut {
  id: string;
  mechanism: number;
  mechanism_name: string;
  status: "pending" | "approved" | "rejected";
  payload: Record<string, unknown>;
  supporting_feedback_ids: string[];
  created_at: string;
  reviewed_at: string | null;
}
export interface LearningProposalsResponse {
  items: LearningProposalOut[];
}
export interface LearningProposalDecisionResponse {
  id: string;
  status: string;
  passed: boolean;
  after_state: Record<string, unknown>;
  metric_delta: Record<string, unknown>;
  reason: string;
}

// ---- Tier 2 (real schemas, `backend/app/schemas/tier2.py` verbatim) ----

export interface IncidentTypeBreakdownOut {
  incident_type: string;
  signature_count: number;
  tenant_count: number;
  avg_confidence: number;
  /** Mean `evidence_confidence` over the signatures of this type that carry one, and how many
   * that was. `null` when none do. The count travels with the mean because SQL `AVG` skips
   * NULLs — without it a single assessed signature would look like the whole type's average. */
  avg_evidence_confidence: number | null;
  evidence_confidence_count: number;
}
export interface Tier2OverviewResponse {
  total_signatures: number;
  total_tenants: number;
  total_overlapping_indicators: number;
  by_incident_type: IncidentTypeBreakdownOut[];
}
export interface IndicatorOverlapEntryOut {
  indicator_hash: string;
  signature_count: number;
  tenant_count: number;
  incident_types: string[];
  first_observed_at: string;
  last_observed_at: string;
}
export interface IndicatorOverlapResponse {
  items: IndicatorOverlapEntryOut[];
}
// `Tier2QueryRequest`/`Tier2QueryResponse` (the NL-to-SQL chatbot's request/response shapes)
// removed along with `POST /api/tier2/query` — see docs/09's Tier 2 section. The four
// cross-tenant learning chart responses added in its place are generated types
// (`lib/api/tier2-charts.ts`, re-exported from `schema.d.ts`), not hand-written here.

// ---- Events (real schemas, `backend/app/schemas/event.py` verbatim) ----

/**
 * M15: `signal_count`/`max_confidence`/`detectors` are what make "highlight the anomalous
 * entries ... with a confidence score" possible from the list view alone, without a fetch per
 * row. `has_signal=true|false` in `GET /api/analyses/{id}/events` now genuinely filters on
 * `signal_count` (it previously always returned zero rows — see `EventExplorer`).
 */
export interface EventListItem {
  id: number;
  analysis_id: string;
  ts: string;
  source_type: string;
  raw_line_no: number;
  ocsf_class_uid: number;
  principal: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  domain: string | null;
  url_path: string | null;
  action: string | null;
  http_method: string | null;
  status_code: number | null;
  bytes_in: number | null;
  bytes_out: number | null;
  user_agent: string | null;
  event_key: string | null;
  /** Count of signals attached to this event. `> 0` is what "signal-bearing" means, both for
   * the row highlight and for the `has_signal` filter. */
  signal_count: number;
  /** Highest `confidence` among this event's signals; `null` when `signal_count` is 0. */
  max_confidence: number | null;
  /** `detector_key`s of every signal attached to this event — "which detector(s) flagged it". */
  detectors: string[];
}
export interface EventListResponse {
  items: EventListItem[];
  next_cursor: string | null;
}

/**
 * A signal as carried on `GET /api/events/{event_id}`, not `GET /api/incidents/{id}` — a
 * narrower projection of `SignalOut` (no `entity_type`/`entity_value`/`evidence_event_ids`/
 * `created_at`: the event itself is already the evidence, and the entity is implied by it).
 * `ExplanationRenderer` only ever reads `detector_key`/`detector_layer`/`explanation`
 * (see that component), so this shape satisfies its prop type structurally — no need to
 * fabricate the fields this endpoint doesn't send.
 */
export interface EventSignalOut {
  id: number;
  detector_key: string;
  detector_layer: string;
  confidence: number;
  raw_score: number;
  mitre_technique: string | null;
  explanation: SignalExplanation;
  window_start: string | null;
  window_end: string | null;
}

export interface EventOut extends EventListItem {
  ocsf: Record<string, unknown>;
  enrichment: Record<string, unknown>;
  /** Why this event was flagged, one entry per detector — rendered through
   * `ExplanationRenderer` in `EventInspector`, never as raw JSON. */
  signals: EventSignalOut[];
}

// ---- Overview, notable users/destinations, semantic findings, Narrator (docs/v2_migration
// changes 8, 9, 10, 14 Path A — `backend/app/schemas/overview.py` verbatim) ----

/** `GET /api/analyses/{id}/overview`'s `overview` field — change 9's deterministic log
 * overview, computed in SQL, always produced. `period_start`/`period_end` are `null` only for
 * an analysis with zero events — a valid, reportable state, not an error. */
export interface LogOverview {
  period_start: string | null;
  period_end: string | null;
  events: number;
  users: number;
  src_ips: number;
  unique_domains: number;
  allowed: number;
  blocked: number;
  bytes_out: number;
  bytes_in: number;
  parse_failure_rate: number | null;
}

/** `app.baseline.resolve.PercentileResult`, serialised. Cold start must stay visible: when
 * `baseline_status !== "ok"`, `percentile` is `null` — never a number computed from a thin
 * history rendered as if it were trustworthy. */
export interface BaselineComparisonOut {
  metric: string;
  value: number;
  baseline_status: "ok" | "insufficient_history";
  n_windows: number;
  percentile: number | null;
  p50: number | null;
  p95: number | null;
  p99: number | null;
}

/** change 9: "notable users (anomalous windows, volume vs. baseline, first-seen domain count,
 * top anomaly score)". */
export interface NotableUser {
  value: string;
  anomalous_windows: number;
  volume_vs_baseline: BaselineComparisonOut;
  first_seen_domain_count: number;
  top_anomaly_score: number | null;
}

export interface PeriodicityOut {
  dominant_period_s: number;
  spectral_strength: number;
}

/** change 9: "notable destinations (first-observed flag, distinct users, DGA score, connection
 * count, periodicity)". `dga_score` is `ML_ANOMALY_LABEL` territory — never relabelled. */
export interface NotableDestination {
  value: string;
  first_observed: boolean;
  distinct_users: number;
  dga_score: number | null;
  connection_count: number;
  periodicity: PeriodicityOut | null;
}

/**
 * change 8: findings from the LLM semantic domain-analysis pass — brand impersonation,
 * typosquatting intent, contextual relevance — labelled distinctly from the ML/DGA pipeline's
 * own findings, and this is not cosmetic (CLAUDE.md/change 8: "never let a semantic judgement
 * inherit the statistical backing of a calibrated classifier"). `label` is pinned to
 * `SEMANTIC_INSIGHT_LABEL` below by the backend schema's own `Literal` type — this interface
 * mirrors that rather than widening it back to `string`, so a caller cannot accidentally render
 * one of these with the ML badge.
 *
 * **Always `[]` today.** `AnalysisOverviewResponse.domain_semantic_findings` has no producer yet
 * — the semantic LLM call belongs in `app/agent` (out of this milestone's ownership boundary;
 * see `backend/app/schemas/overview.py::DomainSemanticFinding`'s own docstring). This type and
 * `SemanticFindingBadge` exist so the UI renders correctly the moment that call lands.
 */
export interface DomainSemanticFinding {
  domain: string;
  label: typeof SEMANTIC_INSIGHT_LABEL;
  assessment: string;
  rationale: string;
  evidence_id: string | null;
}

/** change 8's two labels, verbatim — never construct either as a free-form string elsewhere. */
export const ML_ANOMALY_LABEL = "ML anomaly — high confidence" as const;
export const SEMANTIC_INSIGHT_LABEL = "Analyst insight — requires validation" as const;

/** `GET /api/analyses/{id}/overview` — change 10 Level 1 ("what happened"): overview stats +
 * anomaly count + notable users/destinations. `executive_summary` is not part of this response
 * — see `AnalysisNarrateResponse` and `ExecutiveSummary` for why that's a separate, explicit,
 * cost-bearing call rather than inlined here. */
export interface AnalysisOverviewResponse {
  overview: LogOverview;
  anomaly_count: number;
  notable_users: NotableUser[];
  notable_destinations: NotableDestination[];
  domain_semantic_findings: DomainSemanticFinding[];
  /** The Path A narrative the `triage` stage already generated and persisted, or `null` if the
   * Narrator has not run for this analysis. Reading it costs nothing — it is a column read on
   * `analyses.narrative`, not an LLM call — which is what lets the page render the executive
   * summary on load instead of behind a "generate" button. */
  narrative: StoredNarrative | null;
}

/** `analyses.narrative*`, as served on the overview. */
export interface StoredNarrative {
  executive_summary: string;
  citation_valid: boolean | null;
  invalid_citation_count: number;
  model: string | null;
  cost_usd: number | string | null;
  generated_at: string | null;
}

/** `POST /api/analyses/{id}/narrate` — change 14 Path A's `NarrationResult`, serialised. Not
 * persisted server-side (see `backend/app/schemas/overview.py`'s module docstring): every call
 * re-runs the Narrator and re-spends, so `ExecutiveSummary` calls this once per explicit click,
 * never automatically on page load. */
export interface PhaseNarrativeOut {
  phase_index: number;
  narrative: string;
  cited_log_ids: string[];
}
export interface AnalysisNarrateResponse {
  executive_summary: string;
  phase_narratives: PhaseNarrativeOut[];
  citation_valid: boolean;
  invalid_citations: Record<string, unknown>[];
  model: string;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number | string;
  latency_ms: number;
}

// ---- Evidence (docs/v2_migration changes 2, 11, 16 — `backend/app/schemas/evidence.py`
// verbatim) ----

/**
 * `app.detection.evidence.payload.EvidencePayload`, serialised. `historical` carries change 1's
 * cold-start contract verbatim — keys ending in `_percentile`/`baseline_status`/`n_windows`
 * (optionally namespaced by scope prefix, e.g. burst's `user_percentile`/`department_percentile`/
 * `org_percentile`) — read defensively, the same "no rigid shared shape across detectors" policy
 * `ExplanationRenderer` already holds for `SignalExplanation`.
 */
export interface EvidencePayloadOut {
  evidence_id: string;
  extractor: string;
  entity_type: string;
  entity_value: string;
  window_start: string;
  window_end: string;
  measurements: Record<string, unknown>;
  historical: Record<string, unknown>;
  contributing_line_numbers: number[];
  nominates_candidate: boolean;
  nomination_score: number | null;
  /** Which of this analysis's incidents this payload contributed to — `[]` is the common,
   * expected case on the analysis-wide browser (change 16: "including evidence that never
   * formed an incident"), not missing data. */
  incident_ids: string[];
}

/**
 * `GET /api/incidents/{id}/evidence` — change 16's primary evidence view + change 11's
 * `highlight_lines`. `highlight_lines` is the union of every item's `contributing_line_numbers`
 * — attribution-derived, never LLM-authored. `highlight_line_violations` is every `LOG-n`
 * citation in this incident's verdict narrative that falls **outside** that set — a presenter
 * citing a line the evidence layer never nominated, exactly the scope violation change 11 says
 * must be caught, not silently rendered.
 */
export interface IncidentEvidenceResponse {
  items: EvidencePayloadOut[];
  highlight_lines: number[];
  highlight_line_violations: number[];
}

/** `GET /api/analyses/{id}/evidence` — change 16's secondary, analysis-wide evidence browser.
 * `truncated` marks that `total` exceeds what `items` carries (server-side cap, filterable by
 * `extractor`/`entity_type`/`entity_value`/`min_percentile` query params). */
export interface AnalysisEvidenceResponse {
  items: EvidencePayloadOut[];
  total: number;
  truncated: boolean;
}
