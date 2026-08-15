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
 * SSE payload from `GET /api/analyses/{id}/stream` — docs/01-ARCHITECTURE.md
 * and docs/09-API-CONTRACT.md give this shape verbatim (docs/09 additionally
 * documents `needs_attention` inside `counters`). There is no explicit
 * "done"/terminal flag on the wire; see `lib/api/stream.ts` for how terminal
 * state is inferred from `stage` + `progress` instead.
 */
export interface AnalysisStreamEvent {
  stage: string;
  progress: number;
  message: string;
  counters: Record<string, unknown>;
}

export function isAnalysisStreamEvent(value: unknown): value is AnalysisStreamEvent {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.stage === "string" &&
    typeof v.progress === "number" &&
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

// ---- Ops (M4) ----

/**
 * PLACEHOLDER — best-effort, hand-derived, like the rest of this file.
 *
 * docs/09-API-CONTRACT.md documents `/api/ops/queues`, `/api/ops/dead-letters`,
 * and `/api/ops/dead-letters/{id}/retry` by one-line description only
 * ("Depth per queue", "Failed messages", "Republish") — it does not specify a
 * JSON shape. These are inferred from docs/01's queue topology (one durable
 * queue per worker, one paired `dlq.<name>`) and docs/09's generic
 * list-endpoint convention (`{items, next_cursor}`). Re-check against the
 * generated schema once `/api/ops/*` exists on the backend.
 */
export interface QueueDepth {
  name: string;
  depth: number;
  consumers?: number;
}

export interface QueuesResponse {
  queues: QueueDepth[];
}

/** Mirrors docs/01's `StageMessage` envelope — the payload a dead-lettered
 * message actually carries, for context alongside the failure. */
export interface DeadLetterMessage {
  analysis_id?: string;
  tenant_id?: string;
  stage?: string;
  storage_ref?: string | null;
  source_type?: string | null;
  attempt?: number;
  emitted_at?: string;
}

export interface DeadLetter {
  id: string;
  queue: string;
  error: string;
  attempts: number;
  failed_at: string;
  message?: DeadLetterMessage;
}

export interface DeadLettersResponse {
  items: DeadLetter[];
  next_cursor: string | null;
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
export interface IncidentListItem {
  id: string;
  title: string;
  severity: Severity;
  fused_score: number;
  disposition: Disposition | null;
  citation_valid: boolean | null;
  mitre_techniques: string[];
  entity_count: number;
  signal_count: number;
  recurrence_of: string | null;
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

/** docs/02 `triage_verdicts.narrative` — `[{step, claim, evidence_event_ids}]` */
export interface NarrativeStep {
  step: number;
  claim: string;
  evidence_event_ids: number[];
}

/** docs/07's output schema, `recommended_actions[]` */
export interface RecommendedAction {
  action: string;
  target: string;
  rationale: string;
}

/** docs/07 "Citation verification" — existence/scope/temporal-plausibility failures recorded
 * here (best-effort field names; docs/07 describes the checks but not the exact JSON keys). */
export interface InvalidCitation {
  step?: number;
  evidence_event_id?: number;
  reason: string;
}

/** docs/07 "Tools" — one entry per tool call in a triage run. */
export interface ToolTraceEntry {
  tool: string;
  arguments: Record<string, unknown>;
  result: unknown;
}

/** docs/02 `triage_verdicts` table. */
export interface TriageVerdictOut {
  id: string;
  incident_id: string;
  disposition: Disposition;
  confidence: number;
  llm_severity_opinion: Severity | null;
  mitre_techniques: MitreTechniqueRef[];
  summary: string;
  narrative: NarrativeStep[];
  contradicting_evidence: string;
  recommended_actions: RecommendedAction[];
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
 * timeline, verdict, plan." `verdict` is `null` for an incident not yet triaged (recurrences
 * inherit their parent's verdict per docs/05, so this can still be non-null there). */
export interface IncidentDetail {
  id: string;
  analysis_id: string;
  title: string;
  severity: Severity;
  fused_score: number;
  status: string;
  entity_ids: number[];
  signal_ids: number[];
  recurrence_of: string | null;
  recurrence_similarity: number | null;
  created_at: string;
  entities: EntityOut[];
  signals: SignalOut[];
  verdict: TriageVerdictOut | null;
}

/** `GET /api/incidents/{id}/timeline` — docs/05 "Timeline", output shape verbatim, plus the
 * extra context fields `app/graph/timeline.py::TimelinePhase` actually carries. */
export interface TimelinePhaseOut {
  ts: string | null;
  tactic: string;
  tactic_is_placeholder?: boolean;
  event_ids: number[];
  summary: string;
  detector_key?: string;
  entity_type?: string;
  entity_value?: string;
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

export interface FeedbackRequest {
  agrees: boolean;
  corrected_disposition?: string;
  corrected_technique?: string;
  dismissal_reason?: string;
  mark_benign_baseline?: boolean;
  note?: string;
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
}

// ---- Response plans (M15) — real schemas, `backend/app/schemas/plans.py` verbatim ----

export interface PreconditionCheckOut {
  id: string;
  satisfied: boolean;
  reason: string;
}
export interface PlanStepOut {
  step: number;
  action_id: string;
  name: string;
  target: string;
  target_type: string;
  preconditions: string[];
  blast_radius: string;
  reversible: boolean;
  rollback: string | null;
  rollback_available: boolean;
  depends_on: string[];
  mitre_mitigation: string;
  rationale: string | null;
  implied: boolean;
  live_preconditions: PreconditionCheckOut[];
}
export interface PlanOut {
  id: string;
  incident_id: string;
  status: string;
  actions: PlanStepOut[];
  verification: Record<string, unknown>;
  approved_by: string | null;
  approved_at: string | null;
  execution_log: Record<string, unknown>[];
  outcome: string | null;
  outcome_detail: Record<string, unknown> | null;
}
export interface JournalEntryOut {
  id: number;
  action_id: string;
  before_state: Record<string, unknown> | null;
  after_state: Record<string, unknown> | null;
  succeeded: boolean;
  precondition_failure: string | null;
  executed_at: string;
}
export interface ApproveResponse {
  plan_id: string;
  status: string;
  halted: boolean;
  journal: JournalEntryOut[];
  outcome: string | null;
  outcome_detail: Record<string, unknown> | null;
}
export interface RestoredResourceOut {
  action_id: string;
  resource_type: string;
  resource_id: string;
  restored_state: Record<string, unknown>;
}
export interface RollbackResponse {
  plan_id: string;
  status: string;
  restored: RestoredResourceOut[];
}
export interface StateDiffEntryOut {
  step: number | null;
  action_id: string;
  target: string;
  resource_type: string;
  resource_id: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  current: Record<string, unknown> | null;
  succeeded: boolean;
  precondition_failure: string | null;
  executed_at: string;
}
export interface StateDiffResponse {
  plan_id: string;
  status: string;
  diff: StateDiffEntryOut[];
}

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
export interface ContainmentSummaryOut {
  contained: number;
  partially_contained: number;
  failed: number;
  total_with_outcome: number;
  rate: number | null;
}
export interface LearningMetricsResponse {
  computed_at: string;
  n_feedback_events: number;
  n_synthetic_feedback_events: number;
  synthetic: boolean;
  alignment_pct: number | null;
  alignment_trend: AlignmentPointOut[];
  detector_precision_trend: DetectorPrecisionPointOut[];
  containment: ContainmentSummaryOut;
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

// ---- Tier 2 (real schemas, `backend/app/schemas/tier2.py` verbatim) ----

export interface IncidentTypeBreakdownOut {
  incident_type: string;
  signature_count: number;
  tenant_count: number;
  avg_confidence: number;
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
export interface Tier2QueryRequest {
  question: string;
}
export type ChartHint = "table" | "bar" | "line" | "number";
export interface Tier2QueryResponse {
  sql: string;
  explanation: string;
  columns: string[];
  rows: unknown[][];
  chart_hint: ChartHint;
  rejected: boolean;
  rejection_reason: string | null;
}

// ---- Events (real schemas, `backend/app/schemas/event.py` verbatim) ----

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
}
export interface EventListResponse {
  items: EventListItem[];
  next_cursor: string | null;
}
export interface EventOut extends EventListItem {
  ocsf: Record<string, unknown>;
  enrichment: Record<string, unknown>;
}
