/**
 * Type aliases for the four Tier 2 cross-tenant learning chart responses
 * (docs/09), re-exported from the generated `schema.d.ts` rather than
 * hand-derived — CLAUDE.md/docs/10: "Types for API responses generated from
 * the OpenAPI schema — do not hand-write them." `lib/api/types.ts` is a
 * pre-existing, explicitly-labeled placeholder (see its own header comment)
 * that predates this file; new response shapes added here go straight to
 * the generated schema instead of growing that placeholder further.
 */
import type { components } from "./schema";

export type OverlapBucketOut = components["schemas"]["OverlapBucketOut"];
export type OverlapDistributionResponse = components["schemas"]["OverlapDistributionResponse"];

export type TechniquePrevalenceEntryOut = components["schemas"]["TechniquePrevalenceEntryOut"];
export type TechniquePrevalenceResponse = components["schemas"]["TechniquePrevalenceResponse"];

export type DetectorReliabilityEntryOut = components["schemas"]["DetectorReliabilityEntryOut"];
export type DetectorReliabilityResponse = components["schemas"]["DetectorReliabilityResponse"];

export type FirstSeenTenantObservationOut = components["schemas"]["FirstSeenTenantObservationOut"];
export type FirstSeenIndicatorOut = components["schemas"]["FirstSeenIndicatorOut"];
export type FirstSeenResponse = components["schemas"]["FirstSeenResponse"];
