import type {
  AutoencoderExplanationPayload,
  BeaconingExplanationPayload,
  BurstExplanationPayload,
  DGAExplanationPayload,
  PerFeatureContributionExplanation,
  RarityExplanationPayload,
  SigmaExplanationPayload,
  SignalOut,
  STLExplanationPayload,
  UrlPathExplanationPayload,
} from "@/lib/api/types";
import { AutoencoderExplanation } from "./AutoencoderExplanation";
import { BeaconingExplanation } from "./BeaconingExplanation";
import { BurstExplanation } from "./BurstExplanation";
import { DGAExplanation } from "./DGAExplanation";
import { FallbackExplanation } from "./FallbackExplanation";
import { PerFeatureBars } from "./PerFeatureBars";
import { RarityExplanation } from "./RarityExplanation";
import { SigmaExplanation } from "./SigmaExplanation";
import { STLExplanation } from "./STLExplanation";
import { UrlPathExplanation } from "./UrlPathExplanation";

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}
function hasKeys(v: Record<string, unknown>, keys: string[]): boolean {
  return keys.every((k) => k in v);
}

/**
 * Dispatches an incident signal's structured `explanation` to a labelled, detector-specific
 * view. Primary dispatch is on `detector_key` (authoritative — the same string
 * `app/detection/**` writes to `signals.detector_key`, docs/02); a shape-sniffing fallback
 * covers any detector this component doesn't explicitly know about, and the last resort is
 * `FallbackExplanation`'s flattened key/value view. **No path here ever renders raw JSON**
 * (docs/13 M15 acceptance criterion) — every branch is a labelled view of some kind.
 *
 * The prop only requires the three fields this component actually reads, not the full
 * `SignalOut` — `SignalOut` satisfies it structurally, and so does `EventSignalOut`
 * (`GET /api/events/{event_id}`'s narrower per-event signal shape), so the same renderer
 * serves both the case file's `SignalsSection` and `EventInspector`'s "why flagged" view.
 */
export function ExplanationRenderer({
  signal,
}: {
  signal: Pick<SignalOut, "detector_key" | "detector_layer" | "explanation">;
}) {
  const { detector_key: key, detector_layer: layer, explanation } = signal;

  if (!isRecord(explanation)) {
    return <FallbackExplanation explanation={explanation} detectorKey={key} />;
  }

  switch (key) {
    case "ml.autoencoder":
      return <AutoencoderExplanation explanation={explanation as unknown as AutoencoderExplanationPayload} />;
    case "ml.iforest":
      return <PerFeatureBars explanation={explanation as unknown as PerFeatureContributionExplanation} flavor="iforest" />;
    case "ml.mahalanobis":
      return <PerFeatureBars explanation={explanation as unknown as PerFeatureContributionExplanation} flavor="mahalanobis" />;
    case "ml.ecod":
      return <PerFeatureBars explanation={explanation as unknown as PerFeatureContributionExplanation} flavor="ecod" />;
    case "ml.peer_group":
      return <PerFeatureBars explanation={explanation as unknown as PerFeatureContributionExplanation} flavor="lof" />;
    case "signal.beaconing":
      return <BeaconingExplanation explanation={explanation as unknown as BeaconingExplanationPayload} />;
    case "signal.dga":
      return <DGAExplanation explanation={explanation as unknown as DGAExplanationPayload} />;
    case "signal.stl_residual":
      return <STLExplanation explanation={explanation as unknown as STLExplanationPayload} />;
    case "signal.burst":
      return <BurstExplanation explanation={explanation as unknown as BurstExplanationPayload} />;
    case "signal.rarity":
      return <RarityExplanation explanation={explanation as unknown as RarityExplanationPayload} />;
    case "signal.url_path_entropy":
      return <UrlPathExplanation explanation={explanation as unknown as UrlPathExplanationPayload} />;
    default:
      break;
  }

  if (layer === "rule" || key.startsWith("sigma.")) {
    return <SigmaExplanation explanation={explanation as unknown as SigmaExplanationPayload} />;
  }

  // Shape-sniffing fallback — a forward-compatible net for a detector_key this component
  // doesn't explicitly list yet (e.g. a future graph-layer classifier), matched on the
  // payload's own structure rather than a name.
  if (typeof explanation.total_recon_error === "number" && Array.isArray(explanation.per_feature)) {
    return <AutoencoderExplanation explanation={explanation as unknown as AutoencoderExplanationPayload} />;
  }
  if (hasKeys(explanation, ["mean_interval", "cv", "dominant_period_s"])) {
    return <BeaconingExplanation explanation={explanation as unknown as BeaconingExplanationPayload} />;
  }
  if (hasKeys(explanation, ["seasonal_component", "residual_z", "period_used"])) {
    return <STLExplanation explanation={explanation as unknown as STLExplanationPayload} />;
  }
  if (hasKeys(explanation, ["shannon_entropy", "weights", "decision_threshold"])) {
    return <DGAExplanation explanation={explanation as unknown as DGAExplanationPayload} />;
  }
  if (hasKeys(explanation, ["bucket_start", "median", "mad"])) {
    return <BurstExplanation explanation={explanation as unknown as BurstExplanationPayload} />;
  }
  if (hasKeys(explanation, ["domain_rarity", "org_wide_event_count"])) {
    return <RarityExplanation explanation={explanation as unknown as RarityExplanationPayload} />;
  }
  if (hasKeys(explanation, ["mean_path_entropy", "segment_random_ratio"])) {
    return <UrlPathExplanation explanation={explanation as unknown as UrlPathExplanationPayload} />;
  }
  if (hasKeys(explanation, ["rule_id", "condition", "logsource"])) {
    return <SigmaExplanation explanation={explanation as unknown as SigmaExplanationPayload} />;
  }
  if (typeof explanation.total_score === "number" && Array.isArray(explanation.per_feature)) {
    return <PerFeatureBars explanation={explanation as unknown as PerFeatureContributionExplanation} flavor="tree" />;
  }

  return <FallbackExplanation explanation={explanation} detectorKey={key} />;
}
