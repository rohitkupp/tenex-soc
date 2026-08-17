"""Pydantic v2 schemas for docs/09-API-CONTRACT.md's "Tier 2" section."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class IncidentTypeBreakdownOut(BaseModel):
    incident_type: str
    signature_count: int
    tenant_count: int
    avg_confidence: float


class Tier2OverviewResponse(BaseModel):
    total_signatures: int
    total_tenants: int
    total_overlapping_indicators: int
    by_incident_type: list[IncidentTypeBreakdownOut]


class IndicatorOverlapEntryOut(BaseModel):
    indicator_hash: str
    signature_count: int
    tenant_count: int
    incident_types: list[str]
    first_observed_at: datetime
    last_observed_at: datetime


class IndicatorOverlapResponse(BaseModel):
    items: list[IndicatorOverlapEntryOut]


# ---------------------------------------------------------------------------- chart 1: overlap distribution


class OverlapBucketOut(BaseModel):
    """`bucket` is one of `"1"`, `"2"`, `"3+"` — the number of distinct tenants that have
    seen a given indicator signature. The `"2"`/`"3+"` buckets together are the cross-tenant
    signal itself; `"1"` is the (expected) majority of indicators seen by only one tenant."""

    bucket: str
    indicator_count: int


class OverlapDistributionResponse(BaseModel):
    total_indicators: int
    buckets: list[OverlapBucketOut]


# ---------------------------------------------------------------------------- chart 2: technique prevalence


class TechniquePrevalenceEntryOut(BaseModel):
    """One row per allowlisted technique (`data/kb/mitre/allowlist.yml`) — always all 13,
    including ones with `tenant_count == 0`, never a fabricated id."""

    technique_id: str
    technique_name: str
    tenant_count: int
    signature_count: int


class TechniquePrevalenceResponse(BaseModel):
    total_tenants_with_signatures: int
    items: list[TechniquePrevalenceEntryOut]


# ---------------------------------------------------------------------------- chart 3: detector reliability


class DetectorReliabilityEntryOut(BaseModel):
    detector_key: str
    detector_layer: str
    confirmed: int
    dismissed: int


class DetectorReliabilityResponse(BaseModel):
    """`total_tenants` is the count of distinct tenants that have contributed *any* analyst
    feedback, pooled across the whole fleet — see `app.tier2.detector_reliability`."""

    total_tenants: int
    items: list[DetectorReliabilityEntryOut]


# ---------------------------------------------------------------------------- chart 4: first-seen propagation


class FirstSeenTenantObservationOut(BaseModel):
    tenant_hash: str
    first_observed_at: datetime


class FirstSeenIndicatorOut(BaseModel):
    indicator_hash: str
    tenant_count: int
    observations: list[FirstSeenTenantObservationOut]


class FirstSeenResponse(BaseModel):
    items: list[FirstSeenIndicatorOut]
