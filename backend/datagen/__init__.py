"""Synthetic log generator (docs/11).

Reproducible from a seed, end to end. The public surface below is the contract emitters,
scenarios, the CLI and the eval harness code against.

    from datagen import Org, SeededRandom, TimeWindow, merge_streams, assign_line_numbers

    org = Org(seed=42)
    rng = SeededRandom(42).substream("benign")
    window = TimeWindow.of_days(14)

`datagen.scenarios` is deliberately not imported here: importing it runs scenario discovery,
and scenario modules import from this package.
"""

from __future__ import annotations

from .org import (
    DEFAULT_DEPARTMENTS,
    DEFAULT_SAAS_APPS,
    SERVICE_ACCOUNT_CATALOG,
    DeviceFingerprint,
    Org,
    SaasApp,
    ServiceAccountSpec,
    User,
)
from .realism import (
    AUTOMATION_AGENTS,
    DATA_DIR,
    DEFAULT_OFFICE_CODES,
    FOREIGN_LOCATIONS,
    HOSTING_ASNS,
    OFFICE_CATALOG,
    RESIDENTIAL_ASNS,
    DGAGenerator,
    DiurnalCurve,
    DomainPopularity,
    GeoDistribution,
    GeoPoint,
    NewlyRegisteredDomainPool,
    Office,
    RealismModels,
    RegisteredDomain,
    ResponseSizeModel,
    UserAgentMix,
    UserAgentSpec,
    WorkHours,
    build_models,
    haversine_km,
)
from .rng import SeededRandom, derive_seed, stable_hash
from .types import (
    DETECTOR_KEYS,
    BenignContext,
    Disposition,
    EntityRef,
    EntityType,
    EventRecord,
    GroundTruth,
    LabelSet,
    LogEmitter,
    Scenario,
    ScenarioContext,
    SourceType,
    TimeWindow,
    assign_line_numbers,
    finalize_ground_truth,
    merge_streams,
    sigma_key,
)

__all__ = [
    "AUTOMATION_AGENTS",
    "DATA_DIR",
    "DEFAULT_DEPARTMENTS",
    "DEFAULT_OFFICE_CODES",
    "DEFAULT_SAAS_APPS",
    "DETECTOR_KEYS",
    "FOREIGN_LOCATIONS",
    "HOSTING_ASNS",
    "OFFICE_CATALOG",
    "RESIDENTIAL_ASNS",
    "SERVICE_ACCOUNT_CATALOG",
    "BenignContext",
    "DGAGenerator",
    "DeviceFingerprint",
    "Disposition",
    "DiurnalCurve",
    "DomainPopularity",
    "EntityRef",
    "EntityType",
    "EventRecord",
    "GeoDistribution",
    "GeoPoint",
    "GroundTruth",
    "LabelSet",
    "LogEmitter",
    "NewlyRegisteredDomainPool",
    "Office",
    "Org",
    "RealismModels",
    "RegisteredDomain",
    "ResponseSizeModel",
    "SaasApp",
    "Scenario",
    "ScenarioContext",
    "SeededRandom",
    "ServiceAccountSpec",
    "SourceType",
    "TimeWindow",
    "User",
    "UserAgentMix",
    "UserAgentSpec",
    "WorkHours",
    "assign_line_numbers",
    "build_models",
    "derive_seed",
    "finalize_ground_truth",
    "haversine_km",
    "merge_streams",
    "sigma_key",
    "stable_hash",
]
