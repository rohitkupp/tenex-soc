"""Contracts every emitter, scenario and writer in `datagen` codes against.

Three things live here and nowhere else:

* `EventRecord` — what an emitter produces *before* serialization. Emitters own their line
  format; the rest of the generator only ever handles records.
* `GroundTruth` — the label schema from docs/11, byte-for-byte. The eval harness reads it.
* `Scenario` / `LogEmitter` — the two extension points. Nine modules implement one of them.

The line-number contract is the subtle part. A scenario cannot know the line numbers of the
events it injects, because those are only fixed once its events are merged into the benign
stream and the whole file is sorted by time. So scenarios return a `GroundTruth` with an empty
`malicious_line_numbers`, and the driver calls `finalize_ground_truth` after
`assign_line_numbers`. Any other split makes the label depend on injection order.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, ClassVar, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from .org import Org, User
from .realism import RealismModels
from .rng import SeededRandom

__all__ = [
    "DETECTOR_KEYS",
    "BenignContext",
    "Disposition",
    "EntityRef",
    "EntityType",
    "EventRecord",
    "GroundTruth",
    "LabelSet",
    "LogEmitter",
    "Scenario",
    "ScenarioContext",
    "SourceType",
    "TimeWindow",
    "assign_line_numbers",
    "finalize_ground_truth",
    "merge_streams",
    "sigma_key",
]


class SourceType(StrEnum):
    """Matches `LogParser.source_type` in docs/03 — the value a parser advertises.

    ZScaler is the only member today. Okta and CloudTrail were removed (this project is narrowed
    to ZScaler web proxy logs only); kept as an enum rather than collapsed to a bare string
    constant so a future source is "add one more member here", not a type change at every call
    site that names `SourceType`.
    """

    ZSCALER = "zscaler"


EntityType = Literal["user", "src_ip", "domain", "dst_ip", "asn", "country", "session"]
Disposition = Literal["true_positive", "false_positive", "benign", "needs_review"]


# ---------------------------------------------------------------------------- detector keys

# `signals.detector_key` values (docs/02). Scenario authors put these in `expected_detectors`;
# using the constants rather than string literals is what keeps the eval harness's per-detector
# recall table from silently reporting zero for a typo.
SIGNAL_BEACONING = "signal.beaconing"
SIGNAL_DGA = "signal.dga"
SIGNAL_BURST = "signal.burst"
SIGNAL_RARITY = "signal.rarity"
SIGNAL_NEWLY_REGISTERED = "signal.newly_registered_domain"
SIGNAL_OUT_IN_RATIO = "signal.out_in_ratio"

ML_AUTOENCODER = "ml.autoencoder"
ML_IFOREST = "ml.iforest"
ML_MAHALANOBIS = "ml.mahalanobis"
ML_PEER_GROUP = "ml.peer_group"
ML_LIGHTGBM = "ml.lightgbm"

GRAPH_FAN_OUT = "graph.fan_out"
GRAPH_SHARED_INFRA = "graph.shared_infra"

# The seven ZScaler-only Sigma rules under `app/detection/rules/`. The identity-only and
# cross-source rules (impossible-travel, password-spray, brute-force, okta-mfa-fatigue,
# first-login-new-country, mfa-factor-deactivated, api-token-created-off-hours, privilege-grant,
# and the three xsrc-* rules) were deleted along with Okta.
SIGMA_NON_BROWSER_UA = "sigma.non_browser_user_agent"
SIGMA_LARGE_POST_NRD = "sigma.large_post_to_new_domain"
SIGMA_DIRECT_TO_IP = "sigma.direct_to_ip_request"
SIGMA_CREDS_IN_URL = "sigma.credentials_in_url"
SIGMA_BLOCKED_THEN_ALLOWED = "sigma.blocked_then_allowed"
SIGMA_THREAT_CATEGORY = "sigma.malicious_url_category"

DETECTOR_KEYS: frozenset[str] = frozenset(
    v
    for k, v in dict(globals()).items()
    if k.startswith(("SIGNAL_", "ML_", "GRAPH_", "SIGMA_")) and isinstance(v, str)
)


def sigma_key(rule_id: str) -> str:
    """`detector_key` for a Sigma rule id, e.g. `large-post-to-new-domain` ->
    `sigma.large_post_to_new_domain`."""
    return f"sigma.{rule_id.strip().lower().replace('-', '_')}"


# ---------------------------------------------------------------------------- time


@dataclass(frozen=True, slots=True)
class TimeWindow:
    """The period a corpus or scenario covers. Always timezone-aware UTC."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("TimeWindow bounds must be timezone-aware")
        if self.end <= self.start:
            raise ValueError("TimeWindow end must be after start")

    @classmethod
    def of_days(cls, days: int, *, ending: datetime | None = None) -> TimeWindow:
        """Fixed default end date — `datetime.now()` anywhere in datagen breaks reproducibility."""
        end = ending or datetime(2026, 3, 1, tzinfo=UTC)
        return cls(start=end - timedelta(days=days), end=end)

    @property
    def duration_s(self) -> float:
        return (self.end - self.start).total_seconds()

    @property
    def duration_h(self) -> float:
        return self.duration_s / 3600.0

    @property
    def duration_days(self) -> float:
        return self.duration_s / 86400.0

    def contains(self, ts: datetime) -> bool:
        return self.start <= ts < self.end

    def offset(self, seconds: float) -> datetime:
        return self.start + timedelta(seconds=seconds)

    def fraction(self, f: float) -> datetime:
        """Point `f` of the way through the window; `f=0.5` is the midpoint."""
        return self.start + timedelta(seconds=self.duration_s * f)

    def clamp(self, ts: datetime) -> datetime:
        return min(max(ts, self.start), self.end - timedelta(microseconds=1))

    def subwindow(self, *, start_fraction: float, hours: float) -> TimeWindow:
        """A shorter window inside this one — how a scenario picks its attack period."""
        start = self.fraction(start_fraction)
        end = min(start + timedelta(hours=hours), self.end)
        return TimeWindow(start=start, end=end)


# ---------------------------------------------------------------------------- events


@dataclass(slots=True)
class EventRecord:
    """One log event, pre-serialization.

    `fields` holds the vendor-native record using exactly the field names docs/03 maps from —
    `host`, `requestsize`, `useragent` for ZScaler, the only registered source. Nothing downstream
    of the emitter reinterprets them; the emitter's `serialize` renders them and the real parser
    reads them back. That round trip is the point: if a scenario is not parseable it is not
    detectable, and the eval would be measuring nothing.

    `scenario_id` and `malicious` are generator-side labels. They never appear in the emitted
    line — writing the label into the file would leak the answer into the detectors.
    """

    ts: datetime
    source: SourceType
    principal: str
    fields: dict[str, Any]
    src_ip: str | None = None
    scenario_id: str | None = None
    malicious: bool = False
    tags: tuple[str, ...] = ()
    line_no: int | None = None
    seq: int = 0

    @property
    def sort_key(self) -> tuple[datetime, str, str, int]:
        """Total order for the merged stream. `seq` breaks same-timestamp ties deterministically."""
        return (self.ts, str(self.source), self.principal, self.seq)

    def label(self, scenario_id: str, *, malicious: bool = True) -> EventRecord:
        self.scenario_id = scenario_id
        self.malicious = malicious
        return self


def merge_streams(*streams: Iterable[EventRecord]) -> list[EventRecord]:
    """Concatenate in argument order, assign `seq`, then sort. Deterministic, total, stable."""
    merged: list[EventRecord] = []
    for stream in streams:
        merged.extend(stream)
    for i, record in enumerate(merged):
        record.seq = i
    merged.sort(key=lambda r: r.sort_key)
    return merged


def assign_line_numbers(records: Sequence[EventRecord], *, start: int = 1) -> Sequence[EventRecord]:
    """Stamp 1-based file line numbers. Call once, after merging, before writing."""
    for offset, record in enumerate(records):
        record.line_no = start + offset
    return records


# ---------------------------------------------------------------------------- ground truth


class EntityRef(BaseModel):
    """`{"type": "user", "value": "jdoe@corp.example"}` — the incident's primary entity."""

    model_config = ConfigDict(extra="forbid")

    type: EntityType
    value: str


class GroundTruth(BaseModel):
    """The label for one injected scenario. Schema is docs/11 "Ground truth format", verbatim.

    `must_correlate_into_one_incident` is the field that lets the harness measure incident-level
    recall rather than per-signal recall — whether the graph pulled the events together or
    fragmented them into three alerts a human would have to reassemble.
    """

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    technique: str | None = None
    malicious_line_numbers: list[int] = Field(default_factory=list)
    primary_entity: EntityRef
    expected_detectors: list[str] = Field(default_factory=list)
    expected_disposition: Disposition = "true_positive"
    must_correlate_into_one_incident: bool = True
    notes: str = ""

    def to_json(self, *, indent: int = 2) -> str:
        return self.model_dump_json(indent=indent)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_json(cls, payload: str) -> GroundTruth:
        return cls.model_validate_json(payload)


class LabelSet(BaseModel):
    """Contents of a `.labels.json` file. A demo file carries several scenarios; an eval file one."""

    model_config = ConfigDict(extra="forbid")

    log_file: str
    seed: int
    org_fingerprint: str
    total_lines: int
    window_start: datetime
    window_end: datetime
    scenarios: list[GroundTruth] = Field(default_factory=list)

    def to_json(self, *, indent: int = 2) -> str:
        return self.model_dump_json(indent=indent)

    @classmethod
    def from_json(cls, payload: str) -> LabelSet:
        return cls.model_validate_json(payload)


def finalize_ground_truth(truth: GroundTruth, records: Sequence[EventRecord]) -> GroundTruth:
    """Fill `malicious_line_numbers` from the numbered stream. Idempotent; sorted ascending."""
    truth.malicious_line_numbers = sorted(
        r.line_no
        for r in records
        if r.malicious and r.scenario_id == truth.scenario_id and r.line_no is not None
    )
    return truth


# ---------------------------------------------------------------------------- emitters


@dataclass(slots=True)
class BenignContext:
    """Everything a benign emitter needs. `rng` is already scoped to that emitter's sub-stream."""

    org: Org
    rng: SeededRandom
    window: TimeWindow
    n_events: int

    @property
    def models(self) -> RealismModels:
        return self.org.models

    def user_rng(self, user: User) -> SeededRandom:
        """That user's independent stream. Stable regardless of generation order."""
        return self.rng.substream(user.key)


@runtime_checkable
class LogEmitter(Protocol):
    """One log source: benign traffic generation plus line serialization.

    `serialize` must produce a line the matching parser in `app/parsers/` accepts — the
    generator and the parser are two halves of one contract and are tested against each other.
    """

    source: ClassVar[SourceType]
    file_suffix: ClassVar[str]

    def header(self) -> str | None:
        """First line of the file, if the format has one (ZScaler NSS does; a JSON Lines format
        would not)."""
        ...

    def generate_benign(self, ctx: BenignContext) -> Iterator[EventRecord]:
        """Yield roughly `ctx.n_events` benign records inside `ctx.window`."""
        ...

    def serialize(self, record: EventRecord) -> str:
        """One log line, no trailing newline."""
        ...


# ---------------------------------------------------------------------------- scenarios


@dataclass(slots=True)
class ScenarioContext:
    """Handed to `Scenario.inject`. The scenario appends its events to `stream`.

    `stream` already contains the benign corpus for the window, so a scenario can read it to
    blend in — pick a domain the target already visits, match their usual response sizes — which
    is what `blend_with_normal_traffic` knobs are for.
    """

    org: Org
    rng: SeededRandom
    window: TimeWindow
    stream: list[EventRecord]
    scenario_id: str
    injected: list[EventRecord] = field(default_factory=list)

    @property
    def models(self) -> RealismModels:
        return self.org.models

    def user_rng(self, user: User) -> SeededRandom:
        return self.rng.substream(user.key)

    def add(self, record: EventRecord, *, malicious: bool = True) -> EventRecord:
        """Label, append, and remember. The only sanctioned way to inject an event."""
        record.scenario_id = self.scenario_id
        record.malicious = malicious
        self.stream.append(record)
        self.injected.append(record)
        return record

    def add_many(
        self, records: Iterable[EventRecord], *, malicious: bool = True
    ) -> list[EventRecord]:
        return [self.add(r, malicious=malicious) for r in records]

    def benign_for(self, user: User) -> list[EventRecord]:
        """Existing benign events for one principal — the baseline a scenario blends against."""
        return [r for r in self.stream if r.principal == user.principal and not r.malicious]


class Scenario(ABC):
    """One labeled attack (or deliberate non-attack) injected into a benign stream.

    Subclasses take their difficulty knobs as `__init__` keyword arguments and store them as
    public attributes, so `knobs()` picks them up and `python -m datagen sweep` can vary one by
    name (docs/11 "Parameterization"). A scenario with a single fixed configuration cannot
    produce a detection curve, and a curve is the whole reason the knobs exist.
    """

    key: ClassVar[str]
    technique: ClassVar[str | None] = None
    sources: ClassVar[tuple[SourceType, ...]] = ()
    expected_detectors: ClassVar[tuple[str, ...]] = ()
    expected_disposition: ClassVar[Disposition] = "true_positive"
    must_correlate_into_one_incident: ClassVar[bool] = True
    description: ClassVar[str] = ""

    def knobs(self) -> dict[str, Any]:
        """Public instance attributes — the difficulty settings, for notes and sweep reports."""
        names = getattr(self, "__slots__", None) or vars(self).keys()
        return {
            name: getattr(self, name)
            for name in sorted(names)
            if not name.startswith("_") and hasattr(self, name)
        }

    def instance_id(self, index: int = 1) -> str:
        """`c2_beaconing_001` — the `scenario_id` written into ground truth."""
        return f"{self.key}_{index:03d}"

    def make_ground_truth(
        self,
        ctx: ScenarioContext,
        *,
        primary_entity: EntityRef,
        notes: str = "",
        technique: str | None = None,
        expected_detectors: Sequence[str] | None = None,
        expected_disposition: Disposition | None = None,
        must_correlate_into_one_incident: bool | None = None,
    ) -> GroundTruth:
        """Build the label from class defaults. `malicious_line_numbers` is filled by the driver."""
        knob_note = ", ".join(f"{k}={v}" for k, v in self.knobs().items())
        return GroundTruth(
            scenario_id=ctx.scenario_id,
            technique=technique if technique is not None else self.technique,
            malicious_line_numbers=[],
            primary_entity=primary_entity,
            expected_detectors=list(
                expected_detectors if expected_detectors is not None else self.expected_detectors
            ),
            expected_disposition=(
                expected_disposition
                if expected_disposition is not None
                else self.expected_disposition
            ),
            must_correlate_into_one_incident=(
                must_correlate_into_one_incident
                if must_correlate_into_one_incident is not None
                else self.must_correlate_into_one_incident
            ),
            notes=f"{notes} [{knob_note}]" if notes else knob_note,
        )

    @abstractmethod
    def inject(self, ctx: ScenarioContext) -> GroundTruth:
        """Append events to `ctx.stream` via `ctx.add` and return the label."""
