"""AWS CloudTrail emitter (docs/03 "AWS CloudTrail -> OCSF API Activity (6003)").

Deliberately the thin one. docs/03 says CloudTrail earns its slot by proving the parser
interface generalizes to a third vendor shape, not by carrying detectors of its own, so this
module emits the eleven fields that mapping table names and stops. No session context, no
resource blocks, no data-event richness that nothing downstream reads.

Output is JSON Lines rather than the `{"Records": [...]}` envelope AWS delivers: the parser
contract is `parse_line(line, line_no)` and ground truth is line numbers, so one record per
line is the only shape that can be labelled.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, ClassVar

from ..org import User
from ..rng import SeededRandom, stable_hash
from ..types import BenignContext, EventRecord, ScenarioContext, SourceType

__all__ = [
    "AUTOMATION_OPERATIONS",
    "HUMAN_OPERATIONS",
    "ApiOperation",
    "CloudTrailEmitter",
]


@dataclass(frozen=True, slots=True)
class ApiOperation:
    """One `(eventSource, eventName)` pair and its share of a principal's API traffic."""

    event_source: str
    event_name: str
    weight: float


# Automation is read-heavy object storage plus the telemetry and credential calls every agent
# makes. This mix is what the sequence models will see as the normal machine vocabulary.
AUTOMATION_OPERATIONS: tuple[ApiOperation, ...] = (
    ApiOperation("s3.amazonaws.com", "GetObject", 26.0),
    ApiOperation("s3.amazonaws.com", "PutObject", 14.0),
    ApiOperation("s3.amazonaws.com", "ListObjectsV2", 8.0),
    ApiOperation("s3.amazonaws.com", "HeadObject", 6.0),
    ApiOperation("sts.amazonaws.com", "AssumeRole", 7.0),
    ApiOperation("logs.amazonaws.com", "PutLogEvents", 10.0),
    ApiOperation("logs.amazonaws.com", "CreateLogStream", 2.0),
    ApiOperation("monitoring.amazonaws.com", "PutMetricData", 6.0),
    ApiOperation("ec2.amazonaws.com", "DescribeInstances", 5.0),
    ApiOperation("secretsmanager.amazonaws.com", "GetSecretValue", 3.0),
    ApiOperation("kms.amazonaws.com", "Decrypt", 4.0),
    ApiOperation("dynamodb.amazonaws.com", "Query", 3.0),
    ApiOperation("lambda.amazonaws.com", "Invoke", 3.0),
    ApiOperation("ecr.amazonaws.com", "GetAuthorizationToken", 2.0),
)

# People drive the console: overwhelmingly Describe/List/Get, with the occasional session.
HUMAN_OPERATIONS: tuple[ApiOperation, ...] = (
    ApiOperation("signin.amazonaws.com", "ConsoleLogin", 6.0),
    ApiOperation("sts.amazonaws.com", "GetCallerIdentity", 8.0),
    ApiOperation("ec2.amazonaws.com", "DescribeInstances", 12.0),
    ApiOperation("ec2.amazonaws.com", "DescribeSecurityGroups", 5.0),
    ApiOperation("s3.amazonaws.com", "ListBuckets", 7.0),
    ApiOperation("s3.amazonaws.com", "GetObject", 10.0),
    ApiOperation("s3.amazonaws.com", "GetBucketPolicy", 3.0),
    ApiOperation("logs.amazonaws.com", "FilterLogEvents", 9.0),
    ApiOperation("cloudformation.amazonaws.com", "DescribeStacks", 5.0),
    ApiOperation("rds.amazonaws.com", "DescribeDBInstances", 4.0),
    ApiOperation("iam.amazonaws.com", "ListRoles", 3.0),
    ApiOperation("iam.amazonaws.com", "GetUser", 2.0),
    ApiOperation("lambda.amazonaws.com", "ListFunctions", 3.0),
    ApiOperation("ssm.amazonaws.com", "StartSession", 2.0),
)

_AUTOMATION_WEIGHTS: tuple[float, ...] = tuple(o.weight for o in AUTOMATION_OPERATIONS)
_HUMAN_WEIGHTS: tuple[float, ...] = tuple(o.weight for o in HUMAN_OPERATIONS)

# A non-zero baseline error rate is deliberate. If every benign call succeeded, `errorCode` would
# be a perfect discriminator and the `{eventSource}:{eventName}:{errorCode}` event key would make
# any failed-call scenario trivially detectable.
_HUMAN_ERRORS: tuple[tuple[str, float], ...] = (
    ("AccessDenied", 5.0),
    ("UnauthorizedOperation", 2.0),
    ("ValidationException", 1.0),
    ("NoSuchEntity", 1.0),
)
_AUTOMATION_ERRORS: tuple[tuple[str, float], ...] = (
    ("ThrottlingException", 4.0),
    ("AccessDenied", 2.0),
    ("NoSuchKey", 2.0),
    ("ExpiredToken", 1.0),
)
_HUMAN_ERROR_RATE = 0.025
_AUTOMATION_ERROR_RATE = 0.012

_REGION_BY_COUNTRY: dict[str, str] = {
    "US": "us-east-1",
    "IE": "eu-west-1",
    "GB": "eu-west-2",
    "DE": "eu-central-1",
    "SG": "ap-southeast-1",
    "IN": "ap-south-1",
    "AU": "ap-southeast-2",
    "JP": "ap-northeast-1",
    "CA": "ca-central-1",
}
_REGIONS: tuple[str, ...] = (
    "us-east-1",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-1",
    "ap-northeast-1",
)
_OFF_REGION_RATE = 0.12

_ROLE_BY_DEPARTMENT: dict[str, str] = {
    "Engineering": "Developer",
    "IT": "PlatformAdmin",
    "Security": "SecurityAudit",
    "Operations": "Operator",
    "Finance": "BillingReadOnly",
}
_DEFAULT_ROLE = "ReadOnly"

# Departments whose people plausibly hold console access at all. Combined with the org's own
# `saas_apps` assignment this keeps the CloudTrail principal set a realistic minority.
_CLOUD_DEPARTMENTS = frozenset({"Engineering", "IT", "Security", "Operations", "Product"})
_AWS_APP_NAME = "AWS Console"

# Automation outweighs people by roughly an order of magnitude, which is what a real management
# event trail looks like. Not further, though: a human console baseline thin enough to vanish
# would let any people-driven scenario stand out on principal identity alone.
_SERVICE_AWS_WEIGHT = 1.0
_SERVICE_OTHER_WEIGHT = 0.12
_HUMAN_WEIGHT = 0.25
_DEFAULT_INTERVAL_S = 300
_BUCKET_SUFFIXES = ("data", "logs", "artifacts", "backups", "reports")


@dataclass(frozen=True, slots=True)
class _Identity:
    """The AWS-side identity of a principal. A pure function of the `User`, never of the RNG."""

    account_id: str
    arn: str
    identity_type: str
    user_name: str
    role: str
    home_region: str
    buckets: tuple[str, ...]

    @property
    def assumed_role_arn(self) -> str:
        return f"arn:aws:sts::{self.account_id}:assumed-role/{self.role}/{self.user_name}"


def _account_id(email_domain: str) -> str:
    """Twelve digits from the org's mail domain.

    Derived from the domain rather than the seed so that a scenario-crafted event and the benign
    corpus agree on the account without threading the whole `Org` through the event builder.
    """
    return f"{stable_hash(f'aws-account|{email_domain}') % 1_000_000_000_000:012d}"


def _role_for(user: User) -> str:
    """Each service account gets its own role rather than a shared admin one.

    Otherwise every benign `AssumeRole` in the corpus targets the same privileged role and a
    privilege-escalation rule has no baseline left to stand out against.
    """
    if user.is_service_account:
        return f"{user.username}-role"
    return _ROLE_BY_DEPARTMENT.get(user.department, _DEFAULT_ROLE)


def _identity_for(user: User) -> _Identity:
    domain = user.email.rpartition("@")[2]
    account = _account_id(domain)
    slug = domain.partition(".")[0]
    role = _role_for(user)
    if user.is_service_account:
        arn = f"arn:aws:iam::{account}:user/{user.username}"
        identity_type = "IAMUser"
    else:
        arn = f"arn:aws:sts::{account}:assumed-role/{role}/{user.username}"
        identity_type = "AssumedRole"
    return _Identity(
        account_id=account,
        arn=arn,
        identity_type=identity_type,
        user_name=user.username,
        role=role,
        home_region=_REGION_BY_COUNTRY.get(user.office.country, "us-east-1"),
        buckets=tuple(f"{slug}-{s}" for s in _BUCKET_SUFFIXES),
    )


class CloudTrailEmitter:
    """`LogEmitter` for AWS CloudTrail management events.

    Benign volume is dominated by service accounts, matching the org model: twelve machine
    principals on fixed schedules plus a minority of engineers clicking through the console.
    That ratio is the point — regular-interval automation against cloud APIs is the false
    positive every cloud detector has to survive.
    """

    source: ClassVar[SourceType] = SourceType.CLOUDTRAIL
    file_suffix: ClassVar[str] = ".jsonl"
    event_version: ClassVar[str] = "1.09"

    def __init__(self, *, account_id: str | None = None) -> None:
        self.account_id = account_id

    def header(self) -> str | None:
        return None

    # ---------------------------------------------------------------- benign

    def generate_benign(self, ctx: BenignContext) -> Iterator[EventRecord]:
        """Yield roughly `ctx.n_events` records, one principal's stream at a time."""
        for user, count in self._allocate(ctx):
            rng = ctx.user_rng(user)
            identity = self._identity(user)
            if user.is_service_account:
                yield from self._service_stream(ctx, user, identity, rng, count)
            else:
                yield from self._human_stream(ctx, user, identity, rng, count)

    def _allocate(self, ctx: BenignContext) -> list[tuple[User, int]]:
        """Split the event budget over the principals that touch AWS, in org order."""
        if ctx.n_events <= 0:
            return []
        pool: list[tuple[User, float]] = []
        for user in ctx.org.principals:
            weight = self._cloud_weight(user)
            if weight > 0.0:
                pool.append((user, weight))
        total = sum(w for _, w in pool)
        if total <= 0.0:
            return []
        budget = [(u, round(ctx.n_events * w / total)) for u, w in pool]
        return [(u, n) for u, n in budget if n > 0]

    @staticmethod
    def _cloud_weight(user: User) -> float:
        if user.is_service_account:
            uses_aws = _AWS_APP_NAME in user.saas_apps
            factor = _SERVICE_AWS_WEIGHT if uses_aws else _SERVICE_OTHER_WEIGHT
            return user.activity_weight * factor
        if user.department in _CLOUD_DEPARTMENTS and _AWS_APP_NAME in user.saas_apps:
            return user.activity_weight * _HUMAN_WEIGHT
        return 0.0

    def _service_stream(
        self, ctx: BenignContext, user: User, identity: _Identity, rng: SeededRandom, count: int
    ) -> Iterator[EventRecord]:
        """Fixed-cadence ticks, several calls per tick — the machine signature the org promises."""
        interval = float(user.interval_s or _DEFAULT_INTERVAL_S)
        n_ticks = max(1, int(ctx.window.duration_s // interval))
        # Fit the budget to the schedule without breaking periodicity: batch calls into each tick
        # when there are more events than ticks, otherwise skip whole ticks. Skipping multiplies
        # the observed period by `stride` — still perfectly regular, which is the property the
        # account is here to contribute.
        if count >= n_ticks:
            per_tick, stride = -(-count // n_ticks), 1
        else:
            per_tick, stride = 1, -(-n_ticks // count)

        phase = rng.uniform(0.0, interval)
        emitted = 0
        tick = 0
        while tick < n_ticks and emitted < count:
            offset = phase + tick * interval + rng.uniform(-interval * 0.03, interval * 0.03)
            base = ctx.window.offset(offset)
            for step in range(per_tick):
                if emitted >= count:
                    break
                ts = ctx.window.clamp(base + timedelta(seconds=step * rng.uniform(0.4, 2.5)))
                yield self._benign_event(user, identity, ts, rng, automation=True)
                emitted += 1
            tick += stride

    def _human_stream(
        self, ctx: BenignContext, user: User, identity: _Identity, rng: SeededRandom, count: int
    ) -> Iterator[EventRecord]:
        for ts in ctx.models.diurnal.sample_timestamps(
            rng, ctx.window.start, ctx.window.end, user.work_hours, count
        ):
            yield self._benign_event(user, identity, ts, rng, automation=False)

    def _benign_event(
        self,
        user: User,
        identity: _Identity,
        ts: datetime,
        rng: SeededRandom,
        *,
        automation: bool,
    ) -> EventRecord:
        if automation:
            op = rng.weighted_choice(AUTOMATION_OPERATIONS, _AUTOMATION_WEIGHTS)
            errors, error_rate = _AUTOMATION_ERRORS, _AUTOMATION_ERROR_RATE
        else:
            op = rng.weighted_choice(HUMAN_OPERATIONS, _HUMAN_WEIGHTS)
            errors, error_rate = _HUMAN_ERRORS, _HUMAN_ERROR_RATE
        error_code = (
            rng.weighted_choice([c for c, _ in errors], [w for _, w in errors])
            if rng.chance(error_rate)
            else None
        )
        return self.build_event(
            user=user,
            ts=ts,
            event_name=op.event_name,
            event_source=op.event_source,
            rng=rng,
            error_code=error_code,
        )

    # ---------------------------------------------------------------- scenario API

    def build_event(
        self,
        *,
        user: User,
        ts: datetime,
        event_name: str,
        event_source: str,
        rng: SeededRandom,
        region: str | None = None,
        src_ip: str | None = None,
        user_agent: str | None = None,
        error_code: str | None = None,
        request_parameters: Mapping[str, Any] | None = None,
        response_elements: Mapping[str, Any] | None = None,
    ) -> EventRecord:
        """Assemble one CloudTrail record. The single place `fields` is constructed.

        Scenarios call this to craft an event, then hand it to `ScenarioContext.add` (or use
        `inject`, which does both). Anything left `None` is synthesized from the principal.
        """
        identity = self._identity(user)
        if region is None:
            region = rng.choice(_REGIONS) if rng.chance(_OFF_REGION_RATE) else identity.home_region
        if src_ip is None:
            src_ip = user.source_ip(rng)
        if request_parameters is None:
            request_parameters = _request_parameters(event_name, identity, user, rng)
        if response_elements is None:
            response_elements = _response_elements(event_name, identity, error_code)

        # Whole seconds, because `eventTime` has one-second resolution. Truncating here rather
        # than at serialization keeps EventRecord.ts and the emitted line exactly equal, so the
        # parser round-trip test can compare them directly.
        ts = ts.replace(microsecond=0)

        fields: dict[str, Any] = {
            "eventVersion": self.event_version,
            "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": event_source,
            "eventName": event_name,
            "awsRegion": region,
            "sourceIPAddress": src_ip,
            "userAgent": user_agent if user_agent is not None else user.device.user_agent,
            "userIdentity": {
                "type": identity.identity_type,
                "arn": identity.arn,
                "accountId": identity.account_id,
                "userName": identity.user_name,
            },
            "requestParameters": dict(request_parameters) if request_parameters else None,
            "responseElements": dict(response_elements) if response_elements else None,
        }
        # Real CloudTrail omits the key entirely on success; `errorCode or 'OK'` in the event-key
        # derivation (docs/03) is written against exactly that absence.
        if error_code is not None:
            fields["errorCode"] = error_code
        fields["eventID"] = rng.uuid()

        # `principal` stays the email even though the line carries the ARN: it is the generator's
        # cross-source join key and what `ScenarioContext.benign_for` matches on. The ARN embeds
        # the username, so the parser can still resolve the same person from the line alone.
        return EventRecord(
            ts=ts,
            source=self.source,
            principal=user.principal,
            fields=fields,
            src_ip=src_ip,
        )

    def inject(
        self,
        ctx: ScenarioContext,
        *,
        user: User,
        ts: datetime,
        event_name: str,
        event_source: str,
        malicious: bool = True,
        rng: SeededRandom | None = None,
        **kwargs: Any,
    ) -> EventRecord:
        """Build a crafted event and append it to the scenario's stream in one call."""
        record = self.build_event(
            user=user,
            ts=ts,
            event_name=event_name,
            event_source=event_source,
            rng=rng if rng is not None else ctx.user_rng(user),
            **kwargs,
        )
        return ctx.add(record, malicious=malicious)

    @staticmethod
    def line_numbers(records: Sequence[EventRecord]) -> list[int]:
        """Where injected records landed in the file. Valid only after `assign_line_numbers`."""
        if any(r.line_no is None for r in records):
            raise ValueError("line numbers are stamped by assign_line_numbers; call it first")
        return sorted(r.line_no for r in records if r.line_no is not None)

    # ---------------------------------------------------------------- serialization

    def serialize(self, record: EventRecord) -> str:
        return json.dumps(record.fields, separators=(",", ":"))

    def _identity(self, user: User) -> _Identity:
        identity = _identity_for(user)
        if self.account_id is None:
            return identity
        return _Identity(
            account_id=self.account_id,
            arn=identity.arn.replace(f"::{identity.account_id}:", f"::{self.account_id}:"),
            identity_type=identity.identity_type,
            user_name=identity.user_name,
            role=identity.role,
            home_region=identity.home_region,
            buckets=identity.buckets,
        )


def _request_parameters(
    event_name: str, identity: _Identity, user: User, rng: SeededRandom
) -> dict[str, Any] | None:
    """Just enough shape per operation to be recognisable; `api.request.data` is not a hot column."""
    if event_name in {"GetObject", "PutObject", "HeadObject"}:
        bucket = rng.choice(identity.buckets)
        return {"bucketName": bucket, "key": f"{rng.hex_token(3)}/{rng.hex_token(6)}.parquet"}
    if event_name in {"ListObjectsV2", "GetBucketPolicy"}:
        return {"bucketName": rng.choice(identity.buckets)}
    if event_name == "AssumeRole":
        return {
            "roleArn": f"arn:aws:iam::{identity.account_id}:role/{identity.role}",
            "roleSessionName": user.username,
        }
    if event_name == "GetSecretValue":
        return {"secretId": f"{identity.buckets[0]}/{rng.hex_token(4)}"}
    if event_name in {"PutLogEvents", "CreateLogStream", "FilterLogEvents"}:
        return {
            "logGroupName": f"/aws/{user.username}",
            "logStreamName": f"stream-{rng.hex_token(4)}",
        }
    if event_name in {"Invoke", "ListFunctions"}:
        return {"functionName": f"fn-{rng.hex_token(4)}"}
    if event_name in {"DescribeInstances", "DescribeSecurityGroups", "DescribeDBInstances"}:
        return {"maxResults": rng.choice((50, 100, 200))}
    if event_name == "ConsoleLogin":
        return None
    return {}


def _response_elements(
    event_name: str, identity: _Identity, error_code: str | None
) -> dict[str, Any] | None:
    """Null for reads and for anything that failed, which is what CloudTrail actually records."""
    if error_code is not None:
        return None
    if event_name == "ConsoleLogin":
        return {"ConsoleLogin": "Success"}
    if event_name == "AssumeRole":
        role_id = f"AROA{stable_hash(identity.role) % 10**12:012X}"
        return {
            "assumedRoleUser": {
                "arn": identity.assumed_role_arn,
                "assumedRoleId": f"{role_id}:{identity.user_name}",
            }
        }
    return None
