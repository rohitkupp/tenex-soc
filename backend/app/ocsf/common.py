"""Shared OCSF building blocks used by all three event classes (docs/03).

These are the nested objects the docs/03 mapping tables point into — `actor.user.email_addr`,
`src_endpoint.location.country`, `http_request.url.path`, and so on. Every class here is a plain
Pydantic v2 model with every field optional, because a single source only ever populates a subset
(ZScaler never touches `api.*`; CloudTrail never touches `http_response.*`) and the parser must be
free to leave the rest at their defaults rather than inventing values.

Two deliberate simplifications versus the full OCSF taxonomy, both because a byte-for-byte OCSF
implementation needs lookup tables this project does not ship:

* `Url.category_ids` holds the vendor's own category *name* (ZScaler's `urlcategory`), not a real
  OCSF URL Category enum id — there is no bundled category-name -> OCSF-id mapping table. Kept as
  `list[str]` rather than `list[int]` so the value stays honest about what it actually is.
* `Malware.classification_ids` holds ZScaler's own `threatcategory` string, for the same reason.

Both are still exactly what docs/03's tables ask for ("urlcategory -> http_request.url.category_ids",
"threatcategory -> malware[].classification_ids") — just carrying the source's native identifier
instead of a taxonomy id nobody supplied.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class User(BaseModel):
    """`actor.user` — docs/03 populates a different subset of this per source.

    ZScaler/Okta identify a principal by email (`email_addr`); CloudTrail identifies one by ARN
    (`uid`) instead — docs/03's CloudTrail table maps `userIdentity.arn -> actor.user.uid`, not
    `email_addr`. Both fields exist here so each parser sets the one its source actually has.
    """

    model_config = ConfigDict(extra="forbid")

    email_addr: str | None = None
    name: str | None = None
    uid: str | None = None
    type: str | None = None
    groups: list[str] = Field(default_factory=list)


class Actor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user: User = Field(default_factory=User)


class GeoCoordinates(BaseModel):
    """`src_endpoint.location.coordinates` — from Okta's `geographicalContext.geolocation`."""

    model_config = ConfigDict(extra="forbid")

    lat: float | None = None
    lon: float | None = None


class Location(BaseModel):
    model_config = ConfigDict(extra="forbid")

    country: str | None = None
    city: str | None = None
    coordinates: GeoCoordinates | None = None


class AutonomousSystem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    number: int | None = None


class NetworkEndpoint(BaseModel):
    """`src_endpoint` / `dst_endpoint`."""

    model_config = ConfigDict(extra="forbid")

    ip: str | None = None
    location: Location | None = None
    autonomous_system: AutonomousSystem | None = None


class Url(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str | None = None
    path: str | None = None
    category_ids: list[str] = Field(default_factory=list)


class HttpRequest(BaseModel):
    """`http_request` — every source that carries a user agent uses this, not just ZScaler."""

    model_config = ConfigDict(extra="forbid")

    url: Url | None = None
    http_method: str | None = None
    user_agent: str | None = None
    referrer: str | None = None


class HttpResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: int | None = None


class Traffic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bytes_out: int | None = None
    bytes_in: int | None = None


class Malware(BaseModel):
    """One entry of `malware[]` — ZScaler's `threatname` / `threatcategory` pair."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    classification_ids: list[str] = Field(default_factory=list)


class Resource(BaseModel):
    """One entry of `resources[]` — Okta's `target[]`."""

    model_config = ConfigDict(extra="forbid")

    type: str | None = None
    uid: str | None = None
    name: str | None = None


class ApiService(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None


class Api(BaseModel):
    """`api.*` — CloudTrail's `eventName` / `eventSource` / request & response bodies."""

    model_config = ConfigDict(extra="forbid")

    operation: str | None = None
    service: ApiService | None = None
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None


class Cloud(BaseModel):
    model_config = ConfigDict(extra="forbid")

    region: str | None = None
