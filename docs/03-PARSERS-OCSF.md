# 03 — Parsers & OCSF Normalization

## Why OCSF

Detectors operate on the normalized schema, never on vendor fields. Adding a log source means
writing one parser and inheriting every existing detector. That argument goes in the README —
the reviewing team came from Google Chronicle, so also note UDM equivalence where it applies.

## Parser contract

```python
class LogParser(Protocol):
    source_type: str
    ocsf_class_uid: int

    def sniff(self, sample: str) -> float:
        """Confidence 0..1 that this parser handles the sample. Called on first 50 lines."""

    def parse_line(self, line: str, line_no: int) -> OCSFEvent | ParseFailure:
        ...
```

Registry in `parsers/registry.py` runs every `sniff()` and picks the highest score above 0.6.
A single upload may contain multiple source types (mixed export) — detect per-line-block and
fan out to multiple parser queues.

**Track parse failures.** `analyses.parse_failure_rate` is a quality metric, surfaced in the UI.
Do not silently drop malformed lines; record them.

## Event key derivation

Every event gets an `event_key` — a discrete token used by the sequence models (`docs/04` §4).

| Source | `event_key` |
|---|---|
| Okta | `{eventType}:{outcome.result}` — already discrete, ~150 values |
| CloudTrail | `{eventSource}:{eventName}:{errorCode or 'OK'}` |
| ZScaler | `{method}:{urlcategory}:{action}:{status_class}` — Drain3 templating on `url` if needed |

Okta needs no Drain3. ZScaler does, and it is the source where sequence modeling is
**deliberately not applied** — see `docs/04` §4.

## ZScaler NSS Web → OCSF HTTP Activity (4002)

Assume the standard NSS feed format. Tab- or comma-delimited with a header, or JSON lines.

| ZScaler field | OCSF path | Hot column |
|---|---|---|
| `datetime` | `time` | `ts` |
| `user` | `actor.user.email_addr` | `principal` |
| `clientip` | `src_endpoint.ip` | `src_ip` |
| `serverip` | `dst_endpoint.ip` | `dst_ip` |
| `host` | `http_request.url.hostname` | `domain` |
| `url` | `http_request.url.path` | `url_path` |
| `requestmethod` | `http_request.http_method` | `http_method` |
| `status` | `http_response.code` | `status_code` |
| `requestsize` | `traffic.bytes_out` | `bytes_out` |
| `responsesize` | `traffic.bytes_in` | `bytes_in` |
| `useragent` | `http_request.user_agent` | `user_agent` |
| `action` | `activity_name` + `disposition` | `action` |
| `urlcategory` | `http_request.url.category_ids` | — |
| `urlsupercategory` | `unmapped.url_supercategory` | — |
| `appname` / `appclass` | `unmapped.app_*` | — |
| `threatname` | `malware[].name` | — |
| `threatcategory` | `malware[].classification_ids` | — |
| `riskscore` | `risk_score` | — |
| `reason` | `unmapped.block_reason` | — |
| `referer` | `http_request.referrer` | — |
| `dlpengine` / `dlpdictionaries` | `unmapped.dlp_*` | — |
| `location` / `department` | `actor.user.groups` | — |

`action` normalization: `Allowed → allowed`, `Blocked → blocked`, everything else → `other`.

## Okta System Log → OCSF Authentication (3002)

Input is JSON Lines from the `/api/v1/logs` export.

| Okta field | OCSF path | Hot column |
|---|---|---|
| `published` | `time` | `ts` |
| `eventType` | `activity_name` | — |
| `outcome.result` | `status` | `action` |
| `outcome.reason` | `status_detail` | — |
| `actor.alternateId` | `actor.user.email_addr` | `principal` |
| `actor.displayName` | `actor.user.name` | — |
| `client.ipAddress` | `src_endpoint.ip` | `src_ip` |
| `client.userAgent.rawUserAgent` | `http_request.user_agent` | `user_agent` |
| `client.geographicalContext.country` | `src_endpoint.location.country` | — |
| `client.geographicalContext.city` | `src_endpoint.location.city` | — |
| `client.geographicalContext.geolocation` | `src_endpoint.location.coordinates` | — |
| `securityContext.asNumber` | `src_endpoint.autonomous_system.number` | — |
| `securityContext.isProxy` | `unmapped.is_proxy` | — |
| `authenticationContext.authenticationStep` | `auth_protocol` | — |
| `target[]` | `resources[]` | — |
| `debugContext.debugData` | `unmapped.debug` | — |

Event types that matter for detection — make sure these survive normalization intact:
`user.session.start`, `user.authentication.auth_via_mfa`, `user.mfa.factor.deactivate`,
`user.mfa.factor.activate`, `user.account.lock`, `system.api_token.create`,
`user.account.privilege.grant`, `policy.lifecycle.update`, `user.session.impersonation.initiate`.

## AWS CloudTrail → OCSF API Activity (6003)

| CloudTrail field | OCSF path | Hot column |
|---|---|---|
| `eventTime` | `time` | `ts` |
| `eventName` | `api.operation` | — |
| `eventSource` | `api.service.name` | — |
| `userIdentity.arn` | `actor.user.uid` | `principal` |
| `userIdentity.type` | `actor.user.type` | — |
| `sourceIPAddress` | `src_endpoint.ip` | `src_ip` |
| `userAgent` | `http_request.user_agent` | `user_agent` |
| `errorCode` | `status_code` | `status_code` |
| `awsRegion` | `cloud.region` | — |
| `requestParameters` | `api.request.data` | — |
| `responseElements` | `api.response.data` | — |

CloudTrail exists mainly to prove the parser interface generalizes. Keep it thin — do not build
CloudTrail-specific detectors beyond what the shared rules cover.

## Enrichment

Runs after parse, before anonymization, so enrichment sees real values.

| Input | Enrichment | Source |
|---|---|---|
| `src_ip` / `dst_ip` | ASN, org, country, hosting-provider flag | offline MaxMind GeoLite2 + ASN db in `data/enrichment/` |
| `domain` | registrable domain, TLD risk tier, registrar, age in days | offline top-sites list + TLD risk table; domain age from a bundled snapshot |
| `user_agent` | family, is_browser, is_automation_tool | `ua-parser` |
| all | tag bank match | `data/tags/tag_bank.yml` |

Newly-registered domain (age < 30 days) is a strong C2 indicator — surface it as a first-class
enrichment flag, not buried in JSON.

Write results to `events.enrichment`. Do not make network calls at runtime; everything is offline
datasets bundled in the image so the demo works without external dependencies.
