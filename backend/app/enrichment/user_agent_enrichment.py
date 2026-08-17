"""user_agent -> family, is_browser, is_automation_tool, os_type, os_version
(docs/03-PARSERS-OCSF.md "Enrichment"). Feeds docs/04's L3 `automation_ua_ratio` feature, the L1
Sigma rule "Non-browser user agent (curl, python-requests, powershell, wget)", and (the two OS
fields) the asset-tag bank's useragent-derived OS fallback (docs/11 "derive OS family/version
from useragent" -- `app.graph.asset_tags`).

`ua-parser` (offline, regex-table-driven, no network) resolves most of this on its own, but
two of `datagen`'s own automation user-agent strings (`realism.py: AUTOMATION_AGENTS`) --
`"Datadog Agent/7.59.0"` and a PowerShell UA wrapped in a `Mozilla/5.0 (...)` prefix -- parse
to ua-parser's generic `"Other"` family, because its bundled rule table has no entry for
either literal shape. Rather than accept "Other" (which would make `automation_ua_ratio`
undercount two entire service accounts' worth of legitimate automation traffic),
`AUTOMATION_KEYWORDS` below is a small, explicit keyword fallback: it both classifies
`is_automation_tool` and, when ua-parser gave up, supplies a readable family name. This is
deliberately layered *on top of* ua-parser, never a replacement for it -- ua-parser's
verdict wins whenever it has one.

`os_type`/`os_version` are a **fallback**, not a replacement for an event's own explicit
`device.os` (docs/v1/zscaler-nss-web-fields.md's Client Connector fields, `app.parsers.zscaler`):
this function is a pure transform of `user_agent` alone and has no way to know whether an
explicit device field was already present, so precedence ("prefer the real device field, fall
back to this only when absent") is the caller's job -- `app.graph.asset_tags.compute_asset_tags`
is the one place that precedence is actually applied. Kept here rather than duplicated because the
underlying parse (`ua_parser.parse_os`) is exactly the same offline call this module already makes
for `family` -- computing `os_type`/`os_version` alongside it costs nothing extra and keeps "how do
we read an OS out of a UA string" in one place.
"""

from __future__ import annotations

from dataclasses import dataclass

from ua_parser import OS, parse_os, parse_user_agent

from app.ocsf import normalize_os_type

# ua-parser family names (lowercased) that are unambiguously a human-driven browser, not a
# script/CLI/agent. Deliberately excludes "Other" and anything not in this set.
KNOWN_BROWSER_FAMILIES: frozenset[str] = frozenset(
    {
        "chrome",
        "chrome mobile",
        "chrome mobile ios",
        "chrome mobile webview",
        "chromium",
        "firefox",
        "firefox mobile",
        "firefox ios",
        "safari",
        "mobile safari",
        "mobile safari ui/wkwebview",
        "edge",
        "edge mobile",
        "opera",
        "opera mobile",
        "opera mini",
        "samsung internet",
        "uc browser",
        "vivaldi",
        "brave",
        "ie",
        "ie mobile",
        "internet explorer",
        "yandex browser",
        "silk",
    }
)

# ua-parser family names (lowercased) that are unambiguously a non-browser HTTP client.
AUTOMATION_FAMILIES: frozenset[str] = frozenset(
    {
        "curl",
        "python requests",
        "wget",
        "go-http-client",
        "okhttp",
        "java",
        "aws-cli",
        "rclone",
        "apache-httpclient",
        "axios",
        "libwww-perl",
        "python-urllib",
        "scrapy",
    }
)

# Case-insensitive substring -> canonical family label, checked in order. Covers strings
# ua-parser's bundled table resolves to "Other" (see module docstring) plus a broader set of
# common CLI/scripting/scanning tools for robustness beyond datagen's specific fixtures.
AUTOMATION_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("datadog agent", "Datadog Agent"),
    ("powershell", "PowerShell"),
    ("ansible", "Ansible"),
    ("terraform", "Terraform"),
    ("node-fetch", "node-fetch"),
    ("postman", "Postman"),
    ("insomnia", "Insomnia"),
    ("headlesschrome", "HeadlessChrome"),
    ("phantomjs", "PhantomJS"),
    ("selenium", "Selenium"),
    ("puppeteer", "Puppeteer"),
    ("playwright", "Playwright"),
    ("sqlmap", "sqlmap"),
    ("nikto", "Nikto"),
    ("masscan", "masscan"),
    ("gobuster", "gobuster"),
    ("nuclei", "nuclei"),
    ("nmap", "nmap"),
)

# Generic weak signals: enough to flag `is_automation_tool`, too generic to name a family.
GENERIC_AUTOMATION_HINTS: tuple[str, ...] = ("bot", "crawler", "spider")


@dataclass(frozen=True, slots=True)
class UserAgentEnrichment:
    family: str | None
    is_browser: bool
    is_automation_tool: bool
    # Useragent-derived OS fallback (see module docstring) -- `os_type` already run through
    # `app.ocsf.normalize_os_type` (same vocabulary as an explicit `device.os.type`); `os_version`
    # is `ua_parser`'s own `major.minor.patch`, dot-joined, dropping any trailing components
    # `ua_parser` did not resolve (e.g. `"10"`, not `"10.None.None"`).
    os_type: str | None = None
    os_version: str | None = None


def enrich_user_agent(user_agent: str | None) -> UserAgentEnrichment | None:
    if not user_agent or not user_agent.strip():
        return None
    ua = user_agent.strip()
    ua_lower = ua.lower()

    # `ua_parser.parse_user_agent` is the modern, typed API (unlike the legacy
    # `user_agent_parser.ParseUserAgent`, which ships genuinely unannotated -- untyped
    # even inside this package's own otherwise-`py.typed` surface -- and returns the
    # string `"Other"` rather than `None` on no match).
    parsed = parse_user_agent(ua)
    family = parsed.family if parsed is not None else None
    family_lower = (family or "").lower()

    is_automation = family_lower in AUTOMATION_FAMILIES
    keyword_family: str | None = None
    for keyword, canonical in AUTOMATION_KEYWORDS:
        if keyword in ua_lower:
            is_automation = True
            keyword_family = canonical
            break
    if not is_automation:
        is_automation = any(hint in ua_lower for hint in GENERIC_AUTOMATION_HINTS)

    is_browser = (not is_automation) and family_lower in KNOWN_BROWSER_FAMILIES
    resolved_family = family or keyword_family

    os_result = parse_os(ua)
    os_type = normalize_os_type(os_result.family) if os_result is not None else None
    os_version = _os_version_string(os_result) if os_result is not None else None

    return UserAgentEnrichment(
        family=resolved_family,
        is_browser=is_browser,
        is_automation_tool=is_automation,
        os_type=os_type,
        os_version=os_version,
    )


def _os_version_string(os_result: OS) -> str | None:
    """`ua_parser.OS`'s `major`/`minor`/`patch`/`patch_minor` -> a dot-joined version string, or
    `None` when ua-parser resolved a family but no version at all (e.g. a bare `"Linux"` UA token
    carries no version information to report). Stops at the first missing component rather than
    leaving gaps (`"10..7"`) -- `ua_parser.OS` documents that a missing `minor` implies every
    field after it is also unset, so this is a truncation, not a lossy skip."""
    parts: list[str] = []
    for value in (os_result.major, os_result.minor, os_result.patch, os_result.patch_minor):
        if value is None:
            break
        parts.append(str(value))
    return ".".join(parts) if parts else None
