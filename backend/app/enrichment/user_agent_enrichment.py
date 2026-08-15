"""user_agent -> family, is_browser, is_automation_tool (docs/03-PARSERS-OCSF.md
"Enrichment"). Feeds docs/04's L3 `automation_ua_ratio` feature and the L1 Sigma rule
"Non-browser user agent (curl, python-requests, powershell, wget)".

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
"""

from __future__ import annotations

from dataclasses import dataclass

from ua_parser import parse_user_agent

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

    return UserAgentEnrichment(
        family=resolved_family, is_browser=is_browser, is_automation_tool=is_automation
    )
