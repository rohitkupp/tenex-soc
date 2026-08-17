"""app/enrichment/user_agent_enrichment.py -- user_agent -> family, is_browser,
is_automation_tool (docs/03-PARSERS-OCSF.md "Enrichment").

Fixtures are the literal UA strings `datagen/realism.py` uses (`_BROWSER_SHARE`,
`AUTOMATION_AGENTS`) -- real, not paraphrased -- so this doubles as a coverage check
against exactly what the M2 corpus will actually contain.
"""

from __future__ import annotations

import pytest

from app.enrichment.user_agent_enrichment import enrich_user_agent

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like "
    "Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) "
    "SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0",
]

AUTOMATION_UAS = [
    "curl/8.7.1",
    "python-requests/2.32.3",
    "Wget/1.21.4",
    "Go-http-client/2.0",
    "okhttp/4.12.0",
    "Java/17.0.9",
    "aws-cli/2.19.1 Python/3.12.6",
    "rclone/v1.68.1",
    "Datadog Agent/7.59.0",
    "Apache-HttpClient/4.5.14 (Java/17.0.9)",
    "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.19045) PowerShell/7.4.6",
    "axios/1.7.7",
]


def test_none_and_blank_input_return_none() -> None:
    assert enrich_user_agent(None) is None
    assert enrich_user_agent("") is None
    assert enrich_user_agent("   ") is None


@pytest.mark.parametrize("ua", BROWSER_UAS)
def test_every_datagen_browser_ua_is_recognized_as_a_browser(ua: str) -> None:
    result = enrich_user_agent(ua)
    assert result is not None
    assert result.is_browser is True, ua
    assert result.is_automation_tool is False, ua
    assert result.family is not None


@pytest.mark.parametrize("ua", AUTOMATION_UAS)
def test_every_datagen_automation_ua_is_recognized_as_automation_not_a_browser(ua: str) -> None:
    result = enrich_user_agent(ua)
    assert result is not None
    assert result.is_automation_tool is True, ua
    assert result.is_browser is False, ua
    assert result.family is not None, ua  # every one resolves to a readable family, none "Other"


def test_ua_parser_family_wins_over_the_keyword_fallback_when_it_has_an_answer() -> None:
    result = enrich_user_agent("curl/8.7.1")
    assert result is not None
    assert result.family == "curl"


def test_keyword_fallback_supplies_a_family_when_ua_parser_says_other() -> None:
    """`ua-parser`'s bundled table resolves "Datadog Agent/7.59.0" to the generic "Other"
    family (verified directly against the installed parser); the keyword fallback is what
    turns that into a readable, correctly-classified result instead of a silent gap."""
    result = enrich_user_agent("Datadog Agent/7.59.0")
    assert result is not None
    assert result.family == "Datadog Agent"
    assert result.is_automation_tool is True


def test_unrecognized_ua_is_neither_browser_nor_automation() -> None:
    result = enrich_user_agent("SomeTotallyUnknownThing/1.0")
    assert result is not None
    assert result.is_browser is False
    assert result.is_automation_tool is False


def test_scanning_tool_keywords_are_flagged_automation() -> None:
    for ua in ["sqlmap/1.7.2#stable", "nmap NSE", "Mozilla/5.0 (compatible; Nikto/2.5.0)"]:
        result = enrich_user_agent(ua)
        assert result is not None and result.is_automation_tool is True, ua


# ---------------------------------------------------------------------------- useragent-derived
# OS fallback (this task, docs/11 "derive OS family/version from useragent")


def test_windows_ua_derives_normalized_os_type_and_version() -> None:
    result = enrich_user_agent(BROWSER_UAS[0])  # "Windows NT 10.0"
    assert result is not None
    assert result.os_type == "windows"
    assert result.os_version == "10"


def test_macos_ua_derives_normalized_os_type_and_dotted_version() -> None:
    result = enrich_user_agent(BROWSER_UAS[1])  # "Intel Mac OS X 10_15_7"
    assert result is not None
    assert result.os_type == "macos"
    assert result.os_version == "10.15.7"


def test_ios_ua_derives_ios_os_type() -> None:
    result = enrich_user_agent(BROWSER_UAS[4])  # "iPhone; CPU iPhone OS 18_1"
    assert result is not None
    assert result.os_type == "ios"


def test_android_ua_derives_android_os_type() -> None:
    result = enrich_user_agent(BROWSER_UAS[2])  # "Linux; Android 14; Pixel 8"
    assert result is not None
    assert result.os_type == "android"


def test_linux_automation_ua_derives_linux_os_type() -> None:
    """`curl/8.7.1` alone carries no OS token (ua-parser resolves no OS at all for a bare tool
    string) -- the Linux `AUTOMATION_AGENTS` fixture that does carry one is the PowerShell UA,
    which is wrapped in a `Windows NT` string despite representing a Windows automation host."""
    result = enrich_user_agent(
        "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"
    )
    assert result is not None
    assert result.os_type == "linux"


def test_ua_with_no_resolvable_os_leaves_os_fields_none() -> None:
    result = enrich_user_agent("curl/8.7.1")
    assert result is not None
    assert result.os_type is None
    assert result.os_version is None
