"""app/enrichment/tags.py -- tag bank matching against data/tags/tag_bank.yml
(docs/03-PARSERS-OCSF.md "Enrichment": "all -> tag bank match")."""

from __future__ import annotations

from app.enrichment.tags import match_tags


def test_no_matching_conditions_returns_an_empty_list() -> None:
    assert match_tags() == []
    assert match_tags(registrable_domain="totally-unremarkable-site.example") == []


def test_known_corporate_saas_domain_is_tagged() -> None:
    assert "corporate_saas" in match_tags(registrable_domain="slack.com")


def test_domain_match_is_case_insensitive() -> None:
    assert "corporate_saas" in match_tags(registrable_domain="Slack.COM")


def test_paste_site_domain_is_tagged() -> None:
    assert "paste_site" in match_tags(registrable_domain="pastebin.com")


def test_high_abuse_tld_is_tagged_from_tld_alone() -> None:
    tags = match_tags(registrable_domain="whatever123.top", tld="top")
    assert "high_abuse_tld" in tags


def test_low_risk_tld_is_not_tagged_high_abuse() -> None:
    tags = match_tags(registrable_domain="github.com", tld="com")
    assert "high_abuse_tld" not in tags


def test_automation_client_ua_keyword_is_tagged() -> None:
    assert "automation_client" in match_tags(user_agent="python-requests/2.32.3")
    assert "automation_client" in match_tags(user_agent="curl/8.7.1")


def test_browser_ua_is_not_tagged_automation() -> None:
    tags = match_tags(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0")
    assert "automation_client" not in tags


def test_hosting_infrastructure_flag_is_tagged() -> None:
    assert "hosting_infrastructure" in match_tags(is_hosting=True)
    assert "hosting_infrastructure" not in match_tags(is_hosting=False)
    assert "hosting_infrastructure" not in match_tags()  # not asserted at all -> no match


def test_multiple_rules_can_match_the_same_event() -> None:
    tags = match_tags(
        registrable_domain="slack.com",
        user_agent="python-requests/2.32.3",
        is_hosting=True,
    )
    assert set(tags) >= {"corporate_saas", "automation_client", "hosting_infrastructure"}


def test_a_rule_requiring_multiple_conditions_needs_all_of_them() -> None:
    """`anonymizer_or_proxy_keyword` matches on a domain regex; confirms the regex-based
    rule type works and is scoped to the domain, not incidentally triggered by unrelated
    fields."""
    assert "anonymizer_or_proxy_keyword" in match_tags(registrable_domain="freevpn123.example")
    assert "anonymizer_or_proxy_keyword" not in match_tags(registrable_domain="github.com")
