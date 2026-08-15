"""app/enrichment/domain_enrichment.py -- domain -> registrable domain, TLD risk tier, age
in days, newly-registered flag (docs/03-PARSERS-OCSF.md "Enrichment").

docs/03: "Newly-registered domain (age < 30 days) is a strong C2 indicator -- surface it as
a first-class enrichment flag, not buried in JSON."
"""

from __future__ import annotations

from datetime import date

from app.enrichment.domain_enrichment import NEWLY_REGISTERED_THRESHOLD_DAYS, enrich_domain


def test_none_and_empty_input_return_none() -> None:
    assert enrich_domain(None) is None
    assert enrich_domain("") is None


def test_registrable_domain_extraction_strips_subdomain() -> None:
    result = enrich_domain("www.mail.example.com")
    assert result is not None
    assert result.registrable_domain == "example.com"
    assert result.tld == "com"


def test_multi_label_public_suffix_is_handled_correctly() -> None:
    """`co.uk` is a two-label public suffix; a naive "last two labels" heuristic would get
    this wrong (`.co.uk` instead of `.uk`, or the wrong registrable domain)."""
    result = enrich_domain("sub.example.co.uk")
    assert result is not None
    assert result.registrable_domain == "example.co.uk"
    assert result.tld == "co.uk"


def test_direct_ip_host_has_no_tld_and_is_not_dropped() -> None:
    """docs/04's "Direct-to-IP HTTP request" rule fires on exactly this shape -- enrichment
    must not silently drop it."""
    result = enrich_domain("203.0.113.9")
    assert result is not None
    assert result.registrable_domain == "203.0.113.9"
    assert result.tld == ""
    assert result.tld_risk_tier == "unknown"


def test_bare_hostname_with_no_dot_falls_back_to_itself() -> None:
    result = enrich_domain("localhost")
    assert result is not None
    assert result.registrable_domain == "localhost"


def test_is_case_and_trailing_dot_insensitive() -> None:
    a = enrich_domain("Example.COM.")
    b = enrich_domain("example.com")
    assert a is not None and b is not None
    assert a.registrable_domain == b.registrable_domain == "example.com"


class TestTldRiskTier:
    def test_high_risk_tld(self) -> None:
        result = enrich_domain("secure-vault-portal99.top")
        assert result is not None
        assert result.tld_risk_tier == "high"

    def test_low_risk_tld(self) -> None:
        result = enrich_domain("github.com")
        assert result is not None
        assert result.tld_risk_tier == "low"

    def test_medium_risk_tld(self) -> None:
        result = enrich_domain("something.biz")
        assert result is not None
        assert result.tld_risk_tier == "medium"

    def test_unrecognized_tld_is_unknown_not_defaulted_to_low(self) -> None:
        """An absent TLD must not silently read as "vetted safe" (see
        data/enrichment/tld_risk.yml's header comment)."""
        result = enrich_domain("something.qqzz")
        assert result is not None
        assert result.tld_risk_tier == "unknown"


class TestDomainAge:
    """`age_days`/`newly_registered` come from `data/enrichment/domain_age_snapshot.csv`,
    which only covers the reused top-5000 popularity list (see module docstring for why).
    These tests pin known-good/known-absent domains rather than depending on that file's
    exact contents drifting."""

    def test_known_old_domain_resolves_a_positive_age_and_is_not_newly_registered(self) -> None:
        result = enrich_domain("google.com", as_of=date(2026, 1, 1))
        assert result is not None
        assert result.age_known is True
        assert result.age_days is not None and result.age_days > NEWLY_REGISTERED_THRESHOLD_DAYS
        assert result.newly_registered is False

    def test_age_is_computed_relative_to_as_of_not_wall_clock(self) -> None:
        result_early = enrich_domain("google.com", as_of=date(2000, 1, 1))
        result_late = enrich_domain("google.com", as_of=date(2020, 1, 1))
        assert result_early is not None and result_late is not None
        assert result_early.age_days is not None and result_late.age_days is not None
        assert result_late.age_days > result_early.age_days

    def test_domain_absent_from_the_snapshot_has_honestly_unknown_age(self) -> None:
        """This is the *expected*, documented common case for attacker-controlled domains
        in the M2 corpus (see module docstring) -- age must read as unknown, not as a
        fabricated number, and must not default to `newly_registered=True` either (that
        would false-flag every ordinary long-tail domain the snapshot doesn't happen to
        cover)."""
        result = enrich_domain("some-domain-never-in-any-bundled-list-xyzzy123.example")
        assert result is not None
        assert result.age_known is False
        assert result.age_days is None
        assert result.newly_registered is False

    def test_a_domain_younger_than_the_threshold_is_flagged_newly_registered(self) -> None:
        """Exercises the mechanism end to end using a real snapshot-covered domain, pinning
        `as_of` to just after that domain's own bundled `first_seen` date so the test does
        not depend on wall-clock date drift."""
        from app.enrichment.domain_enrichment import _age_snapshot

        domain, first_seen = next(iter(_age_snapshot().items()))
        as_of = date.fromordinal(first_seen.toordinal() + 5)  # 5 days old
        result = enrich_domain(domain, as_of=as_of)
        assert result is not None
        assert result.age_known is True
        assert result.age_days == 5
        assert result.newly_registered is True

    def test_threshold_boundary_is_strictly_less_than_30_days(self) -> None:
        from app.enrichment.domain_enrichment import _age_snapshot

        domain, first_seen = next(iter(_age_snapshot().items()))
        exactly_30 = date.fromordinal(first_seen.toordinal() + NEWLY_REGISTERED_THRESHOLD_DAYS)
        result = enrich_domain(domain, as_of=exactly_30)
        assert result is not None
        assert result.age_days == NEWLY_REGISTERED_THRESHOLD_DAYS
        assert result.newly_registered is False


class TestPopularity:
    """Reused from `datagen/data/top_domains.txt` per the M5 task brief ("reuse ... rather
    than inventing parallel datasets")."""

    def test_top_ranked_domain_is_flagged_a_top_site_with_a_low_rank_number(self) -> None:
        result = enrich_domain("google.com")
        assert result is not None
        assert result.is_top_site is True
        assert result.popularity_rank is not None
        assert result.popularity_rank <= 10

    def test_unlisted_domain_is_not_a_top_site(self) -> None:
        result = enrich_domain("some-domain-never-in-any-bundled-list-xyzzy123.example")
        assert result is not None
        assert result.is_top_site is False
        assert result.popularity_rank is None


def test_offline_extraction_never_touches_the_network() -> None:
    """`tldextract.TLDExtract(suffix_list_urls=())` forces the bundled snapshot. tldextract
    lazily builds its suffix trie on *first use*, not at construction, so this clears the
    module's cached extractor first and blocks every socket connection before that first
    use -- otherwise, if some earlier test already triggered the lazy build, this would
    pass trivially without proving anything (docs/03: "Do not make network calls at
    runtime")."""
    import socket

    from app.enrichment import domain_enrichment

    def _blocked(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network call attempted during domain enrichment")

    domain_enrichment._extractor.cache_clear()
    original_connect = socket.socket.connect
    socket.socket.connect = _blocked  # type: ignore[method-assign]
    try:
        result = enrich_domain("www.some-new-domain-never-seen.top")
        assert result is not None
        assert result.registrable_domain == "some-new-domain-never-seen.top"
    finally:
        socket.socket.connect = original_connect  # type: ignore[method-assign]
        domain_enrichment._extractor.cache_clear()  # fresh, normally-built instance for later tests
