"""app/enrichment/ip_enrichment.py -- IP -> ASN, org, country, hosting-provider flag
(docs/03-PARSERS-OCSF.md "Enrichment")."""

from __future__ import annotations

from app.enrichment.ip_enrichment import enrich_ip


def test_none_and_empty_input_return_none() -> None:
    assert enrich_ip(None) is None
    assert enrich_ip("") is None


def test_unparseable_string_returns_none_not_a_crash() -> None:
    assert enrich_ip("not-an-ip-address") is None


def test_known_hosting_provider_range_resolves_with_asn_org_and_hosting_flag() -> None:
    # Inside Cloudflare's officially published 104.16.0.0/13.
    result = enrich_ip("104.16.5.1")
    assert result is not None
    assert result.asn == 13335
    assert result.org == "Cloudflare"
    assert result.is_hosting is True
    assert result.is_special_use is False


def test_unresolved_ip_returns_a_well_formed_negative_result() -> None:
    """An address outside every bundled provider block (the overwhelmingly common case for
    a random residential address) still returns a full, honest `IPEnrichment` rather than
    `None` -- "no ASN data" and "no IP provided" are different things and callers (e.g. the
    L3 `hosting_provider_ratio` feature, docs/04) need to be able to tell them apart."""
    result = enrich_ip("1.2.3.4")
    assert result is not None
    assert result.asn is None
    assert result.org is None
    assert result.is_hosting is False
    assert result.is_special_use is False


class TestSpecialUseRanges:
    """RFC 5737/1918/etc special-purpose IPv4 space. Exact by construction (stdlib
    `ipaddress` membership), and load-bearing: `datagen`'s default office egress addresses
    sit in the three RFC 5737 TEST-NET blocks on purpose (docs/11), so a real bundled
    dataset alone would never classify the M2 corpus's own corporate traffic correctly."""

    def test_rfc1918_private_range(self) -> None:
        result = enrich_ip("10.1.2.3")
        assert result is not None
        assert result.is_special_use is True
        assert result.is_hosting is False
        assert result.asn is None
        assert "1918" in (result.org or "")

    def test_rfc1918_covers_all_three_blocks(self) -> None:
        for ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1"]:
            result = enrich_ip(ip)
            assert result is not None and result.is_special_use is True, ip

    def test_rfc5737_documentation_ranges_used_by_datagens_default_offices(self) -> None:
        # US-CA, US-NY, IE-DU -- datagen/realism.py OFFICE_CATALOG / DEFAULT_OFFICE_CODES.
        for ip, label in [
            ("203.0.113.10", "TEST-NET-3"),
            ("198.51.100.10", "TEST-NET-2"),
            ("192.0.2.10", "TEST-NET-1"),
        ]:
            result = enrich_ip(ip)
            assert result is not None
            assert result.is_special_use is True
            assert label in (result.org or ""), ip

    def test_loopback(self) -> None:
        result = enrich_ip("127.0.0.1")
        assert result is not None and result.is_special_use is True

    def test_link_local(self) -> None:
        result = enrich_ip("169.254.1.1")
        assert result is not None and result.is_special_use is True


def test_ipv6_resolves_cleanly_to_no_data_rather_than_raising() -> None:
    """No parser or datagen emitter produces IPv6 (see module docstring); still must not
    error on one."""
    result = enrich_ip("2001:4860:4860::8888")
    assert result is not None
    assert result.asn is None
    assert result.is_hosting is False


def test_whitespace_is_tolerated() -> None:
    a = enrich_ip("104.16.5.1")
    b = enrich_ip("  104.16.5.1  ")
    assert a == b
