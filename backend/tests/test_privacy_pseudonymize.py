"""app/privacy/pseudonymize.py -- docs/06-PRIVACY-SECURITY.md "Pseudonymization", normative.

Verification bar (M5 task brief):
  * Determinism: same (value, kind, salt) -> same pseudonym.
  * Different salt -> different pseudonym.
  * Non-reversibility: the pseudonym cannot be inverted without the map.
"""

from __future__ import annotations

import hashlib
import hmac
import re

import pytest

from app.privacy.pseudonymize import PREFIX, indicator_hash, pseudonymize

HEX12 = re.compile(r"^[0-9a-f]{12}$")


def test_matches_docs_06s_reference_implementation_exactly() -> None:
    """The doc gives the algorithm verbatim; this proves the module is not a
    close-but-different reimplementation."""
    value, kind, salt = "alice@corp.example", "user", b"tenant-salt"
    expected_digest = hmac.new(salt, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()
    expected = f"u_{expected_digest[:12]}"
    assert pseudonymize(value, kind, salt) == expected


@pytest.mark.parametrize("kind", ["user", "ip", "host", "session", "device"])
def test_deterministic_same_input_same_output(kind: str) -> None:
    salt = b"tenant-a-salt"
    first = pseudonymize("some-value", kind, salt)
    second = pseudonymize("some-value", kind, salt)
    assert first == second


def test_different_salt_different_pseudonym() -> None:
    value, kind = "alice@corp.example", "user"
    a = pseudonymize(value, kind, b"tenant-a-salt")
    b = pseudonymize(value, kind, b"tenant-b-salt")
    assert a != b


def test_different_value_different_pseudonym() -> None:
    kind, salt = "user", b"tenant-a-salt"
    assert pseudonymize("alice@corp.example", kind, salt) != pseudonymize(
        "bob@corp.example", kind, salt
    )


def test_different_kind_different_pseudonym_even_for_the_same_raw_value() -> None:
    """`f"{kind}:{value}"` is hashed, not just `value` -- so the same string used as two
    different kinds of entity (e.g. a hostname that happens to equal a username) never
    collides purely by coincidence of the input string."""
    salt = b"tenant-a-salt"
    assert pseudonymize("shared-string", "user", salt) != pseudonymize(
        "shared-string", "host", salt
    )


@pytest.mark.parametrize(("kind", "prefix"), sorted(PREFIX.items()))
def test_output_is_prefixed_per_kind_and_12_hex_chars(kind: str, prefix: str) -> None:
    out = pseudonymize("value", kind, b"salt")
    assert out.startswith(f"{prefix}_")
    suffix = out[len(prefix) + 1 :]
    assert HEX12.match(suffix), f"expected 12 lowercase hex chars, got {suffix!r}"


def test_unknown_kind_raises_rather_than_falling_back_to_a_default_prefix() -> None:
    with pytest.raises(ValueError, match="unknown pseudonymization kind"):
        pseudonymize("value", "totally-not-a-kind", b"salt")


def test_domain_is_not_a_pseudonymize_kind() -> None:
    """The do-NOT-pseudonymize list (docs/06) names domains explicitly; asserting this
    raises is a regression guard against ever wiring a domain through the per-tenant path
    (`indicator_hash` below is the *only* sanctioned way to hash a domain, and only with a
    shared, cross-tenant salt)."""
    with pytest.raises(ValueError, match="unknown pseudonymization kind"):
        pseudonymize("evil.example", "domain", b"salt")


class TestNonReversibility:
    """The pseudonym cannot be inverted without the (out-of-band) reverse map."""

    def test_pseudonym_does_not_contain_or_visibly_encode_the_original_value(self) -> None:
        value = "alice@corp.example"
        out = pseudonymize(value, "user", b"salt")
        assert value not in out
        assert value.encode().hex() not in out

    def test_brute_forcing_a_small_known_space_without_the_salt_does_not_recover_the_value(
        self,
    ) -> None:
        """An attacker who captured a pseudonym but not the tenant's salt cannot recover
        the original value even when the universe of candidate values is small and fully
        known -- because they are also missing the one thing this is keyed on."""
        real_value, kind, salt = "alice@corp.example", "user", b"the-real-secret-salt"
        target = pseudonymize(real_value, kind, salt)

        candidates = [f"user{i}@corp.example" for i in range(500)] + [real_value]
        wrong_salt = b"a-guessed-salt"
        recovered = [c for c in candidates if pseudonymize(c, kind, wrong_salt) == target]
        assert recovered == []

    def test_same_value_different_tenants_are_unlinkable(self) -> None:
        """Two tenants pseudonymizing the identical username produce unrelated-looking
        outputs -- nothing about the two pseudonyms reveals they share an input, which is
        exactly what per-tenant salting is for."""
        value = "shared.vendor.contractor@example.com"
        a = pseudonymize(value, "user", b"tenant-a-salt")
        b = pseudonymize(value, "user", b"tenant-b-salt")
        assert a != b
        # no shared substring of meaningful length beyond the common "u_" prefix
        assert a[2:] != b[2:]


class TestIndicatorHash:
    """docs/06's Tier 2 exception: domains/dst IPs use a *shared* cross-tenant salt so
    cross-tenant overlap is detectable -- a separate mechanism from `pseudonymize()`."""

    def test_deterministic(self) -> None:
        a = indicator_hash("evil.example", "domain", b"shared-salt")
        b = indicator_hash("evil.example", "domain", b"shared-salt")
        assert a == b

    def test_same_domain_same_shared_salt_matches_across_simulated_tenants(self) -> None:
        """The entire point of the shared salt: two different tenants both observing the
        same indicator produce the *same* hash, so overlap is detectable without either
        tenant seeing the other's raw data."""
        shared_salt = b"cross-tenant-shared-salt"
        tenant_a_view = indicator_hash("c2.evil.example", "domain", shared_salt)
        tenant_b_view = indicator_hash("c2.evil.example", "domain", shared_salt)
        assert tenant_a_view == tenant_b_view

    def test_uses_a_distinct_prefix_namespace_from_the_per_tenant_user_kind(self) -> None:
        out = indicator_hash("evil.example", "domain", b"shared-salt")
        assert out.startswith("d_")

    def test_unknown_kind_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown indicator kind"):
            indicator_hash("value", "user", b"salt")  # type: ignore[arg-type]
