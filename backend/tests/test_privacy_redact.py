"""app/privacy/redact.py -- docs/06-PRIVACY-SECURITY.md "Secret & PII redaction",
normative. One fires-test and one does-not-false-positive test per pattern in that doc's
table (M5 verification bar), plus the Luhn check called out explicitly: "Show the Luhn
check rejecting a non-card 16-digit run."
"""

from __future__ import annotations

from app.privacy.redact import _luhn_ok, redact_many, redact_text

# ---------------------------------------------------------------------------- token


def test_token_query_param_fires() -> None:
    result = redact_text("GET /api/v1/export?token=abc123XYZ789 HTTP/1.1")
    assert "abc123XYZ789" not in result.text
    assert "<REDACTED:token>" in result.text
    assert result.counts == {"token": 1}


def test_token_all_named_params_fire_case_insensitively() -> None:
    for name in ["token", "key", "secret", "password", "auth", "sig", "access_token", "TOKEN"]:
        result = redact_text(f"?{name}=supersecretvalue123")
        assert result.counts.get("token") == 1, f"expected {name}= to fire"


def test_token_does_not_false_positive_on_param_names_that_merely_contain_the_keyword() -> None:
    """`primarykey=1` and `category=key_metrics` both contain the substring "key" but are
    not the named param docs/06 lists -- redaction must anchor on the exact param name."""
    result = redact_text("GET /report?primarykey=1&category=key_metrics HTTP/1.1")
    assert result.counts == {}
    assert result.text == "GET /report?primarykey=1&category=key_metrics HTTP/1.1"


# ---------------------------------------------------------------------------- bearer


def test_bearer_header_fires() -> None:
    result = redact_text(
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.thisisalongopaquebearertoken1234567890"
    )
    assert "eyJhbGciOiJIUzI1NiJ9" not in result.text
    assert "<REDACTED:bearer>" in result.text
    assert result.counts.get("bearer") == 1


def test_bearer_does_not_false_positive_on_the_plain_english_word() -> None:
    """ "bearer" is an ordinary English/financial word; a naive `Bearer\\s+\\S+` pattern
    would misfire on prose that happens to use it. The real pattern requires a long,
    token-shaped run immediately after "Bearer ", which ordinary short words never are."""
    result = redact_text("Note: the bearer of good news arrived, and bearer bonds matured.")
    assert result.counts == {}
    assert "bearer" in result.text.lower()  # untouched


# ---------------------------------------------------------------------------- aws_key


def test_aws_access_key_id_fires() -> None:
    # AWS's own canonical documentation example key.
    result = redact_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in result.text
    assert "<REDACTED:aws_key>" in result.text
    assert result.counts == {"aws_key": 1}


def test_aws_access_key_id_does_not_false_positive_on_similar_shaped_strings() -> None:
    """Wrong prefix (`BKIA`) and a key-shaped string embedded in a longer alphanumeric run
    (which is not a real, isolated AWS key) must not fire."""
    result = redact_text("BKIAIOSFODNN7EXAMPLE XAKIAIOSFODNN7EXAMPLEX")
    assert result.counts == {}


# ---------------------------------------------------------------------------- jwt


def test_jwt_fires() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ"
    result = redact_text(f"Cookie: session={jwt}; Path=/")
    assert jwt not in result.text
    assert "<REDACTED:jwt>" in result.text
    assert result.counts == {"jwt": 1}


def test_jwt_does_not_false_positive_on_an_incomplete_token() -> None:
    """Needs two dot-separated segments after the `eyJ` header; a bare `eyJ...` prefix with
    no dots at all is not a JWT and must not fire."""
    result = redact_text("weird_prefix eyJ_not_actually_a_jwt_no_dots_here")
    assert result.counts == {}


# ---------------------------------------------------------------------------- privkey


def test_private_key_pem_block_fires() -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
        "-----END RSA PRIVATE KEY-----"
    )
    result = redact_text(f"backup contents:\n{pem}\ndone")
    assert "MIIEowIBAAKCAQEA" not in result.text
    assert "<REDACTED:privkey>" in result.text
    assert result.counts == {"privkey": 1}


def test_private_key_does_not_false_positive_on_prose_mentioning_private_keys() -> None:
    result = redact_text("please rotate your private key soon, it's overdue for renewal")
    assert result.counts == {}


# ---------------------------------------------------------------------------- pan (+ Luhn)


def test_luhn_check_accepts_a_real_card_number() -> None:
    # Well-known Visa test number; passes Luhn.
    assert _luhn_ok("4111111111111111") is True


def test_luhn_check_rejects_a_non_card_16_digit_run() -> None:
    """Explicit verification-bar requirement: "Show the Luhn check rejecting a non-card
    16-digit run." """
    non_card = "1234567890123456"
    assert _luhn_ok(non_card) is False


def test_pan_fires_on_a_luhn_valid_card_number() -> None:
    result = redact_text("card on file: 4111111111111111 exp 12/29")
    assert "4111111111111111" not in result.text
    assert "<REDACTED:pan>" in result.text
    assert result.counts == {"pan": 1}


def test_pan_fires_on_a_luhn_valid_card_number_with_separators() -> None:
    result = redact_text("card: 4111 1111 1111 1111")
    assert result.counts == {"pan": 1}
    assert "4111" not in result.text


def test_pan_does_not_false_positive_on_a_luhn_invalid_16_digit_run() -> None:
    """The same shape (16 digits) that is NOT a valid card number -- e.g. an order ID or a
    phone number with a country code -- must survive untouched. This is what the Luhn check
    buys over a plain digit-count regex."""
    non_card = "1234567890123456"
    assert _luhn_ok(non_card) is False  # precondition for this test to mean anything
    result = redact_text(f"order reference: {non_card}")
    assert result.counts == {}
    assert non_card in result.text


def test_pan_does_not_swallow_a_trailing_separator_into_the_redaction() -> None:
    """Regression: a naive `(?:\\d[ -]?){13,19}` grouping can consume one trailing
    space/dash past the last digit. The shipped pattern must not."""
    result = redact_text("spaced 4111 1111 1111 1111 end")
    assert result.text == "spaced <REDACTED:pan> end"


# ---------------------------------------------------------------------------- email in URL path


def test_email_in_url_path_fires() -> None:
    result = redact_text("GET /api/users/jane.doe@example.com/profile HTTP/1.1")
    assert "jane.doe@example.com" not in result.text
    assert "<REDACTED:email>" in result.text
    assert result.counts == {"email": 1}


def test_email_not_in_a_url_path_does_not_false_positive() -> None:
    """docs/06 scopes this pattern specifically to "Email addresses in URL paths" -- a
    plain free-floating email (e.g. in a contact field) is intentionally out of scope here;
    `principal` fields carry emails and are handled by pseudonymization instead, not this
    redaction pattern."""
    result = redact_text("contact: jane.doe@example.com for questions")
    assert result.counts == {}
    assert "jane.doe@example.com" in result.text


# ---------------------------------------------------------------------------- counting + batch


def test_counts_multiple_hits_of_the_same_pattern() -> None:
    result = redact_text("?token=aaa some text ?password=bbb")
    assert result.counts == {"token": 2}
    assert result.total == 2


def test_redact_many_sums_counts_across_fields_and_preserves_none_and_order() -> None:
    fields = ["?token=abc123456", None, "AKIAIOSFODNN7EXAMPLE", "nothing to see here"]
    redacted, totals = redact_many(fields)
    assert len(redacted) == 4
    assert redacted[1] is None
    assert redacted[3] == "nothing to see here"
    assert totals == {"token": 1, "aws_key": 1}


def test_empty_and_none_text_short_circuit_cleanly() -> None:
    assert redact_text("").counts == {}
    assert redact_text("").text == ""
