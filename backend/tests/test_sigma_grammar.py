"""`app.detection.sigma.grammar` — the `condition` mini-language tokenizer/parser. Pure unit
tests, no database: every case here is about the AST a condition string parses to, not about
what it does against real events (that is `tests/test_rules_fixtures.py` and
`tests/test_sigma_compiler.py`)."""

from __future__ import annotations

import pytest

from app.detection.sigma.grammar import (
    And,
    BlockRef,
    CountAgg,
    Not,
    NotSeenBefore,
    Or,
    SigmaConditionError,
    SpeedKmh,
    parse_condition,
)


def test_docs04_worked_example_parses_to_anchored_count() -> None:
    """docs/04's own literal example: `failures | count() by principal >= 5 and success`."""
    node = parse_condition("failures | count() by principal >= 5 and success")
    assert node == And(
        (
            CountAgg(
                block="failures",
                distinct_field=None,
                max_each=None,
                by=("principal",),
                comparator=">=",
                value=5.0,
            ),
            BlockRef("success"),
        )
    )


def test_bare_block_reference() -> None:
    assert parse_condition("selection") == BlockRef("selection")


def test_and_or_not_precedence() -> None:
    # `and` binds tighter than `or`: `a or b and c` == `a or (b and c)`.
    node = parse_condition("a or b and c")
    assert node == Or((BlockRef("a"), And((BlockRef("b"), BlockRef("c")))))


def test_not_binds_to_the_next_atom_only() -> None:
    node = parse_condition("not a and b")
    assert node == And((Not(BlockRef("a")), BlockRef("b")))


def test_parentheses_override_precedence() -> None:
    node = parse_condition("(a or b) and c")
    assert node == And((Or((BlockRef("a"), BlockRef("b"))), BlockRef("c")))


def test_count_distinct_with_max_each() -> None:
    node = parse_condition("attempts | count(principal, max_each=3) by src_ip >= 10")
    assert node == CountAgg(
        block="attempts",
        distinct_field="principal",
        max_each=3,
        by=("src_ip",),
        comparator=">=",
        value=10.0,
    )


def test_count_by_multiple_fields() -> None:
    node = parse_condition("blocked | count() by domain, src_ip >= 1")
    assert isinstance(node, CountAgg)
    assert node.by == ("domain", "src_ip")


def test_not_seen_before() -> None:
    node = parse_condition("logins | not_seen_before(principal, country) in logins")
    assert node == NotSeenBefore(
        block="logins", fields=("principal", "country"), other_block="logins"
    )


def test_speed_kmh() -> None:
    node = parse_condition("logins | speed_kmh(lat, lon) by principal > 900")
    assert node == SpeedKmh(
        block="logins",
        lat_field="lat",
        lon_field="lon",
        min_km=0.0,
        by=("principal",),
        comparator=">",
        value=900.0,
    )


def test_speed_kmh_with_min_km() -> None:
    node = parse_condition("logins | speed_kmh(lat, lon, min_km=100) by principal > 900")
    assert node == SpeedKmh(
        block="logins",
        lat_field="lat",
        lon_field="lon",
        min_km=100.0,
        by=("principal",),
        comparator=">",
        value=900.0,
    )


@pytest.mark.parametrize(
    "source",
    [
        "",
        "   ",
        "a and",
        "a | count( by principal >= 5",
        "a | bogus_function() by x >= 1",
        "a and b (",
        "1abc",
    ],
)
def test_invalid_conditions_raise(source: str) -> None:
    with pytest.raises(SigmaConditionError):
        parse_condition(source)


def test_trailing_garbage_after_a_complete_condition_raises() -> None:
    with pytest.raises(SigmaConditionError):
        parse_condition("a and b extra_token")
