"""The Sigma `condition` mini-language: tokenizer, parser, AST.

docs/04 shows one worked example of the condition grammar this evaluator must support:

```
condition: failures | count() by principal >= 5 and success
```

That line is the spec. Reading it left to right: `failures` and `success` are the names of
`detection` blocks (field-filter dicts); `|` pipes a block into an aggregation function
(`count()`); `by principal` is the group key; `>= 5` is the threshold; `and success` requires a
second block to also match. Everything below is built to parse exactly that shape and a small,
deliberate set of siblings the rule inventory (docs/04 "Rule inventory") actually needs:

* Boolean combinators `and` / `or` / `not` / parentheses over block references and aggregations,
  for simple multi-field or multi-block presence rules (most of the proxy and identity rules).
* `count(field) by g >= N` — distinct-count aggregation (Sigma's own correlation syntax
  distinguishes `count()` — row count — from `count(field)` — distinct values of `field`), used
  by the password-spray rule's "≥10 distinct principals" clause. An optional `max_each=K` keyword
  argument caps which distinct values count at all: "count(principal, max_each=3) by src_ip"
  only counts a principal once it has ≤3 matching rows against that group in the same window —
  the spray rule's "≤3 attempts each" half.
* `not_seen_before(fields...) in other_block` — no earlier row (in the same analysis) shares the
  given field values with the current one. Powers "first login from new country" (fields:
  principal, country; other_block: same block) and the cross-source "successful login from an IP
  with no prior proxy history" rule (fields: principal, src_ip; other_block: a different
  logsource's block) — one primitive, reused, not two hand-rolled checks.
* `speed_kmh(lat_field, lon_field) by g > N` — great-circle speed between an entity's consecutive
  matching rows exceeds `N` km/h. Powers impossible travel. A named aggregation function
  alongside `count`, not a special case grafted onto the grammar.

None of this is rule-specific logic living in Python — every one of these is a generic,
reusable aggregation *shape* that any rule's YAML can invoke by name, the same way `count()` is
generic. The rule-specific part (which fields, which thresholds, which technique) lives entirely
in the YAML `detection` block and the numbers next to `by`/`>=` in `condition`, per
`CLAUDE.md`'s "rules are Sigma YAML" constraint.

## Grammar (informal EBNF)

```
condition   := or_expr
or_expr     := and_expr ( "or" and_expr )*
and_expr    := unary ( "and" unary )*
unary       := "not" unary | atom
atom        := "(" condition ")" | agg_term | IDENT
agg_term    := IDENT "|" func_call
func_call   := "count" "(" [ field_arg ] ")" "by" field_list comparator NUMBER
             | "not_seen_before" "(" field_list ")" "in" IDENT
             | "speed_kmh" "(" IDENT "," IDENT ")" "by" field_list comparator NUMBER
field_arg   := IDENT [ "," "max_each" "=" NUMBER ]
field_list  := IDENT ( "," IDENT )*
comparator  := ">=" | ">" | "<=" | "<" | "==" | "="
```

`and`/`or` are left-associative and `and` binds tighter than `or`, matching every boolean
expression language libSigma users already know. There is no scoped alternative to a `not`
without parentheses (`not a and b` is `(not a) and b`), matching Python's own precedence, which
whoever tunes rules is more likely to know than raw Sigma's.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

__all__ = [
    "And",
    "BlockRef",
    "ConditionNode",
    "CountAgg",
    "Not",
    "NotSeenBefore",
    "Or",
    "SigmaConditionError",
    "SpeedKmh",
    "parse_condition",
]


class SigmaConditionError(ValueError):
    """A `condition` string could not be tokenized or parsed."""


# ---------------------------------------------------------------------------- AST


@dataclass(frozen=True, slots=True)
class BlockRef:
    """Bare reference to a `detection` block name — "this block's filters matched this row"."""

    name: str


@dataclass(frozen=True, slots=True)
class Not:
    term: ConditionNode


@dataclass(frozen=True, slots=True)
class And:
    terms: tuple[ConditionNode, ...]


@dataclass(frozen=True, slots=True)
class Or:
    terms: tuple[ConditionNode, ...]


@dataclass(frozen=True, slots=True)
class CountAgg:
    """`block | count([field[, max_each=K]]) by f1[, f2...] <cmp> N`."""

    block: str
    distinct_field: str | None
    max_each: int | None
    by: tuple[str, ...]
    comparator: str
    value: float


@dataclass(frozen=True, slots=True)
class NotSeenBefore:
    """`block | not_seen_before(f1[, f2...]) in other_block`.

    Convention (enforced by `app.detection.sigma.compiler._run_not_seen_before`, not by this
    grammar): **the first field, `f1`, is the "who" this rule tracks a baseline for** —
    `principal` in both of this evaluator's rules that use the primitive. A match additionally
    requires at least one earlier `other_block` row sharing that same `f1` value; without that, a
    principal's very first-ever row would trivially have "no earlier row sharing these field
    values" and every principal's first login in the file would read as a "new country" rather
    than as a missing baseline.
    """

    block: str
    fields: tuple[str, ...]
    other_block: str


@dataclass(frozen=True, slots=True)
class SpeedKmh:
    """`block | speed_kmh(lat_field, lon_field[, min_km=K]) by f1[, f2...] <cmp> N`.

    `min_km` (default 0) guards against the false-positive mode every real impossible-travel
    detector has to handle: two genuine logins seconds apart with *slightly* different
    geolocation (GPS/IP-geolocation jitter within the same city, a second device, a VPN
    reconnect) divide a small-but-nonzero distance by a near-zero elapsed time and produce an
    inflated "speed" that clears the threshold on pure noise. Requiring the pair's distance to
    also clear `min_km` before its speed is even considered is standard practice (commercial
    impossible-travel rules almost universally pair a speed threshold with a distance floor for
    exactly this reason), not a special case bolted onto this one rule.
    """

    block: str
    lat_field: str
    lon_field: str
    min_km: float
    by: tuple[str, ...]
    comparator: str
    value: float


ConditionNode = BlockRef | Not | And | Or | CountAgg | NotSeenBefore | SpeedKmh

_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "and",
        "or",
        "not",
        "by",
        "in",
        "count",
        "not_seen_before",
        "speed_kmh",
        "max_each",
        "min_km",
    }
)
_COMPARATORS: Final[frozenset[str]] = frozenset({">=", "<=", "==", ">", "<", "="})

_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<number>\d+\.\d+|\d+)
    | (?P<comparator>>=|<=|==|>|<|=)
    | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    | (?P<punct>[|(),])
    """,
    re.VERBOSE,
)


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str  # "number" | "comparator" | "ident" | "punct" | "eof"
    text: str


def _tokenize(source: str) -> list[_Token]:
    tokens: list[_Token] = []
    pos = 0
    n = len(source)
    while pos < n:
        m = _TOKEN_RE.match(source, pos)
        if m is None:
            raise SigmaConditionError(
                f"unexpected character {source[pos]!r} at offset {pos} in condition {source!r}"
            )
        pos = m.end()
        if m.lastgroup == "ws":
            continue
        assert m.lastgroup is not None
        tokens.append(_Token(kind=m.lastgroup, text=m.group()))
    tokens.append(_Token(kind="eof", text=""))
    return tokens


class _Parser:
    """Recursive-descent parser over the token stream. One condition string per instance."""

    def __init__(self, tokens: list[_Token], *, source: str) -> None:
        self._tokens = tokens
        self._pos = 0
        self._source = source

    # ------------------------------------------------------------ token helpers

    @property
    def _current(self) -> _Token:
        return self._tokens[self._pos]

    def _advance(self) -> _Token:
        tok = self._tokens[self._pos]
        if tok.kind != "eof":
            self._pos += 1
        return tok

    def _error(self, message: str) -> SigmaConditionError:
        return SigmaConditionError(
            f"{message} (at {self._current.kind} {self._current.text!r}) in condition "
            f"{self._source!r}"
        )

    def _expect_ident(self, text: str) -> None:
        tok = self._current
        if tok.kind != "ident" or tok.text != text:
            raise self._error(f"expected {text!r}")
        self._advance()

    def _expect_punct(self, text: str) -> None:
        tok = self._current
        if tok.kind != "punct" or tok.text != text:
            raise self._error(f"expected {text!r}")
        self._advance()

    def _is_ident(self, text: str) -> bool:
        return self._current.kind == "ident" and self._current.text == text

    # ------------------------------------------------------------ grammar

    def parse(self) -> ConditionNode:
        node = self._or_expr()
        if self._current.kind != "eof":
            raise self._error("trailing input after a complete condition")
        return node

    def _or_expr(self) -> ConditionNode:
        terms = [self._and_expr()]
        while self._is_ident("or"):
            self._advance()
            terms.append(self._and_expr())
        return terms[0] if len(terms) == 1 else Or(tuple(terms))

    def _and_expr(self) -> ConditionNode:
        terms = [self._unary()]
        while self._is_ident("and"):
            self._advance()
            terms.append(self._unary())
        return terms[0] if len(terms) == 1 else And(tuple(terms))

    def _unary(self) -> ConditionNode:
        if self._is_ident("not"):
            self._advance()
            return Not(self._unary())
        return self._atom()

    def _atom(self) -> ConditionNode:
        tok = self._current
        if tok.kind == "punct" and tok.text == "(":
            self._advance()
            node = self._or_expr()
            self._expect_punct(")")
            return node
        if tok.kind != "ident":
            raise self._error("expected a block name, function call, or '('")
        name = self._advance().text
        if self._current.kind == "punct" and self._current.text == "|":
            self._advance()
            return self._agg_term(name)
        return BlockRef(name)

    def _agg_term(self, block: str) -> ConditionNode:
        if self._is_ident("count"):
            return self._count_agg(block)
        if self._is_ident("not_seen_before"):
            return self._not_seen_before(block)
        if self._is_ident("speed_kmh"):
            return self._speed_kmh(block)
        raise self._error(
            "expected an aggregation function: count(), not_seen_before(), or speed_kmh()"
        )

    def _count_agg(self, block: str) -> CountAgg:
        self._advance()  # "count"
        self._expect_punct("(")
        distinct_field: str | None = None
        max_each: int | None = None
        if not (self._current.kind == "punct" and self._current.text == ")"):
            distinct_field = self._advance_ident("a field name")
            if self._current.kind == "punct" and self._current.text == ",":
                self._advance()
                self._expect_ident("max_each")
                self._expect_comparator_eq()
                max_each = int(self._advance_number())
        self._expect_punct(")")
        self._expect_ident("by")
        by = self._field_list()
        comparator, value = self._comparator_number()
        return CountAgg(
            block=block,
            distinct_field=distinct_field,
            max_each=max_each,
            by=by,
            comparator=comparator,
            value=value,
        )

    def _not_seen_before(self, block: str) -> NotSeenBefore:
        self._advance()  # "not_seen_before"
        self._expect_punct("(")
        fields = self._field_list()
        self._expect_punct(")")
        self._expect_ident("in")
        other_block = self._advance_ident("a block name")
        return NotSeenBefore(block=block, fields=fields, other_block=other_block)

    def _speed_kmh(self, block: str) -> SpeedKmh:
        self._advance()  # "speed_kmh"
        self._expect_punct("(")
        lat_field = self._advance_ident("a field name")
        self._expect_punct(",")
        lon_field = self._advance_ident("a field name")
        min_km = 0.0
        if self._current.kind == "punct" and self._current.text == ",":
            self._advance()
            self._expect_ident("min_km")
            self._expect_comparator_eq()
            min_km = self._advance_number()
        self._expect_punct(")")
        self._expect_ident("by")
        by = self._field_list()
        comparator, value = self._comparator_number()
        return SpeedKmh(
            block=block,
            lat_field=lat_field,
            lon_field=lon_field,
            min_km=min_km,
            by=by,
            comparator=comparator,
            value=value,
        )

    def _field_list(self) -> tuple[str, ...]:
        fields = [self._advance_ident("a field name")]
        while self._current.kind == "punct" and self._current.text == ",":
            self._advance()
            fields.append(self._advance_ident("a field name"))
        return tuple(fields)

    def _comparator_number(self) -> tuple[str, float]:
        if self._current.kind != "comparator":
            raise self._error("expected a comparator (>=, >, <=, <, ==)")
        comparator = self._advance().text
        value = self._advance_number()
        return comparator, value

    def _expect_comparator_eq(self) -> None:
        if self._current.kind != "comparator" or self._current.text not in {"=", "=="}:
            raise self._error("expected '='")
        self._advance()

    def _advance_ident(self, what: str) -> str:
        if self._current.kind != "ident":
            raise self._error(f"expected {what}")
        return self._advance().text

    def _advance_number(self) -> float:
        if self._current.kind != "number":
            raise self._error("expected a number")
        return float(self._advance().text)


def parse_condition(source: str) -> ConditionNode:
    """Parse a Sigma-style `condition` string into a `ConditionNode` tree."""
    if not source or not source.strip():
        raise SigmaConditionError("condition must not be empty")
    tokens = _tokenize(source)
    return _Parser(tokens, source=source).parse()
