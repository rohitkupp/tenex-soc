"""The enforcement boundary docs/06 "Text-to-SQL safety" describes: every string this
package is ever asked to execute — LLM-generated or the canned fallback alike — passes
through `validate_and_prepare` first. Nothing downstream trusts the caller to have already
checked; there is exactly one place a query is allowed to become "safe to run."

## What "rejected" means, precisely

`sqlglot.parse` builds a real AST (Postgres dialect); every check below inspects that tree,
never the raw string. That is deliberate — see `tests/test_tier2_sql_validator.py` for the
comment-evasion attack this specifically defeats (`sqlglot` discards comments during
tokenization, so `SELECT ... -- ; DROP TABLE x` is structurally just a `SELECT`, and a
regex/keyword-matching validator that had to reason about comment syntax itself would be a
much larger attack surface than "trust the parser docs/06 already named").

The rule, in order:

1. **No semicolons, full stop** — checked on the raw text, not inferred from statement
   count. A lone trailing `;` before a comment-only remainder can parse as a second,
   *empty* `Semicolon` statement (verified against this `sqlglot` version) that a
   count-based check alone would wave through; docs/06 says "no `;`", not "no second
   non-empty statement", so that's the literal rule this enforces.
2. **Exactly one parsed statement.**
3. **That statement's root node must be `sqlglot.exp.Select`** — not `Union`/`Intersect`/
   `Except` (rules out "a UNION reaching `events`/`users`" by construction: a top-level
   `UNION` simply is not a `Select` node, whatever its branches reference), not
   `Insert`/`Update`/`Delete`/`Drop`/`Create`/`Grant`/`Set`/`Copy`/`Command`/etc. A
   read-only `WITH x AS (SELECT ...) SELECT ...` still parses with root type `Select` (the
   CTE lives in a `with_` arg on the same node), so this rule does not reject ordinary
   CTEs — only the next rule does, for CTEs that write.
4. **No mutating/DDL node anywhere in the tree**, including inside a CTE body — this is
   what actually blocks `WITH x AS (DELETE FROM foo RETURNING *) SELECT * FROM x` (root
   type is still `Select`; the `Delete` is a descendant `find_all` still reaches).
5. **No `SELECT INTO`** (`args["into"]`) and **no locking clause** (`FOR UPDATE`/`FOR
   SHARE`, `args["locks"]`) — the first creates a table (a write dressed as a `Select`),
   the second would fail anyway (the role has no `UPDATE` grant to lock rows) but is
   rejected here rather than surfaced as a confusing Postgres permission error.
6. **Every table reference — anywhere in the tree, including nested subqueries and
   CTEs — must be on `app.tier2.views.ALLOWED_VIEWS`.** `find_all(exp.Table)` walks the
   whole tree, so `SELECT (SELECT password_hash FROM users LIMIT 1)` is caught even though
   `users` never appears in a top-level `FROM`.
7. **No call to a blocklisted function** (`pg_sleep`, `dblink*`, `lo_*`, `pg_read_file`,
   etc.) — checked both structurally (by AST node name) and as a regex backstop over the
   regenerated SQL text, in case a future `sqlglot` version classifies one of these
   differently than this version does. Belt and suspenders around the *one* layer here
   that depends on `sqlglot`'s function taxonomy rather than pure grammar shape.

Then, only for a query that survives all seven: **a hard `LIMIT`** is injected (absent) or
clamped (present but over `MAX_ROWS`) before the rewritten SQL is handed back — never the
caller's job, so there is no path that executes an unlimited query.

## What this module does *not* do

It does not connect to Postgres and does not know about the `tier2_readonly` role's grants.
Those are `app.tier2.readonly_db`'s job, and are the second, independent layer docs/06 asks
for: even a hypothetical bypass of every check above still hits a database role with
`SELECT` on exactly two views and nothing else (`tests/test_tier2_readonly_role.py` proves
that against the real database, not by inspecting this file).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import sqlglot
from sqlglot import exp
from sqlglot.optimizer.scope import Scope, build_scope

from app.tier2.views import ALLOWED_VIEWS

MAX_ROWS = 500

# Every node type sqlglot(30.x)/Postgres can produce for a statement that writes,
# alters schema, or issues an administrative command — checked with find_all() so a
# match anywhere in the tree (top-level *or* nested inside a CTE) is rejected. Deliberately
# broad: this list costs nothing to over-include (a real analytical question never needs
# any of these), and the two "REJECTED unless" tests in the milestone brief are exactly
# about what happens when one shows up disguised inside an otherwise SELECT-shaped query.
_FORBIDDEN_NODE_TYPES: tuple[type[exp.Expression], ...] = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
    exp.Create,
    exp.Drop,
    exp.Alter,
    exp.TruncateTable,
    exp.Grant,
    exp.Set,
    exp.Copy,
    exp.Command,
    exp.Cache,
    exp.Comment,
    exp.Use,
    exp.Attach,
    exp.Detach,
)

# Functions that are safe for *any* role to be granted EXECUTE on by default in stock
# Postgres (most of `pg_catalog` is PUBLIC-executable) but have no legitimate use in an
# analytical SELECT over two narrow views, and either burn wall-clock time
# (`pg_sleep`, capped by `statement_timeout` but still a pointless DoS knob), reach outside
# the database (`dblink*`, `lo_import`/`lo_export`, `pg_read_*file*`), or affect session/
# server state (`set_config`, `pg_terminate_backend`, `pg_cancel_backend`,
# `pg_reload_conf`). None of these are reachable via the two allowlisted views' own
# columns, so a legitimate question never needs them.
_FORBIDDEN_FUNCTIONS: frozenset[str] = frozenset(
    {
        "pg_sleep",
        "pg_sleep_for",
        "pg_sleep_until",
        "pg_read_file",
        "pg_read_binary_file",
        "pg_ls_dir",
        "pg_ls_logdir",
        "pg_ls_waldir",
        "pg_stat_file",
        "lo_import",
        "lo_export",
        "lo_get",
        "lo_put",
        "dblink",
        "dblink_connect",
        "dblink_connect_u",
        "dblink_exec",
        "dblink_send_query",
        "pg_terminate_backend",
        "pg_cancel_backend",
        "pg_reload_conf",
        "pg_read_server_files",
        "set_config",
        "current_setting",
        "pg_export_snapshot",
    }
)
_FORBIDDEN_FUNCTION_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(name) for name in _FORBIDDEN_FUNCTIONS) + r")\s*\(",
    re.IGNORECASE,
)


class SqlRejectedError(Exception):
    """The generated SQL failed validation. `reason` is safe to show the caller — it never
    echoes back attacker-controlled content beyond identifiers already present in their
    own query (a table name, a function name), and docs/09 requires the *rejected* SQL
    itself to still be returned to the caller alongside this, "especially then" — rejection
    is a transparency event, not a reason to go quiet.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ValidatedQuery:
    sql: str
    """The rewritten, `LIMIT`-capped SQL text — safe to execute as-is against the
    `tier2_readonly` role. Always different from the input text (at minimum, a `LIMIT`
    clause was added or clamped)."""
    tables: tuple[str, ...]
    """The allowlisted view name(s) actually referenced, sorted — informational, e.g. for
    logging which of the two views a question touched."""


def _check_no_semicolons(sql: str) -> None:
    if ";" in sql:
        raise SqlRejectedError("semicolons are not allowed")


def _parse_single_statement(sql: str) -> exp.Expression:
    try:
        statements = [s for s in sqlglot.parse(sql, read="postgres") if s is not None]
    except Exception as exc:  # sqlglot raises its own ParseError/TokenError hierarchy
        raise SqlRejectedError(f"could not parse SQL: {exc}") from exc
    if len(statements) != 1:
        raise SqlRejectedError("exactly one SQL statement is required")
    return statements[0]


def _check_is_plain_select(root: exp.Expression) -> exp.Select:
    if not isinstance(root, exp.Select):
        raise SqlRejectedError(
            f"only a single SELECT statement is allowed, got {type(root).__name__}"
        )
    return root


def _check_no_select_into_or_locks(root: exp.Select) -> None:
    if root.args.get("into"):
        raise SqlRejectedError("SELECT INTO is not allowed")
    if root.args.get("locks"):
        raise SqlRejectedError("row-locking clauses (FOR UPDATE / FOR SHARE) are not allowed")


def _check_no_forbidden_nodes(root: exp.Select) -> None:
    found = list(root.find_all(_FORBIDDEN_NODE_TYPES))
    if found:
        kinds = sorted({type(node).__name__ for node in found})
        raise SqlRejectedError(f"disallowed statement type(s) inside query: {', '.join(kinds)}")


def _real_table_names(root: exp.Select) -> set[str]:
    """Every table name genuinely resolved against the database — i.e. excluding a
    `Table` node that is really a reference to a `WITH x AS (...)` CTE defined
    somewhere in this query (`ranked` in `WITH ranked AS (...) SELECT * FROM ranked`).

    A naive "all `exp.Table` node names, minus every CTE alias name" (an earlier version
    of this function) has a real bypass: `WITH users AS (SELECT * FROM users) SELECT *
    FROM users` — set-difference-by-name removes *both* the CTE's own alias reference
    *and* the CTE body's genuine reference to the real `users` table, since both nodes
    happen to share the string `"users"`. `sqlglot.optimizer.scope.build_scope` resolves
    each `Table` node against the scope it actually appears in, so it correctly tells
    the CTE-body's `FROM users` (resolves to a real `Table` source) apart from the outer
    query's `FROM users` (resolves to a `Scope`, i.e. the CTE) even though the two nodes
    are textually identical — verified empirically against exactly this attack.
    """
    names: set[str] = set()
    for scope in build_scope(root).traverse():
        for table in scope.tables:
            source = scope.sources.get(table.alias_or_name)
            if isinstance(source, Scope):
                continue  # a CTE/derived-table reference, not a real table
            names.add(table.name)
    return names


def _check_tables_allowlisted(root: exp.Select, allowed_tables: frozenset[str]) -> tuple[str, ...]:
    referenced = sorted(_real_table_names(root))
    if not referenced:
        raise SqlRejectedError("query does not reference any allowlisted table")
    disallowed = [name for name in referenced if name not in allowed_tables]
    if disallowed:
        raise SqlRejectedError(
            f"query references table(s) not on the allowlist: {', '.join(disallowed)}"
        )
    return tuple(referenced)


def _check_no_forbidden_functions(root: exp.Select) -> None:
    for func in root.find_all((exp.Anonymous, exp.Func)):
        name = (getattr(func, "name", "") or "").lower()
        if name in _FORBIDDEN_FUNCTIONS:
            raise SqlRejectedError(f"function {name}() is not allowed")
    # Regex backstop over the regenerated SQL text — independent of how this sqlglot
    # version classifies a given function's AST node (see module docstring, check 7).
    rendered = root.sql(dialect="postgres")
    match = _FORBIDDEN_FUNCTION_PATTERN.search(rendered)
    if match:
        raise SqlRejectedError(f"function {match.group(1).lower()}() is not allowed")


def _existing_limit(root: exp.Select) -> int | None:
    limit_node = root.args.get("limit")
    if limit_node is None:
        return None
    value = limit_node.expression
    if isinstance(value, exp.Literal) and value.is_number:
        try:
            return int(value.this)
        except ValueError:
            return None
    return None


def _cap_limit(root: exp.Select, max_rows: int) -> exp.Select:
    current = _existing_limit(root)
    if current is None or current > max_rows or current < 0:
        root.set("limit", exp.Limit(expression=exp.Literal.number(max_rows)))
    return root


def validate_and_prepare(
    sql: str,
    *,
    allowed_tables: frozenset[str] = ALLOWED_VIEWS,
    max_rows: int = MAX_ROWS,
) -> ValidatedQuery:
    """Raises `SqlRejectedError` with a human-readable reason, or returns a `ValidatedQuery`
    whose `.sql` is guaranteed: a single read-only `SELECT`, touching only
    `allowed_tables`, with no semicolon, no DDL/DML/admin construct anywhere in the tree,
    and a `LIMIT` at or below `max_rows`."""
    if not sql or not sql.strip():
        raise SqlRejectedError("empty query")

    _check_no_semicolons(sql)
    root = _parse_single_statement(sql)
    select_root = _check_is_plain_select(root)
    _check_no_select_into_or_locks(select_root)
    _check_no_forbidden_nodes(select_root)
    tables = _check_tables_allowlisted(select_root, allowed_tables)
    _check_no_forbidden_functions(select_root)
    _cap_limit(select_root, max_rows)

    return ValidatedQuery(sql=select_root.sql(dialect="postgres"), tables=tables)
