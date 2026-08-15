"""Task 3's own verification bar, quoted in the milestone brief: "Attack your own
validator and paste the results: attempts at DROP/DELETE/UPDATE, semicolon stacking, a CTE
that writes, a UNION reaching `events` or `users`, comment-based evasion, and a
prompt-injection string in the question itself. Every one must be rejected with the SQL
shown." Every attack below is a literal instance of that list; each asserts both that the
query is rejected (`SqlRejectedError`) *and* that no row is ever produced for it, which
would only be possible if `validate_and_prepare` had let something through despite raising.

(The prompt-injection-in-the-question case is exercised end to end in
`tests/test_tier2_nl_to_sql.py`, not here — this file is only about what happens to a SQL
string once one exists; that file is about how one comes to exist in the first place.)
"""

from __future__ import annotations

import pytest

from app.tier2.sql_validator import MAX_ROWS, SqlRejectedError, validate_and_prepare
from app.tier2.views import ALLOWED_VIEWS, TIER2_SIGNATURES_VIEW

# ---------------------------------------------------------------------------- the attacks


@pytest.mark.parametrize(
    "attack_sql",
    [
        pytest.param("DROP TABLE tier2_signatures_v", id="drop"),
        pytest.param("DROP TABLE events", id="drop-events"),
        pytest.param("DELETE FROM tier2_signatures_v", id="delete"),
        pytest.param("DELETE FROM events WHERE true", id="delete-events"),
        pytest.param("UPDATE tier2_signatures_v SET confidence = 0", id="update"),
        pytest.param("UPDATE users SET password_hash = 'x'", id="update-users"),
        pytest.param("INSERT INTO tier2_signatures_v (id) VALUES (gen_random_uuid())", id="insert"),
        pytest.param("TRUNCATE tier2_signatures_v", id="truncate"),
        pytest.param("ALTER TABLE tier2_signatures_v ADD COLUMN x TEXT", id="alter"),
        pytest.param("CREATE TABLE evil (x TEXT)", id="create"),
        pytest.param("GRANT ALL ON tier2_signatures_v TO PUBLIC", id="grant"),
    ],
)
def test_ddl_dml_is_rejected(attack_sql: str) -> None:
    with pytest.raises(SqlRejectedError):
        validate_and_prepare(attack_sql)


@pytest.mark.parametrize(
    "attack_sql",
    [
        pytest.param(
            "SELECT * FROM tier2_signatures_v; DROP TABLE tier2_signatures_v", id="stacked-drop"
        ),
        pytest.param(
            "SELECT * FROM tier2_signatures_v; SELECT * FROM users", id="stacked-select-users"
        ),
        pytest.param("SELECT * FROM tier2_signatures_v;", id="lone-trailing-semicolon"),
        pytest.param(
            "SELECT * FROM tier2_signatures_v; -- trailing comment only",
            id="semicolon-then-comment",
        ),
    ],
)
def test_semicolon_stacking_is_rejected(attack_sql: str) -> None:
    with pytest.raises(SqlRejectedError, match="semicolon"):
        validate_and_prepare(attack_sql)


@pytest.mark.parametrize(
    "attack_sql",
    [
        pytest.param(
            "WITH x AS (DELETE FROM tier2_signatures_v RETURNING *) SELECT * FROM x",
            id="cte-delete",
        ),
        pytest.param(
            "WITH x AS (UPDATE tier2_signatures_v SET confidence = 1 RETURNING *) SELECT * FROM x",
            id="cte-update",
        ),
        pytest.param(
            "WITH x AS (INSERT INTO tier2_signatures_v (id) VALUES (gen_random_uuid()) RETURNING *) "
            "SELECT * FROM x",
            id="cte-insert",
        ),
    ],
)
def test_writing_cte_is_rejected(attack_sql: str) -> None:
    with pytest.raises(SqlRejectedError):
        validate_and_prepare(attack_sql)


def test_cte_named_after_a_forbidden_table_cannot_smuggle_a_real_reference_to_it() -> None:
    """A found-during-testing bypass, fixed in `app.tier2.sql_validator._real_table_names`:
    naming a CTE the same as a real forbidden table used to make the *real* reference to
    that table (inside the CTE's own body) disappear from the allowlist check, because a
    naive "all table names minus every CTE alias name" treats both occurrences of the
    string "users" as the same thing. `WITH users AS (SELECT * FROM users) SELECT * FROM
    users` must still be rejected for touching the real `users` table."""
    with pytest.raises(SqlRejectedError, match="allowlist"):
        validate_and_prepare("WITH users AS (SELECT * FROM users) SELECT * FROM users")


@pytest.mark.parametrize(
    "attack_sql",
    [
        pytest.param(
            "SELECT * FROM tier2_signatures_v UNION SELECT * FROM events", id="union-events"
        ),
        pytest.param(
            "SELECT * FROM tier2_signatures_v UNION SELECT * FROM users", id="union-users"
        ),
        pytest.param(
            "SELECT id, tenant_hash FROM tier2_signatures_v UNION ALL "
            "SELECT id::text, password_hash FROM users",
            id="union-all-users-password",
        ),
        pytest.param(
            "SELECT * FROM tier2_signatures_v INTERSECT SELECT * FROM events", id="intersect-events"
        ),
    ],
)
def test_union_reaching_events_or_users_is_rejected(attack_sql: str) -> None:
    with pytest.raises(SqlRejectedError):
        validate_and_prepare(attack_sql)


@pytest.mark.parametrize(
    "attack_sql",
    [
        pytest.param(
            "SELECT * FROM tier2_signatures_v -- DROP TABLE tier2_signatures_v\n", id="line-comment"
        ),
        pytest.param(
            "SELECT * /* sneaky */ FROM tier2_signatures_v /* DROP TABLE users */",
            id="block-comment",
        ),
        pytest.param("SeLeCt * FrOm tier2_signatures_v", id="case-randomization"),
    ],
)
def test_comment_and_case_evasion_does_not_bypass_the_allowlist(attack_sql: str) -> None:
    """These are not attacks on their own (a comment or mixed case around an otherwise
    legitimate query is harmless) -- they are attempts to see whether *disguising* an
    attack this way changes the outcome. It must not: the AST-based validator discards
    comments during tokenization and is case-insensitive on keywords by construction, so
    each of these is accepted exactly as if the comment/casing weren't there — proving a
    regex/keyword validator's usual blind spot doesn't exist here."""
    result = validate_and_prepare(attack_sql)
    assert result.tables == (TIER2_SIGNATURES_VIEW,)


@pytest.mark.parametrize(
    "attack_sql",
    [
        pytest.param("SELECT * FROM events", id="events-direct"),
        pytest.param("SELECT * FROM users", id="users-direct"),
        pytest.param("SELECT email, password_hash FROM users", id="users-columns"),
        pytest.param("SELECT * FROM pseudonym_map", id="pseudonym-map"),
        pytest.param(
            "SELECT * FROM tier2_signatures_v WHERE tenant_hash IN "
            "(SELECT tenant_hash FROM tier2_signatures_v) OR EXISTS "
            "(SELECT 1 FROM users)",
            id="nested-subquery-users",
        ),
        pytest.param(
            "SELECT (SELECT password_hash FROM users LIMIT 1) AS leak", id="scalar-subquery-users"
        ),
        pytest.param("SELECT * FROM tier2_signatures", id="base-table-not-view"),
        pytest.param("SELECT * FROM pg_catalog.pg_shadow", id="pg-shadow"),
    ],
)
def test_out_of_scope_table_reference_is_rejected(attack_sql: str) -> None:
    with pytest.raises(SqlRejectedError, match="allowlist"):
        validate_and_prepare(attack_sql)


@pytest.mark.parametrize(
    "attack_sql",
    [
        pytest.param("SELECT pg_sleep(10) FROM tier2_signatures_v", id="pg-sleep"),
        pytest.param(
            "SELECT * FROM tier2_signatures_v WHERE pg_sleep(5) IS NULL", id="pg-sleep-in-where"
        ),
        pytest.param(
            "SELECT dblink('host=evil.example', 'select 1') FROM tier2_signatures_v", id="dblink"
        ),
        pytest.param(
            "SELECT pg_read_file('/etc/passwd') FROM tier2_signatures_v", id="pg-read-file"
        ),
        pytest.param(
            "SELECT set_config('statement_timeout', '0', false) FROM tier2_signatures_v",
            id="set-config",
        ),
        pytest.param(
            "SELECT pg_terminate_backend(1) FROM tier2_signatures_v", id="terminate-backend"
        ),
    ],
)
def test_dangerous_functions_are_rejected(attack_sql: str) -> None:
    with pytest.raises(SqlRejectedError, match="not allowed"):
        validate_and_prepare(attack_sql)


@pytest.mark.parametrize(
    "attack_sql",
    [
        pytest.param("SELECT pg_sleep(10)", id="pg-sleep-no-table"),
        pytest.param("SELECT dblink('host=evil.example', 'select 1')", id="dblink-no-table"),
    ],
)
def test_dangerous_function_with_no_table_reference_is_still_rejected(attack_sql: str) -> None:
    """No `FROM` at all is rejected too (`does not reference any allowlisted table`) --
    a different, still-correct reason than the function blocklist. Either way, nothing
    calling `pg_sleep`/`dblink` is ever accepted."""
    with pytest.raises(SqlRejectedError):
        validate_and_prepare(attack_sql)


@pytest.mark.parametrize(
    "attack_sql",
    [
        pytest.param("SELECT * INTO evil_table FROM tier2_signatures_v", id="select-into"),
        pytest.param("SELECT * FROM tier2_signatures_v FOR UPDATE", id="for-update"),
        pytest.param("SELECT * FROM tier2_signatures_v FOR SHARE", id="for-share"),
        pytest.param("EXPLAIN ANALYZE SELECT * FROM tier2_signatures_v", id="explain-analyze"),
        pytest.param("COPY tier2_signatures_v TO '/tmp/exfil.csv'", id="copy-out"),
        pytest.param("", id="empty-string"),
        pytest.param("   ", id="whitespace-only"),
        pytest.param("not even sql", id="garbage"),
    ],
)
def test_other_out_of_scope_constructs_are_rejected(attack_sql: str) -> None:
    with pytest.raises(SqlRejectedError):
        validate_and_prepare(attack_sql)


# ---------------------------------------------------------------------------- the SQL is always visible


def test_sqlrejected_carries_a_human_readable_reason_never_silence() -> None:
    """docs/09: "Always return the generated SQL, even when the query is rejected —
    especially then." This module can't test the API response shape (that's
    `tests/test_tier2_api.py`), but it can prove the exception itself always carries
    something displayable, which is the property that response depends on."""
    with pytest.raises(SqlRejectedError) as exc_info:
        validate_and_prepare("DROP TABLE tier2_signatures_v")
    assert exc_info.value.reason
    assert isinstance(exc_info.value.reason, str)


# ---------------------------------------------------------------------------- legitimate queries still work


def test_a_legitimate_query_is_accepted_and_limit_injected() -> None:
    result = validate_and_prepare("SELECT incident_type, confidence FROM tier2_signatures_v")
    assert "LIMIT" in result.sql.upper()
    assert f"LIMIT {MAX_ROWS}" in result.sql
    assert result.tables == (TIER2_SIGNATURES_VIEW,)


def test_an_oversized_limit_is_clamped_down() -> None:
    result = validate_and_prepare(f"SELECT * FROM tier2_signatures_v LIMIT {MAX_ROWS * 100}")
    assert f"LIMIT {MAX_ROWS}" in result.sql
    assert str(MAX_ROWS * 100) not in result.sql


def test_a_smaller_existing_limit_is_preserved_not_widened() -> None:
    result = validate_and_prepare("SELECT * FROM tier2_signatures_v LIMIT 5")
    assert "LIMIT 5" in result.sql
    assert f"LIMIT {MAX_ROWS}" not in result.sql


def test_read_only_cte_is_accepted() -> None:
    """The other half of the CTE rule: a CTE that only reads must not be collateral
    damage from blocking CTEs that write."""
    result = validate_and_prepare(
        "WITH ranked AS (SELECT incident_type, confidence FROM tier2_signatures_v) "
        "SELECT * FROM ranked WHERE confidence > 0.5"
    )
    assert result.tables == (TIER2_SIGNATURES_VIEW,)


def test_both_allowlisted_views_together_is_accepted() -> None:
    result = validate_and_prepare(
        "SELECT s.incident_type, o.tenant_count FROM tier2_signatures_v s "
        "JOIN tier2_indicator_overlap_v o ON true"
    )
    assert set(result.tables) == ALLOWED_VIEWS


def test_aggregate_functions_are_not_mistaken_for_forbidden_ones() -> None:
    """COUNT/AVG/MIN/MAX/array_agg must never trip the function blocklist -- these are the
    bread and butter of every legitimate Tier 2 question."""
    result = validate_and_prepare(
        "SELECT incident_type, COUNT(*), AVG(confidence), MIN(observed_at), MAX(observed_at) "
        "FROM tier2_signatures_v GROUP BY incident_type"
    )
    assert result.tables == (TIER2_SIGNATURES_VIEW,)
