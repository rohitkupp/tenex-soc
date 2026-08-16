"""Idempotent ETL: `data/baseline/*` -> `baseline_windows` / `baseline_profiles` /
`baseline_contacts` (docs/v2_migration/MIGRATION-01-evidence-first.md, change 1).

`datagen/generate_corpus.py::build_baseline()` (the delivered generator, wired into
`make gen-data`) writes three files this loader reads verbatim:

| File | Shape | Loads into |
|---|---|---|
| `baseline_windows.jsonl` | one JSON object per line: `entity_type`, `entity_value`, `window_start`, `features` (9 keys) | `baseline_windows` |
| `baseline_profiles.json` | `{"{user}\\|{metric}": {..., p50, p95, p99, mean, mad, n_windows}}` | `baseline_profiles` |
| `baseline_contacts.json` | `[{"scope": "user", "scope_value": <email>, "domain": ..., "contact_count": ...}]` | `baseline_contacts` (user rows) + derived department/org rows |

## Two mismatches, handled explicitly

**1. `features` carries 9 keys, not the ~50 the migration doc's SQL comment says ("same
~50-feature vector as L3").** `build_baseline()`'s `features` dict is exactly `n_events,
n_unique_domains, bytes_out, bytes_in, post_ratio, blocked_ratio, off_hours_ratio,
automation_ua_ratio, direct_ip_ratio` — nine keys, four of which (`n_events`, `bytes_out`,
`bytes_in`, `n_unique_domains`) also get a `baseline_profiles` row; the other five have raw
per-window values but no precomputed percentile. This loader does not fabricate the missing
~40 (the entity-relative z-variants, temporal/session/device families docs/04 §L3 defines) —
it loads exactly what the generator produces, so `baseline_windows.features` genuinely has 9
keys per row until a real L3 feature extractor (out of this change's scope) writes richer
windows. Reported to the user in this change's handoff notes for `docs/04`/`docs/02` to record.

**2. `build_baseline()` emits `baseline_contacts` at `scope="user"` only**, but the table (and
`app.baseline.resolve.contact_counts`) needs all three scopes so an evidence payload can say
"zero for Alice, one for Finance, four org-wide". `_rollup_contacts` below sums user-scope
`contact_count` into one `department` row per department (via
`app.baseline.org_directory.department_for_user` — see that module for why department comes
from reconstructing the generator's org rather than a stored directory) and one `scope="org"`
row (`scope_value="org"`) per domain, tenant-wide. A user the org directory doesn't recognize
still contributes to the org total; it just cannot contribute to a department total, and that
count is reported in `BaselineLoadSummary.users_without_department` rather than silently
dropped or guessed.

**A third, smaller gap, not named in the migration doc's mismatch list but handled the same
way:** `baseline_contacts.json` carries no `first_seen`/`last_seen` per contact — the generator
aggregates each (user, domain) pair over the whole 6-month period without tracking exactly when
in that period the contacts happened. Fabricating a specific date would be worse than the
alternative: every loaded contact row (user, department, and org scope alike) gets
`first_seen`/`last_seen` set to the *bounds of the baseline_windows period actually loaded in
this run* (min/max `window_start` across every row in `baseline_windows.jsonl`) — a fact that is
true (the contact happened sometime in that window) rather than an invented data point.

## Idempotency

Every write is `INSERT ... ON CONFLICT ... DO UPDATE` keyed on each table's real unique
constraint (`app.models.baseline_window.BaselineWindow`, `..baseline_profile.BaselineProfile`,
`..baseline_contact.BaselineContact`) — re-running with the same input data leaves row counts
unchanged by construction, not by a pre-check. `INSERT` statements are outside
`app.models.base`'s tenant-scoping guard (it only gates `SELECT`/`UPDATE`/`DELETE`), so no
`tenant_scope`/`tenant_session` wrapper is needed here; `tenant_id` is supplied explicitly on
every row instead, same as `app.scripts.seed`.
"""

from __future__ import annotations

import argparse
import json
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.baseline.org_directory import department_for_user
from app.core.db import get_session_factory
from app.core.logging import configure_logging, get_logger
from app.models.baseline_contact import BaselineContact
from app.models.baseline_profile import BaselineProfile
from app.models.baseline_window import BaselineWindow
from app.models.tenant import get_or_create_live_tenant

log = get_logger(__name__)

# app/baseline/loader.py -> app/baseline -> app -> backend
_BACKEND_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASELINE_DIR = _BACKEND_ROOT / "data" / "baseline"

_WINDOWS_FILENAME = "baseline_windows.jsonl"
_PROFILES_FILENAME = "baseline_profiles.json"
_CONTACTS_FILENAME = "baseline_contacts.json"

# scope_value for the tenant-wide rollup row -- "org" reads clearly next to scope="org" and
# needs no further lookup (unlike "department", there is only ever one org scope per tenant).
_ORG_SCOPE_VALUE = "org"

_UPSERT_CHUNK_SIZE = 5000

__all__ = ["DEFAULT_BASELINE_DIR", "BaselineLoadSummary", "load_baseline", "main"]


@dataclass(frozen=True, slots=True)
class BaselineLoadSummary:
    windows_loaded: int
    profiles_loaded: int
    contacts_user_loaded: int
    contacts_department_loaded: int
    contacts_org_loaded: int
    users_without_department: int
    window_period_start: datetime | None
    window_period_end: datetime | None


def _chunked(rows: list[dict[str, Any]], size: int) -> Iterator[list[dict[str, Any]]]:
    for i in range(0, len(rows), size):
        yield rows[i : i + size]


def _parse_ts(raw: str) -> datetime:
    """`build_baseline()` writes naive ISO timestamps (`datetime(2025, 9, 1)`, no tzinfo). Both
    `baseline_windows.window_start` and `baseline_contacts.first_seen`/`last_seen` are
    TIMESTAMPTZ, so a naive value is assumed UTC -- the same assumption the generator's own
    corpus timestamps make explicit elsewhere (`timezone.utc` on the corpus-file `start`)."""
    ts = datetime.fromisoformat(raw)
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=UTC)


def _read_windows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            rows.append(
                {
                    "entity_type": raw["entity_type"],
                    "entity_value": raw["entity_value"],
                    "window_start": _parse_ts(raw["window_start"]),
                    "features": raw["features"],
                }
            )
    return rows


def _read_profiles(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [
        {
            "entity_type": p["entity_type"],
            "entity_value": p["entity_value"],
            "metric": p["metric"],
            "p50": p.get("p50"),
            "p95": p.get("p95"),
            "p99": p.get("p99"),
            "mean": p.get("mean"),
            "mad": p.get("mad"),
            "n_windows": p["n_windows"],
        }
        for p in raw.values()
    ]


def _read_raw_contacts(path: Path) -> list[dict[str, Any]]:
    raw: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
    return raw


def _rollup_contacts(
    raw_contacts: list[dict[str, Any]],
    *,
    period_start: datetime,
    period_end: datetime,
) -> tuple[list[dict[str, Any]], int]:
    """Mismatch 1: expand `scope="user"` rows into user + department + org rows. Returns the
    full set of `baseline_contacts` rows to upsert and the count of distinct users the org
    directory (`app.baseline.org_directory`) could not place in a department."""
    user_rows = [c for c in raw_contacts if c.get("scope", "user") == "user"]
    passthrough_rows = [c for c in raw_contacts if c.get("scope", "user") != "user"]

    dept_totals: dict[tuple[str, str], int] = {}
    org_totals: dict[str, int] = {}
    unresolved_users: set[str] = set()

    out: list[dict[str, Any]] = []
    for c in user_rows:
        email, domain, count = c["scope_value"], c["domain"], int(c["contact_count"])
        out.append(
            {
                "scope": "user",
                "scope_value": email,
                "domain": domain,
                "contact_count": count,
                "first_seen": period_start,
                "last_seen": period_end,
            }
        )
        org_totals[domain] = org_totals.get(domain, 0) + count

        department = department_for_user(email)
        if department is None:
            unresolved_users.add(email)
            continue
        key = (department, domain)
        dept_totals[key] = dept_totals.get(key, 0) + count

    for (department, domain), count in dept_totals.items():
        out.append(
            {
                "scope": "department",
                "scope_value": department,
                "domain": domain,
                "contact_count": count,
                "first_seen": period_start,
                "last_seen": period_end,
            }
        )
    for domain, count in org_totals.items():
        out.append(
            {
                "scope": "org",
                "scope_value": _ORG_SCOPE_VALUE,
                "domain": domain,
                "contact_count": count,
                "first_seen": period_start,
                "last_seen": period_end,
            }
        )

    # Defensive, not exercised by the current generator (it only ever emits scope="user"):
    # a future generator version emitting department/org rows directly is passed through
    # rather than double-rolled-up.
    for c in passthrough_rows:
        raw_first_seen = c.get("first_seen")
        raw_last_seen = c.get("last_seen")
        out.append(
            {
                "scope": c["scope"],
                "scope_value": c["scope_value"],
                "domain": c["domain"],
                "contact_count": int(c["contact_count"]),
                "first_seen": _parse_ts(raw_first_seen) if raw_first_seen else period_start,
                "last_seen": _parse_ts(raw_last_seen) if raw_last_seen else period_end,
            }
        )

    return out, len(unresolved_users)


def _upsert_windows(session: Session, tenant_id: uuid.UUID, rows: Iterable[dict[str, Any]]) -> int:
    values = [{"tenant_id": tenant_id, **row} for row in rows]
    for chunk in _chunked(values, _UPSERT_CHUNK_SIZE):
        stmt = pg_insert(BaselineWindow).values(chunk)
        stmt = stmt.on_conflict_do_update(
            index_elements=[
                BaselineWindow.tenant_id,
                BaselineWindow.entity_type,
                BaselineWindow.entity_value,
                BaselineWindow.window_start,
            ],
            set_={"features": stmt.excluded.features},
        )
        session.execute(stmt)
    return len(values)


def _upsert_profiles(session: Session, tenant_id: uuid.UUID, rows: Iterable[dict[str, Any]]) -> int:
    values = [{"tenant_id": tenant_id, **row} for row in rows]
    for chunk in _chunked(values, _UPSERT_CHUNK_SIZE):
        stmt = pg_insert(BaselineProfile).values(chunk)
        stmt = stmt.on_conflict_do_update(
            index_elements=[
                BaselineProfile.tenant_id,
                BaselineProfile.entity_type,
                BaselineProfile.entity_value,
                BaselineProfile.metric,
            ],
            set_={
                "p50": stmt.excluded.p50,
                "p95": stmt.excluded.p95,
                "p99": stmt.excluded.p99,
                "mean": stmt.excluded.mean,
                "mad": stmt.excluded.mad,
                "n_windows": stmt.excluded.n_windows,
            },
        )
        session.execute(stmt)
    return len(values)


def _upsert_contacts(session: Session, tenant_id: uuid.UUID, rows: Iterable[dict[str, Any]]) -> int:
    values = [{"tenant_id": tenant_id, **row} for row in rows]
    for chunk in _chunked(values, _UPSERT_CHUNK_SIZE):
        stmt = pg_insert(BaselineContact).values(chunk)
        stmt = stmt.on_conflict_do_update(
            index_elements=[
                BaselineContact.tenant_id,
                BaselineContact.scope,
                BaselineContact.scope_value,
                BaselineContact.domain,
            ],
            set_={
                "contact_count": stmt.excluded.contact_count,
                "first_seen": stmt.excluded.first_seen,
                "last_seen": stmt.excluded.last_seen,
            },
        )
        session.execute(stmt)
    return len(values)


def load_baseline(
    session: Session,
    tenant_id: uuid.UUID,
    baseline_dir: Path = DEFAULT_BASELINE_DIR,
) -> BaselineLoadSummary:
    """Load `baseline_dir`'s three files into `tenant_id`'s baseline tables. Does not commit —
    the caller owns the transaction (mirrors `app.learning.benign_corpus.flag_benign_baseline`
    and friends, not `app.scripts.seed.seed`, since this is meant to compose inside a larger
    seed transaction as easily as run standalone).

    Raises `FileNotFoundError` if `baseline_dir` or any of its three expected files is missing —
    `main()` below is what turns that into a soft skip for `make seed` before
    docs/v2_migration change 13 has actually generated `data/baseline/`.
    """
    windows_path = baseline_dir / _WINDOWS_FILENAME
    profiles_path = baseline_dir / _PROFILES_FILENAME
    contacts_path = baseline_dir / _CONTACTS_FILENAME
    for path in (windows_path, profiles_path, contacts_path):
        if not path.is_file():
            raise FileNotFoundError(f"baseline input missing: {path}")

    windows = _read_windows(windows_path)
    profiles = _read_profiles(profiles_path)
    raw_contacts = _read_raw_contacts(contacts_path)

    starts = [w["window_start"] for w in windows]
    period_start = min(starts) if starts else datetime.now(UTC)
    period_end = max(starts) if starts else datetime.now(UTC)

    contact_rows, users_without_department = _rollup_contacts(
        raw_contacts, period_start=period_start, period_end=period_end
    )
    n_user = sum(1 for c in contact_rows if c["scope"] == "user")
    n_dept = sum(1 for c in contact_rows if c["scope"] == "department")
    n_org = sum(1 for c in contact_rows if c["scope"] == "org")

    n_windows = _upsert_windows(session, tenant_id, windows)
    n_profiles = _upsert_profiles(session, tenant_id, profiles)
    _upsert_contacts(session, tenant_id, contact_rows)

    if users_without_department:
        log.warning(
            "baseline.loader.users_without_department",
            tenant_id=str(tenant_id),
            count=users_without_department,
        )

    return BaselineLoadSummary(
        windows_loaded=n_windows,
        profiles_loaded=n_profiles,
        contacts_user_loaded=n_user,
        contacts_department_loaded=n_dept,
        contacts_org_loaded=n_org,
        users_without_department=users_without_department,
        window_period_start=period_start if starts else None,
        window_period_end=period_end if starts else None,
    )


def main() -> None:
    configure_logging()
    parser = argparse.ArgumentParser(
        description="Load the 6-month historical baseline (data/baseline/) into "
        "baseline_windows / baseline_profiles / baseline_contacts for the live tenant."
    )
    parser.add_argument("--baseline-dir", type=Path, default=DEFAULT_BASELINE_DIR)
    args = parser.parse_args()

    session = get_session_factory()()
    try:
        tenant = get_or_create_live_tenant(session)
        session.commit()

        try:
            summary = load_baseline(session, tenant.id, args.baseline_dir)
        except FileNotFoundError:
            # data/baseline/ doesn't exist until `make gen-data` has run
            # (docs/v2_migration change 13, not yet wired to full scale) -- a soft skip keeps
            # `make seed` usable for every other seed step in the meantime.
            log.warning(
                "baseline.loader.skipped_no_data",
                baseline_dir=str(args.baseline_dir),
                hint="run `make gen-data` to produce data/baseline/, then re-run `make seed`",
            )
            return

        session.commit()
        log.info(
            "baseline.loader.done",
            tenant_id=str(tenant.id),
            windows_loaded=summary.windows_loaded,
            profiles_loaded=summary.profiles_loaded,
            contacts_user_loaded=summary.contacts_user_loaded,
            contacts_department_loaded=summary.contacts_department_loaded,
            contacts_org_loaded=summary.contacts_org_loaded,
            users_without_department=summary.users_without_department,
        )
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()
