"""Unit tests for `app.detection.evidence.url_path.detect_url_path` -- CLAUDE.md's "every detector
needs a synthetic fixture that must fire and one that must not," against pure `EventRow` lists.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from app.detection.evidence.constants import EXTRACTOR_URL_ENTROPY, SIGNAL_URL_PATH
from app.detection.evidence.events_dao import EventRow
from app.detection.evidence.url_path import (
    _is_high_entropy_token,
    detect_url_path,
    raw_evidence_url_entropy,
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)

# Realistic REST-shaped, hyphenated English path segments -- none should ever match the
# high-entropy token pattern (the concrete false-positive risk this module's own docstring and
# `constants.py`'s `URL_PATH_TOKEN_MIN_DISTINCT_CHARS` explain: a pure charset match alone would
# flag these).
_ORDINARY_WORDS = (
    "check-in-endpoint",
    "user-profile-settings",
    "deployments-and-releases",
    "notifications-preferences",
    "account-management-panel",
    "organization-billing-info",
    "warehouse-query-statement",
    "dashboard-overview-panel",
    "repository-commit-history",
    "search-results-page-two",
    "invoice-download-receipt",
    "api-v2-user-profile",
)


def _benign_rows(n_pairs: int, domain: str, *, start_id: int = 0) -> list[EventRow]:
    rows: list[EventRow] = []
    eid = start_id
    for i in range(n_pairs):
        for j in range(6):
            word = _ORDINARY_WORDS[(i + j) % len(_ORDINARY_WORDS)]
            rows.append(
                EventRow(
                    id=eid,
                    ts=_T0 + timedelta(minutes=eid),
                    src_ip=f"10.0.1.{i}",
                    domain=domain,
                    principal="u",
                    url_path=f"/api/v2/{word}",
                )
            )
            eid += 1
    return rows


def _malicious_rows(domain: str, *, start_id: int, seed: int = 3) -> list[EventRow]:
    rng = random.Random(seed)
    rows: list[EventRow] = []
    eid = start_id
    for _j in range(6):
        tok = "".join(rng.choice("0123456789abcdef") for _ in range(32))
        rows.append(
            EventRow(
                id=eid,
                ts=_T0 + timedelta(minutes=eid),
                src_ip="10.0.2.99",
                domain=domain,
                principal="evil",
                url_path=f"/api/v2/{tok}/checkin",
            )
        )
        eid += 1
    return rows


def test_high_entropy_hex_token_fires_against_ordinary_domain_population() -> None:
    domain = "api.corp-tools.example"
    benign = _benign_rows(25, domain)
    malicious = _malicious_rows(domain, start_id=len(benign))

    drafts = detect_url_path(benign + malicious)

    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.detector_key == SIGNAL_URL_PATH
    assert draft.entity_type == "src_ip"
    assert draft.entity_value == "10.0.2.99"
    assert draft.explanation["flagged_on_entropy"] is True
    assert draft.explanation["flagged_on_segment_random"] is True
    # docs/04's exact explanation shape must be present.
    for key in ("mean_path_entropy", "segment_random_ratio", "sample_paths"):
        assert key in draft.explanation


def test_ordinary_rest_paths_do_not_fire() -> None:
    domain = "api.corp-tools.example"
    rows = _benign_rows(25, domain)

    assert detect_url_path(rows) == []


def test_pair_below_min_requests_is_not_scored() -> None:
    domain = "api.corp-tools.example"
    benign = _benign_rows(25, domain)
    # Only 2 malicious requests -- below `URL_PATH_MIN_REQUESTS` (5).
    malicious = _malicious_rows(domain, start_id=len(benign))[:2]

    drafts = detect_url_path(benign + malicious)
    assert drafts == []


def test_domain_with_too_few_pairs_is_not_scored() -> None:
    # Fewer than `URL_PATH_MIN_PAIRS_FOR_PERCENTILE` (20) distinct pairs on this domain -- no
    # meaningful percentile to compare against, even though the malicious pair itself would
    # otherwise clear every other bar.
    domain = "tiny-domain.example"
    benign = _benign_rows(5, domain)
    malicious = _malicious_rows(domain, start_id=len(benign))

    drafts = detect_url_path(benign + malicious)
    assert drafts == []


def test_is_high_entropy_token_rejects_ordinary_hyphenated_words() -> None:
    for word in _ORDINARY_WORDS:
        assert _is_high_entropy_token(word) is False, word


def test_is_high_entropy_token_accepts_a_random_hex_token() -> None:
    assert _is_high_entropy_token("c7f3a9e1b2a4f093") is True


def test_is_high_entropy_token_rejects_short_or_degenerate_segments() -> None:
    assert _is_high_entropy_token("c7f3a9") is False  # too short
    assert _is_high_entropy_token("aaaaaaaaaaaaaaaa") is False  # too few distinct chars


def test_events_without_url_path_are_ignored() -> None:
    domain = "api.corp-tools.example"
    rows = [
        EventRow(id=i, ts=_T0, src_ip=f"10.0.0.{i}", domain=domain, principal="u", url_path=None)
        for i in range(25)
    ]
    assert detect_url_path(rows) == []


def test_raw_evidence_url_entropy_carries_the_literal_path() -> None:
    domain = "api.corp-tools.example"
    benign = _benign_rows(25, domain)
    malicious = _malicious_rows(domain, start_id=len(benign))

    raw = raw_evidence_url_entropy(benign + malicious)

    assert len(raw) == 1
    r = raw[0]
    assert r.extractor == EXTRACTOR_URL_ENTROPY
    assert r.entity["type"] == "src_ip" and r.entity["value"] == "10.0.2.99"
    assert r.measurements["path"].startswith("/api/v2/")
    assert "checkin" in r.measurements["path"]
    assert r.measurements["path_depth"] >= 2
    assert isinstance(r.measurements["shannon_entropy"], float)
    assert isinstance(r.measurements["encoded_param_flag"], bool)
    assert r.contributing_line_numbers
    (query,) = r.baseline_queries
    assert query.historical_prefix == "entropy"


def test_raw_evidence_url_entropy_only_covers_pairs_that_also_fire_as_signals() -> None:
    domain = "api.corp-tools.example"
    rows = _benign_rows(25, domain)
    assert detect_url_path(rows) == []
    assert raw_evidence_url_entropy(rows) == []
