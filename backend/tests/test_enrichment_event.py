"""app/enrichment (top-level) -- `enrich_event`/`enrich_events`, the seam
`app/workers`' enricher worker calls (docs/13-MILESTONES.md M5), plus the package-wide
"no network calls at runtime" guarantee (docs/03-PARSERS-OCSF.md "Enrichment")."""

from __future__ import annotations

import ast
import socket
from pathlib import Path

import pytest

from app.enrichment import enrich_event, enrich_events

EVENT = {
    "principal": "u_ignored_here",  # already-pseudonymized by the time enrichment runs? no --
    # enrichment runs BEFORE anonymization (docs/03); this field is simply not read by
    # enrich_event at all, which is itself part of what's being verified below.
    "src_ip": "104.16.5.1",
    "dst_ip": "10.1.2.3",
    "domain": "www.evil-secure-vault-hub42.top",
    "url_path": "/beacon",
    "user_agent": "python-requests/2.32.3",
    "bytes_out": 128,
}


def test_enrich_event_returns_all_four_top_level_sections_plus_tags() -> None:
    result = enrich_event(EVENT)
    assert set(result) == {"src_ip", "dst_ip", "domain", "user_agent", "tags"}


def test_enrich_event_only_reads_the_four_documented_keys() -> None:
    """Extra keys on the input (a full `Event` row's `__dict__`, say) must be ignored, not
    rejected -- this is what makes `enrich_event` safe to call with an ORM row, an OCSF
    mapper's `hot_columns()` dict, or a bare four-key dict interchangeably."""
    minimal = {"src_ip": EVENT["src_ip"], "domain": EVENT["domain"]}
    full = dict(EVENT)
    assert enrich_event(minimal)["src_ip"] == enrich_event(full)["src_ip"]
    assert enrich_event(minimal)["domain"] == enrich_event(full)["domain"]


def test_enrich_event_composes_the_three_structured_enrichments_correctly() -> None:
    result = enrich_event(EVENT)
    assert result["src_ip"]["org"] == "Cloudflare"
    assert result["src_ip"]["is_hosting"] is True
    assert result["dst_ip"]["is_special_use"] is True  # 10.1.2.3 is RFC 1918
    assert result["domain"]["registrable_domain"] == "evil-secure-vault-hub42.top"
    assert result["domain"]["tld_risk_tier"] == "high"
    assert result["user_agent"]["family"] == "Python Requests"
    assert result["user_agent"]["is_automation_tool"] is True


def test_enrich_event_tags_reflect_both_domain_and_ip_hosting_signal() -> None:
    result = enrich_event(EVENT)
    assert "high_abuse_tld" in result["tags"]
    assert "automation_client" in result["tags"]
    assert "hosting_infrastructure" in result["tags"]  # from src_ip's Cloudflare hit


def test_enrich_event_handles_a_fully_empty_event_gracefully() -> None:
    result = enrich_event({})
    assert result == {
        "src_ip": None,
        "dst_ip": None,
        "domain": None,
        "user_agent": None,
        "tags": [],
    }


def test_enrich_events_batch_preserves_order_and_is_independent_per_event() -> None:
    events = [
        {"domain": "github.com"},
        {"domain": "www.evil-secure-vault-hub42.top"},
        {},
    ]
    results = enrich_events(events)
    assert len(results) == 3
    assert results[0]["domain"]["registrable_domain"] == "github.com"
    assert results[1]["domain"]["tld_risk_tier"] == "high"
    assert results[2]["domain"] is None


def test_enrich_event_result_is_json_serializable() -> None:
    """`events.enrichment` is a JSONB column (docs/02) -- the returned dict must round-trip
    through `json.dumps` with no custom encoder."""
    import json

    json.dumps(enrich_event(EVENT))


def test_no_network_call_anywhere_in_a_full_enrich_event_run() -> None:
    def _blocked_connect(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network connect() attempted during enrichment")

    def _blocked_getaddrinfo(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("DNS resolution attempted during enrichment")

    original_connect = socket.socket.connect
    original_getaddrinfo = socket.getaddrinfo
    socket.socket.connect = _blocked_connect  # type: ignore[method-assign]
    socket.getaddrinfo = _blocked_getaddrinfo  # type: ignore[assignment]
    try:
        result = enrich_event(EVENT)
        assert result["domain"] is not None  # actually did the work, not a no-op
    finally:
        socket.socket.connect = original_connect  # type: ignore[method-assign]
        socket.getaddrinfo = original_getaddrinfo


# ---------------------------------------------------------------------------- static proof


ENRICHMENT_PACKAGE = Path(__file__).resolve().parents[1] / "app" / "enrichment"
PRIVACY_PACKAGE = Path(__file__).resolve().parents[1] / "app" / "privacy"
BANNED_MODULES = {"socket", "requests", "httpx", "urllib.request", "urllib3", "aiohttp"}


def _imported_module_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


@pytest.mark.parametrize(
    "path",
    sorted((*ENRICHMENT_PACKAGE.glob("*.py"), *PRIVACY_PACKAGE.glob("*.py"))),
    ids=lambda p: p.name,
)
def test_no_networking_module_is_imported_anywhere_in_the_enrichment_or_privacy_path(
    path: Path,
) -> None:
    """Static, exhaustive proof to go with the runtime socket-blocking tests above:
    neither package imports `requests`/`httpx`/`socket`/`urllib.request`/anything else
    that could make a network call, in any file, not just the ones exercised by the
    dynamic tests."""
    imported = _imported_module_names(path)
    hit = imported & BANNED_MODULES
    assert not hit, f"{path.name} imports networking module(s): {hit}"
