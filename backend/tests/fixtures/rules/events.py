"""Synthetic-but-realistic `events` rows for the Sigma rule fixtures (docs/04: "Each rule needs a
positive and a negative fixture in tests/fixtures/rules/").

`zscaler_event` produces the same shape `app/parsers/zscaler.py` + `hot_columns()` +
`model_dump(mode="json")` actually write into `events.ocsf` (per `app/pipeline/stages/parse.py`:
`ocsf=result.model_dump(mode="json")`) — every key a rule's YAML can reference through
`app.detection.sigma.fields` is present here under its real OCSF path, not a shortcut shape a
fixture-only code path would accept but production data never would. Building it by hand (rather
than running the real parser over a hand-written log line) is a deliberate simplification this
test package owns the right to make — `tests/test_parsers_zscaler.py` already covers the parser's
own line -> OCSF fidelity; what these fixtures need to prove is that the *evaluator* reacts
correctly to a given OCSF shape, not that the parser produces it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.storage.event_writer import SimpleEventRecord

# A stable anchor so every fixture module's timestamps are legible relative to one another
# without importing `datetime.now()` (determinism, per CLAUDE.md's "seeded RNG... same input
# file must produce the same signals").
T0 = datetime.fromisoformat("2026-03-02T12:00:00+00:00")


_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def zscaler_event(
    principal: str,
    ts: datetime,
    domain: str,
    *,
    disposition: str = "allowed",
    src_ip: str = "203.0.113.5",
    dst_ip: str | None = None,
    http_method: str = "GET",
    url_path: str = "/",
    user_agent: str = _DEFAULT_UA,
    bytes_out: int = 1000,
    bytes_in: int = 5000,
    status_code: int = 200,
    url_supercategory: str | None = None,
    url_category: str | None = None,
    threat_name: str | None = None,
    threat_category: str | None = None,
    risk_score: int | None = None,
    dlp_engine: str | None = None,
    dlp_dictionaries: str | None = None,
    enrichment: dict[str, Any] | None = None,
) -> SimpleEventRecord:
    """One ZScaler NSS Web event, in `HTTPActivity` (4002) OCSF shape."""
    unmapped: dict[str, Any] = {}
    if url_supercategory is not None:
        unmapped["url_supercategory"] = url_supercategory
    if dlp_engine is not None:
        unmapped["dlp_engine"] = dlp_engine
    if dlp_dictionaries is not None:
        unmapped["dlp_dictionaries"] = dlp_dictionaries
    malware: list[dict[str, Any]] = []
    if threat_name is not None:
        malware.append(
            {
                "name": threat_name,
                "classification_ids": [threat_category] if threat_category else [],
            }
        )
    ocsf: dict[str, Any] = {
        "class_uid": 4002,
        "category_uid": 4,
        "activity_name": disposition,
        "time": ts.isoformat(),
        "source_type": "zscaler",
        "line_no": 1,
        "event_key": "k",
        "actor": {"user": {"email_addr": principal}},
        "src_endpoint": {"ip": src_ip},
        "dst_endpoint": {"ip": dst_ip} if dst_ip else None,
        "http_request": {
            "url": {
                "hostname": domain,
                "path": url_path,
                "category_ids": [url_category] if url_category else [],
            },
            "http_method": http_method,
            "user_agent": user_agent,
        },
        "http_response": {"code": status_code},
        "traffic": {"bytes_out": bytes_out, "bytes_in": bytes_in},
        "disposition": disposition,
        "risk_score": risk_score,
        "malware": malware,
        "unmapped": unmapped,
    }
    return SimpleEventRecord(
        ts=ts,
        source_type="zscaler",
        raw_line_no=1,
        ocsf_class_uid=4002,
        ocsf=ocsf,
        principal=principal,
        src_ip=src_ip,
        dst_ip=dst_ip,
        domain=domain,
        url_path=url_path,
        action=disposition,
        http_method=http_method,
        status_code=status_code,
        bytes_out=bytes_out,
        bytes_in=bytes_in,
        user_agent=user_agent,
        enrichment=enrichment or {},
    )
