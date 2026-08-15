"""Deterministic incident titling (docs/05 "Incident titling").

> Deterministic template, not LLM-generated — titles must be stable across runs for the eval
> harness to match on them: `"{top_technique_name} — {primary_entity_type} {primary_entity_value_short}"`
> e.g. `"Command and Control — user u_8f3a91"`.

The LLM (M11) writes `summary`/`narrative`; it never writes the title.

## Technique names, without a MITRE corpus

CLAUDE.md: "Do not fabricate ATT&CK technique IDs. They come from the corpus in
`backend/data/mitre/`." That corpus is not populated yet (`backend/data/mitre/` holds only a
`.gitkeep` — the MITRE RAG ingestion is M11's job, docs/07). `_TECHNIQUE_NAMES` below is
therefore **not** a technique-ID generator — it never invents an ID. It is a small, publicly-
documented lookup restricted to exactly the technique IDs this codebase's own L1 rules
(`app/detection/rules/*.yml`'s `primary_mitre_technique`) and `datagen` scenario labels
already reference, used only to render a human-readable *name* for an ID this system already
produced elsewhere. An ID with no entry here still titles correctly — it falls back to the raw
ID string rather than fabricating a name.
"""

from __future__ import annotations

from typing import Final

__all__ = ["short_entity_value", "technique_name", "title_for_incident"]

# Standard, public MITRE ATT&CK names for the technique IDs this system's own rules/scenarios
# reference (docs/04 §L1's rule inventory table; `datagen/scenarios/*.py`'s `technique` labels).
# Not exhaustive of ATT&CK — scoped to what this codebase can actually produce.
_TECHNIQUE_NAMES: Final[dict[str, str]] = {
    "T1071": "Application Layer Protocol",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1090": "Proxy",
    "T1090.003": "Proxy: Multi-hop Proxy",
    "T1105": "Ingress Tool Transfer",
    "T1567": "Exfiltration Over Web Service",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1048.003": "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
    "T1030": "Data Transfer Size Limits",
    "T1567.002": "Exfiltration to Cloud Storage",
    "T1020": "Automated Exfiltration",
}

_NO_TECHNIQUE_LABEL: Final[str] = "Suspicious Activity"


def technique_name(technique_id: str | None) -> str:
    """A human-readable name for `technique_id`, or a documented fallback — never a fabricated
    one. `None` (no technique attached to any of the incident's signals) -> a generic label;
    an unrecognized ID -> the ID itself, unembellished, so a reviewer can still look it up."""
    if technique_id is None:
        return _NO_TECHNIQUE_LABEL
    return _TECHNIQUE_NAMES.get(technique_id, technique_id)


def short_entity_value(entity_type: str, value: str, *, max_len: int = 24) -> str:
    """A compact rendering of an entity value for the title line. Deterministic and pure string
    manipulation — no hashing/truncation-with-loss beyond simple length capping, since these
    values already came from the pseudonymization stage (docs/06) upstream of this module for
    `user`, and are not identifying for `src_ip`/`domain`/`dst_ip`/`asn`/`country`.

    Emails (`user`) are shortened to the local part (before `@`) — matches docs/05's own example
    (`"user u_8f3a91"`, a bare local-part-shaped token) more closely than the full address would.
    Everything else is capped at `max_len` characters with a `...` marker when truncated.
    """
    rendered = value.split("@", 1)[0] if entity_type == "user" and "@" in value else value
    if len(rendered) <= max_len:
        return rendered
    return rendered[: max_len - 3] + "..."


def title_for_incident(
    *, top_technique_id: str | None, primary_entity_type: str, primary_entity_value: str
) -> str:
    """docs/05's exact template: `"{top_technique_name} — {primary_entity_type} {primary_entity_value_short}"`."""
    name = technique_name(top_technique_id)
    short_value = short_entity_value(primary_entity_type, primary_entity_value)
    return f"{name} — {primary_entity_type} {short_value}"
