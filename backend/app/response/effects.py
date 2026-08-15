"""Effect application — the `after = apply_effects(action, before)` half of docs/08's executor
pseudocode. Pure functions: `(action_id, target, before_state) -> after_state`, no DB access, no
mutation of the input dict (a fresh dict is always returned) so `executor.py` can journal
`before_state`/`after_state` as two genuinely distinct objects rather than two references to the
same mutated dict.
"""

from __future__ import annotations

import copy
from typing import Any

from app.response.state import split_host_file_target


class UnknownEffectError(Exception):
    """No effect function registered for this action id — a catalog/effects module drift."""


def _revoke_okta_sessions(_target: str, before: dict[str, Any]) -> dict[str, Any]:
    after = copy.deepcopy(before)
    for session in after.get("sessions", []):
        session["active"] = False
    return after


def _force_credential_reset(_target: str, before: dict[str, Any]) -> dict[str, Any]:
    after = copy.deepcopy(before)
    after["credential_reset_required"] = True
    return after


def _suspend_user_account(_target: str, before: dict[str, Any]) -> dict[str, Any]:
    after = copy.deepcopy(before)
    after["account_status"] = "suspended"
    return after


def _deactivate_compromised_mfa_factor(_target: str, before: dict[str, Any]) -> dict[str, Any]:
    after = copy.deepcopy(before)
    for factor in after.get("factors", []):
        factor["active"] = False
    return after


def _disable_api_key(_target: str, before: dict[str, Any]) -> dict[str, Any]:
    after = copy.deepcopy(before)
    after["enabled"] = False
    return after


def _block_proxy_target(_target: str, before: dict[str, Any]) -> dict[str, Any]:
    after = copy.deepcopy(before)
    after["blocked"] = True
    return after


def _isolate_host(_target: str, before: dict[str, Any]) -> dict[str, Any]:
    after = copy.deepcopy(before)
    after["isolated"] = True
    return after


def _quarantine_file(target: str, before: dict[str, Any]) -> dict[str, Any]:
    _host_id, file_ref = split_host_file_target(target)
    after = copy.deepcopy(before)
    files = after.setdefault("files", {})
    entry = files.setdefault(file_ref, {"present": True})
    entry["quarantined"] = True
    return after


_EFFECTS: dict[str, Any] = {
    "revoke_okta_sessions": _revoke_okta_sessions,
    "force_credential_reset": _force_credential_reset,
    "suspend_user_account": _suspend_user_account,
    "deactivate_compromised_mfa_factor": _deactivate_compromised_mfa_factor,
    "disable_api_key": _disable_api_key,
    "block_domain_at_proxy": _block_proxy_target,
    "block_dst_ip": _block_proxy_target,
    "isolate_host": _isolate_host,
    "quarantine_file": _quarantine_file,
}


def apply_effects(action_id: str, target: str, before: dict[str, Any]) -> dict[str, Any]:
    fn = _EFFECTS.get(action_id)
    if fn is None:
        raise UnknownEffectError(action_id)
    result: dict[str, Any] = fn(target, before)
    return result
