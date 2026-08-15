"""Unit tests for `app.detection.sequence.markov` -- CLAUDE.md's "every detector needs a
synthetic fixture that must fire and one that must not," applied to the L4 baseline.

The training grammar mirrors `datagen/scenarios/s05_account_takeover.py`'s own design on
purpose: every token the "attack" session uses (`_DEACTIVATE`, `_ACTIVATE`, `_TOKEN_CREATE`) also
appears somewhere in benign training data, so the vocabulary knows all of them individually --
the decoy grammar (`_benign_decoy_factor_swap`) even produces the exact `_DEACTIVATE -> _ACTIVATE`
bigram (an honest phone upgrade). What benign training *never* produces is `_ACTIVATE ->
_TOKEN_CREATE` immediately after each other. That is the one novel transition, and it is what
this test asserts the model catches -- proving the detector learned an ordering, not just which
tokens exist (the same distinction scenario 5's decoys are built to measure).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.detection.sequence import markov
from app.detection.sequence.sessions import Session, SessionEvent
from app.detection.sequence.vocabulary import build_vocabulary

_T0 = datetime(2026, 1, 1, 9, 0, 0, tzinfo=UTC)

_LOGIN = "user.session.start:SUCCESS"
_MFA = "user.authentication.auth_via_mfa:SUCCESS"
_SSO = "user.authentication.sso:SUCCESS"
_LOGOUT = "user.session.end:SUCCESS"
_DEACTIVATE = "user.mfa.factor.deactivate:SUCCESS"
_ACTIVATE = "user.mfa.factor.activate:SUCCESS"
_TOKEN_CREATE = "system.api_token.create:SUCCESS"


def _session(principal: str, keys: list[str], *, start_line: int = 1) -> Session:
    events = tuple(
        SessionEvent(ts=_T0 + timedelta(seconds=30 * i), event_key=key, line_no=start_line + i)
        for i, key in enumerate(keys)
    )
    return Session(principal=principal, events=events, truncated=False)


def _benign_training_sessions(n: int) -> list[Session]:
    """The whole grammar the Markov model sees during training, three shapes mixed together:

    * ordinary login (most common): start -> mfa -> sso (1-3x) -> logout.
    * a decoy factor swap (~1 in 9): start -> mfa -> deactivate -> activate -> sso -> logout --
      an honest phone upgrade, so `_DEACTIVATE`/`_ACTIVATE` and their bigram are both known-normal.
    * a service-account token mint (~1 in 13): start -> token_create -> logout -- so
      `_TOKEN_CREATE` is also known-normal, just never adjacent to `_ACTIVATE`.
    """
    sessions = []
    for i in range(n):
        if i % 13 == 0:
            keys = [_LOGIN, _TOKEN_CREATE, _LOGOUT]
        elif i % 9 == 0:
            keys = [_LOGIN, _MFA, _DEACTIVATE, _ACTIVATE, _SSO, _LOGOUT]
        else:
            n_sso = 1 + (i % 3)
            keys = [_LOGIN, _MFA, *([_SSO] * n_sso), _LOGOUT]
        sessions.append(_session(f"user{i}@corp.example", keys))
    return sessions


def _fit_model() -> tuple[markov.MarkovModel, list[Session]]:
    training = _benign_training_sessions(400)
    vocab = build_vocabulary(key for s in training for key in s.token_keys)
    model = markov.fit(training, vocab)
    return model, training


def test_benign_session_scores_low() -> None:
    model, _training = _fit_model()
    held_out = _session("holdout@corp.example", [_LOGIN, _MFA, _SSO, _SSO, _LOGOUT])
    result = model.score_session(held_out)
    # The grammar is low-entropy and this exact shape was seen many times in training -- mean
    # negative log-probability should be small, not just "smaller than the attack's".
    assert result.session_score < 2.0
    assert result.explanation["session_score"] == result.session_score
    assert result.explanation["n_transitions"] == 5


def test_decoy_factor_swap_scores_low_despite_using_rare_tokens() -> None:
    """The false-positive half of the measurement: `_DEACTIVATE`/`_ACTIVATE` are individually
    rare but their bigram is entirely ordinary, so this session must *not* read as anomalous."""
    model, _training = _fit_model()
    decoy = _session("decoy@corp.example", [_LOGIN, _MFA, _DEACTIVATE, _ACTIVATE, _SSO, _LOGOUT])
    benign = _session("holdout@corp.example", [_LOGIN, _MFA, _SSO, _LOGOUT])
    decoy_result = model.score_session(decoy)
    benign_result = model.score_session(benign)
    # Same order of magnitude as an ordinary session -- not free, but nowhere near flagged.
    assert decoy_result.session_score < 2.0 * benign_result.session_score


def test_account_takeover_ordering_scores_high_and_is_surprising() -> None:
    model, _training = _fit_model()
    # Every individual token here is known-benign (module docstring); only the adjacency
    # `_ACTIVATE -> _TOKEN_CREATE` is novel -- docs/04 §L4's own example of "each event
    # individually legitimate, the ordering is the attack."
    attack = _session(
        "victim@corp.example", [_LOGIN, _MFA, _DEACTIVATE, _ACTIVATE, _TOKEN_CREATE, _LOGOUT]
    )
    benign_result = model.score_session(
        _session("holdout@corp.example", [_LOGIN, _MFA, _SSO, _LOGOUT])
    )
    attack_result = model.score_session(attack)

    assert attack_result.session_score > benign_result.session_score
    assert attack_result.session_score > 2.0 * benign_result.session_score

    explanation = attack_result.explanation
    assert set(explanation) >= {"surprising_transitions", "session_score"}
    surprising_pairs = {(t["from"], t["to"]) for t in explanation["surprising_transitions"]}
    for t in explanation["surprising_transitions"]:
        assert set(t) == {"from", "to", "log_prob"}
    # The one truly novel transition -- not "deactivate exists" or "activate exists", but
    # specifically their adjacency to a token mint -- must be the standout.
    assert (_ACTIVATE, _TOKEN_CREATE) in surprising_pairs


def test_transition_prob_backs_off_from_trigram_to_bigram() -> None:
    model, _training = _fit_model()
    # (_LOGIN, _MFA) -> _SSO was seen often; the interpolated probability should sit well above
    # the never-seen _ACTIVATE -> _TOKEN_CREATE adjacency.
    p_common = model.transition_prob(_LOGIN, _MFA, _SSO)
    p_novel = model.transition_prob(_DEACTIVATE, _ACTIVATE, _TOKEN_CREATE)
    assert p_common > p_novel
    assert p_common > 0.3


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    model, _training = _fit_model()
    path = tmp_path / "seq_markov.json"
    model.save(path)
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 1

    loaded = markov.MarkovModel.load(path)
    session = _session("check@corp.example", [_LOGIN, _MFA, _SSO, _LOGOUT])
    assert loaded.score_session(session).session_score == model.score_session(session).session_score
