"""Unit tests for `app.detection.sequence.logbert`.

Uses a deliberately small `LogBertConfig` (`d_model=32`, 1 layer) rather than docs/04's full
`d_model=128`/2-layer spec -- the real spec is what `train.py` instantiates by default and what
the M9 benchmark trains, but a unit test needs to fit in a CI time budget, and the code path
being exercised (masking, the hypersphere objective, leave-one-out scoring) does not depend on
the width/depth of the encoder.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.detection.sequence import logbert
from app.detection.sequence.sessions import Session, SessionEvent
from app.detection.sequence.vocabulary import build_vocabulary

_T0 = datetime(2026, 1, 1, 9, 0, 0, tzinfo=UTC)

_LOGIN = "user.session.start:SUCCESS"
_MFA = "user.authentication.auth_via_mfa:SUCCESS"
_SSO_A = "user.authentication.sso:SUCCESS:app_a"
_SSO_B = "user.authentication.sso:SUCCESS:app_b"
_SSO_C = "user.authentication.sso:SUCCESS:app_c"
_VERIFY = "user.authentication.verify:SUCCESS"
_SELF_SERVICE = "user.account.update_profile:SUCCESS"
_LOGOUT = "user.session.end:SUCCESS"
_DEACTIVATE = "user.mfa.factor.deactivate:SUCCESS"
_ACTIVATE = "user.mfa.factor.activate:SUCCESS"
_TOKEN_CREATE = "system.api_token.create:SUCCESS"
_PRIV_GRANT = "user.account.privilege.grant:SUCCESS"

_TINY_CONFIG_KWARGS = {"d_model": 32, "nhead": 2, "num_layers": 1, "dim_feedforward": 64}


def _session(principal: str, keys: list[str], *, start_line: int = 1) -> Session:
    events = tuple(
        SessionEvent(ts=_T0 + timedelta(seconds=30 * i), event_key=key, line_no=start_line + i)
        for i, key in enumerate(keys)
    )
    return Session(principal=principal, events=events, truncated=False)


def _benign_training_sessions(n: int) -> list[Session]:
    apps = [_SSO_A, _SSO_B, _SSO_C]
    sessions = []
    for i in range(n):
        keys = [_LOGIN, _MFA, apps[i % 3], _LOGOUT]
        if i % 5 == 0:
            keys = [_LOGIN, _MFA, apps[i % 3], _VERIFY, _LOGOUT]
        if i % 7 == 0:
            keys = [_LOGIN, _MFA, apps[i % 3], _SELF_SERVICE, _LOGOUT]
        sessions.append(_session(f"user{i}@corp.example", keys))
    return sessions


def _train(sessions: list[Session]) -> logbert.TrainedLogBert:
    vocab = build_vocabulary(key for s in sessions for key in s.token_keys)
    config = logbert.LogBertConfig(vocab_size=len(vocab), **_TINY_CONFIG_KWARGS)
    return logbert.train(sessions, vocab, config=config, epochs=10, batch_size=32, seed=7)


def test_score_session_explanation_shape() -> None:
    training = _benign_training_sessions(60)
    trained = _train(training)

    session = _session("holdout@corp.example", [_LOGIN, _MFA, _SSO_A, _LOGOUT])
    result = logbert.score_session(trained, session)

    assert isinstance(result.session_score, float)
    explanation = result.explanation
    assert set(explanation) >= {"surprising_transitions", "session_score"}
    assert explanation["session_score"] == result.session_score
    for t in explanation["surprising_transitions"]:
        assert set(t) == {"from", "to", "log_prob"}
    assert explanation["n_positions"] == 4


def test_handles_short_and_max_length_sessions() -> None:
    training = _benign_training_sessions(40)
    trained = _train(training)

    one_event = _session("short@corp.example", [_LOGIN])
    result = logbert.score_session(trained, one_event)
    assert result.explanation["n_positions"] == 1
    assert result.session_score == result.session_score  # not NaN

    max_len_keys = [_LOGIN, _MFA] + [_SSO_A, _VERIFY] * 31  # 64 tokens total
    full = _session("full@corp.example", max_len_keys)
    full_result = logbert.score_session(trained, full)
    assert full_result.explanation["n_positions"] == 64


def test_novel_ordering_scores_higher_than_benign() -> None:
    training = _benign_training_sessions(200)
    trained = _train(training)

    benign = _session("holdout@corp.example", [_LOGIN, _MFA, _SSO_B, _LOGOUT])
    # None of these four tokens/transitions ever appear in training.
    attack = _session("victim@corp.example", [_DEACTIVATE, _ACTIVATE, _TOKEN_CREATE, _PRIV_GRANT])

    benign_result = logbert.score_session(trained, benign)
    attack_result = logbert.score_session(trained, attack)

    assert attack_result.explanation["anomaly_ratio"] > benign_result.explanation["anomaly_ratio"]
    assert attack_result.session_score > benign_result.session_score


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    training = _benign_training_sessions(40)
    trained = _train(training)

    vocab_path = tmp_path / "seq_vocab.json"
    trained.vocab.save(vocab_path)
    model_path = tmp_path / "seq_logbert.pt"
    meta_path = tmp_path / "seq_logbert_meta.json"
    logbert.save(trained, model_path=model_path, meta_path=meta_path, vocab_path=vocab_path)

    assert model_path.exists()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["version"] == 1
    assert meta["config"]["d_model"] == _TINY_CONFIG_KWARGS["d_model"]

    loaded = logbert.load(trained.vocab, model_path=model_path, meta_path=meta_path)
    session = _session("check@corp.example", [_LOGIN, _MFA, _SSO_A, _LOGOUT])
    original_score = logbert.score_session(trained, session).session_score
    loaded_score = logbert.score_session(loaded, session).session_score
    assert abs(original_score - loaded_score) < 1e-5
