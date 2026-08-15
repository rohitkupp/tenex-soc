"""Unit tests for `app.detection.sequence.vocabulary`."""

from __future__ import annotations

import json
from pathlib import Path

from app.detection.sequence.vocabulary import (
    CLS_ID,
    MASK_ID,
    PAD_ID,
    UNK_ID,
    UNK_TOKEN,
    Vocabulary,
    build_vocabulary,
)


def test_special_tokens_get_fixed_ids() -> None:
    vocab = build_vocabulary(["a", "b", "a"])
    assert vocab.token_to_id["<PAD>"] == PAD_ID == 0
    assert vocab.token_to_id["<UNK>"] == UNK_ID == 1
    assert vocab.token_to_id["<MASK>"] == MASK_ID == 2
    assert vocab.token_to_id["<CLS>"] == CLS_ID == 3


def test_build_vocabulary_orders_by_frequency_then_lexicographic() -> None:
    vocab = build_vocabulary(["rare", "common", "common", "common", "mid", "mid"])
    real_tokens = vocab.id_to_token[4:]
    assert real_tokens == ["common", "mid", "rare"]


def test_encode_unseen_token_returns_unk() -> None:
    vocab = build_vocabulary(["known"])
    assert vocab.encode("known") != UNK_ID
    assert vocab.encode("never_seen") == UNK_ID


def test_normalize_maps_unseen_to_unk_token() -> None:
    vocab = build_vocabulary(["known"])
    assert vocab.normalize("known") == "known"
    assert vocab.normalize("never_seen") == UNK_TOKEN


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    vocab = build_vocabulary(["user.session.start:SUCCESS", "user.session.end:SUCCESS"])
    path = tmp_path / "vocab.json"
    vocab.save(path)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert "id_to_token" in payload

    loaded = Vocabulary.load(path)
    assert loaded.id_to_token == vocab.id_to_token
    assert loaded.encode("user.session.start:SUCCESS") == vocab.encode("user.session.start:SUCCESS")


def test_len_counts_specials_and_real_tokens() -> None:
    vocab = build_vocabulary(["a", "b", "c"])
    assert len(vocab) == 4 + 3
