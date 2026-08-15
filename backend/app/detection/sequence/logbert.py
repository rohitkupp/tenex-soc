"""LogBERT-style transformer (docs/04 §L4 "LogBERT-style transformer").

"2 transformer encoder layers, d_model=128, 4 heads — small, matching the original paper. Two
self-supervised objectives, both required (the paper shows the combination beats either alone):
masked log-key prediction (mask 15%, predict) and the hypersphere objective (minimise volume of
normal-session embeddings). Anomaly score: fraction of masked positions whose true token falls
outside the top-g candidate set (g=8), plus distance from hypersphere center."

## Sequence layout

`sessions.py` truncates/pads every session to `SESSION_MAX_LEN` (64) real tokens. This module
prepends one `<CLS>` position (`vocabulary.CLS_ID`) to every model input -- the hypersphere
objective needs a single pooled vector per session, and `<CLS>` is the standard place to put it
(Devlin et al. and, for logs specifically, the LogBERT paper's own `[DIST]` token) -- so the
model's own input length is `SESSION_MAX_LEN + 1`, not 64. That is an implementation detail of
this file, not a second definition of session length: `sessions.py`'s 64-token contract is
untouched, and `<PAD>` positions are still exactly wherever `sessions.token_ids` put them.

## Masked log-key prediction

Standard BERT recipe (80% of the 15% selected positions become `<MASK>`, 10% a random real
token, 10% left unchanged) over the real, non-`<PAD>` positions of the sequence -- `<CLS>` is
never a masking target, since it carries no `event_key` to predict. Cross-entropy loss over the
selected positions only (`ignore_index=-100` for everything else, PyTorch's own convention).

## Hypersphere objective

A Deep-SVDD-style term: minimize the squared distance from every session's `<CLS>` embedding to a
fixed center `c`. Two things keep this from the well-known trivial-collapse failure mode (every
embedding converging on `c`, satisfying the objective for free rather than learning anything):

1. `c` is computed once, as the mean `<CLS>` embedding over the training corpus after one
   MLM-only warm-up epoch (not before any training -- from a freshly initialized encoder that
   mean is close to meaningless; not gradient-updated afterwards either -- a trainable center is
   the textbook route to collapse), with any near-zero coordinate nudged to a small epsilon (the
   original Deep SVDD paper's own guard against a degenerate all-zero center).
2. The masked-LM loss stays active for the rest of training, at a much larger effective weight
   (`hyper_weight`, default 0.1) than the hypersphere term -- the encoder cannot satisfy the
   hypersphere loss by ignoring its input, because doing so would destroy its ability to predict
   masked tokens, which is still being scored every batch.

## Anomaly score, and why it needs a normalization the doc's formula doesn't spell out

docs/04, verbatim: "fraction of masked positions whose true token falls outside the top-g
candidate set (g=8), plus distance from the hypersphere centre." Taken completely literally that
sums a value in `[0, 1]` (the fraction) with a raw squared-Euclidean distance in 128-dimensional
embedding space, which has no natural scale and would either swamp the fraction term or be
swamped by it depending on how training happens to shape the embedding space that run -- not
"plus" in any meaningful sense, just noise. `training_dist_scale` (the mean training-session
distance to `c`, persisted alongside the model) is the normalization that makes the addition mean
something: `session_score = anomaly_ratio + (distance / training_dist_scale)`, so a session at
the *typical* training distance from center contributes `1.0`, the same order of magnitude as the
fraction term, and the sum is a real "plus," not a unit mismatch.

`anomaly_ratio` itself is computed by **leave-one-out masking**, not the training-time random 15%
sample: every real position is masked individually (with everything else visible) and checked
against the model's top-`g` prediction at that position. This is deterministic (no RNG at
scoring time -- CLAUDE.md rule 7) and exhaustive (every token gets a chance to be "the surprising
one"), which random 15% sampling at inference time would not guarantee.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import torch
from torch import Tensor, nn

from app.detection.sequence.sessions import SESSION_MAX_LEN, Session, token_ids
from app.detection.sequence.vocabulary import (
    CLS_ID,
    CLS_TOKEN,
    MASK_ID,
    PAD_ID,
    SPECIAL_TOKENS,
    Vocabulary,
)

__all__ = [
    "SEQUENCE_LOGBERT",
    "LogBertConfig",
    "LogBertModel",
    "SessionScore",
    "TrainedLogBert",
    "load",
    "save",
    "score_session",
    "score_sessions",
    "train",
]

# Matches `datagen.types.SEQUENCE_LOGBERT`'s string value by convention, not by import -- see
# `markov.py`'s identical note.
SEQUENCE_LOGBERT: Final[str] = "sequence.logbert"

_BACKEND_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
DEFAULT_MODEL_PATH: Final[Path] = _BACKEND_ROOT / "data" / "models" / "seq_logbert.pt"
DEFAULT_META_PATH: Final[Path] = _BACKEND_ROOT / "data" / "models" / "seq_logbert_meta.json"

_TOP_SURPRISING: Final[int] = 5
_MIN_PROB: Final[float] = 1e-9  # log-prob floor, avoids log(0) on a completely missed prediction


@dataclass(frozen=True, slots=True)
class LogBertConfig:
    vocab_size: int
    d_model: int = 128
    nhead: int = 4
    num_layers: int = 2
    dim_feedforward: int = 256
    dropout: float = 0.1
    max_len: int = SESSION_MAX_LEN  # real tokens; model input is max_len + 1 with <CLS>
    mask_prob: float = 0.15
    top_g: int = 8
    hyper_weight: float = 0.1

    @property
    def seq_len(self) -> int:
        return self.max_len + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "vocab_size": self.vocab_size,
            "d_model": self.d_model,
            "nhead": self.nhead,
            "num_layers": self.num_layers,
            "dim_feedforward": self.dim_feedforward,
            "dropout": self.dropout,
            "max_len": self.max_len,
            "mask_prob": self.mask_prob,
            "top_g": self.top_g,
            "hyper_weight": self.hyper_weight,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> LogBertConfig:
        return cls(**payload)


# ---------------------------------------------------------------------------- model


class LogBertModel(nn.Module):
    """2-layer transformer encoder, `d_model=128`, 4 heads (docs/04). One shared body, two heads:
    a masked-log-key softmax over the vocabulary, and the raw `<CLS>` embedding the hypersphere
    loss scores directly (no separate projection head -- Deep SVDD scores the encoder's own
    representation, not a derived one)."""

    def __init__(self, config: LogBertConfig) -> None:
        super().__init__()
        self.config = config
        self.token_emb = nn.Embedding(config.vocab_size, config.d_model, padding_idx=PAD_ID)
        self.pos_emb = nn.Embedding(config.seq_len, config.d_model)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=config.d_model,
            nhead=config.nhead,
            dim_feedforward=config.dim_feedforward,
            dropout=config.dropout,
            activation="gelu",
            batch_first=True,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=config.num_layers)
        self.mlm_head = nn.Linear(config.d_model, config.vocab_size)
        self.emb_dropout = nn.Dropout(config.dropout)

    def forward(self, input_ids: Tensor) -> tuple[Tensor, Tensor]:
        """`input_ids`: `(batch, seq_len)`, `<CLS>` at position 0. Returns `(logits, cls_embedding)`
        -- `logits`: `(batch, seq_len, vocab_size)`, `cls_embedding`: `(batch, d_model)`."""
        batch, seq_len = input_ids.shape
        positions = torch.arange(seq_len, device=input_ids.device).unsqueeze(0).expand(batch, -1)
        x = self.token_emb(input_ids) + self.pos_emb(positions)
        x = self.emb_dropout(x)
        # True at positions the encoder should ignore -- everywhere except real tokens and <CLS>.
        key_padding_mask = input_ids.eq(PAD_ID)
        hidden = self.encoder(x, src_key_padding_mask=key_padding_mask)
        logits: Tensor = self.mlm_head(hidden)
        cls_embedding = hidden[:, 0, :]
        return logits, cls_embedding


# ---------------------------------------------------------------------------- batching


def _pad_batch(sessions: Sequence[Session], vocab: Vocabulary, config: LogBertConfig) -> Tensor:
    rows = []
    for session in sessions:
        real = token_ids(session, vocab, max_len=config.max_len)
        rows.append([CLS_ID, *real])
    return torch.tensor(rows, dtype=torch.long)


def _mask_batch(
    input_ids: Tensor, vocab_size: int, generator: torch.Generator, *, mask_prob: float
) -> tuple[Tensor, Tensor]:
    """BERT-style 80/10/10 masking (module docstring) over real, non-`<CLS>`, non-`<PAD>`
    positions. Returns `(masked_input_ids, labels)`; `labels` is `-100` (PyTorch's
    `ignore_index` convention) everywhere not selected."""
    maskable = (input_ids != PAD_ID) & (input_ids != CLS_ID)
    select = (
        torch.rand(input_ids.shape, generator=generator, device=input_ids.device) < mask_prob
    ) & maskable
    # A masked batch with zero selected positions produces an empty-mean loss (NaN); guarantee at
    # least one selected position per row that has any maskable token at all.
    for row in range(input_ids.shape[0]):
        if select[row].any():
            continue
        candidates = maskable[row].nonzero(as_tuple=True)[0]
        if len(candidates) == 0:
            continue
        pick = candidates[torch.randint(len(candidates), (1,), generator=generator)]
        select[row, pick] = True

    labels = torch.where(select, input_ids, torch.full_like(input_ids, -100))

    action = torch.rand(input_ids.shape, generator=generator, device=input_ids.device)
    masked = input_ids.clone()
    to_mask_token = select & (action < 0.8)
    to_random = select & (action >= 0.8) & (action < 0.9)
    # else (10%): left unchanged, but still scored (label still set).
    masked[to_mask_token] = MASK_ID
    # `low=len(SPECIAL_TOKENS)`: a random-replacement target should be a real event_key, never one
    # of the four mechanics tokens (<PAD>/<UNK>/<MASK>/<CLS> occupy ids 0..3, module docstring).
    random_tokens = torch.randint(
        low=len(SPECIAL_TOKENS),
        high=vocab_size,
        size=input_ids.shape,
        generator=generator,
        device=input_ids.device,
    )
    masked[to_random] = random_tokens[to_random]
    return masked, labels


# ---------------------------------------------------------------------------- training


@dataclass(slots=True)
class TrainedLogBert:
    model: LogBertModel
    vocab: Vocabulary
    config: LogBertConfig
    center: Tensor
    training_dist_scale: float
    training: dict[str, Any]


def train(
    sessions: Sequence[Session],
    vocab: Vocabulary,
    *,
    config: LogBertConfig | None = None,
    epochs: int = 8,
    batch_size: int = 64,
    lr: float = 1e-3,
    seed: int = 42,
    device: str = "cpu",
) -> TrainedLogBert:
    """Fit a `LogBertModel` on benign `sessions` only (docs/04): epoch 0 is masked-LM-only
    (warms the encoder up before the hypersphere center is computed from it, module docstring);
    epochs 1.. add the hypersphere term against that fixed center.
    """
    cfg = config or LogBertConfig(vocab_size=len(vocab))
    torch_device = torch.device(device)
    torch.manual_seed(seed)
    generator = torch.Generator(device="cpu").manual_seed(seed)

    model = LogBertModel(cfg).to(torch_device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    all_inputs = _pad_batch(sessions, vocab, cfg).to(torch_device)
    n = all_inputs.shape[0]
    if n == 0:
        raise ValueError("train() requires at least one session")

    epoch_losses: list[dict[str, float]] = []
    center: Tensor | None = None

    for epoch in range(epochs):
        perm = torch.randperm(n, generator=generator)
        use_hypersphere = center is not None
        total_mlm, total_hyper, n_batches = 0.0, 0.0, 0
        model.train()
        for start in range(0, n, batch_size):
            idx = perm[start : start + batch_size]
            batch = all_inputs[idx]
            masked, labels = _mask_batch(batch, cfg.vocab_size, generator, mask_prob=cfg.mask_prob)

            logits, cls_embedding = model(masked)
            mlm_loss = nn.functional.cross_entropy(
                logits.reshape(-1, cfg.vocab_size), labels.reshape(-1), ignore_index=-100
            )
            loss = mlm_loss
            hyper_loss_val = 0.0
            if use_hypersphere and center is not None:
                hyper_loss = ((cls_embedding - center) ** 2).sum(dim=1).mean()
                loss = loss + cfg.hyper_weight * hyper_loss
                hyper_loss_val = float(hyper_loss.detach())

            optimizer.zero_grad()
            # torch's own stub gap: `Tensor.backward` resolves as untyped under `--strict`.
            loss.backward()  # type: ignore[no-untyped-call]
            optimizer.step()

            total_mlm += float(mlm_loss.detach())
            total_hyper += hyper_loss_val
            n_batches += 1

        epoch_losses.append(
            {
                "epoch": float(epoch),
                "mlm_loss": total_mlm / max(n_batches, 1),
                "hyper_loss": total_hyper / max(n_batches, 1),
            }
        )

        if center is None:
            center = _compute_center(model, all_inputs, batch_size)

    assert center is not None  # guaranteed by epochs >= 1
    training_dist_scale = _compute_dist_scale(model, all_inputs, center, batch_size)

    training_summary: dict[str, Any] = {
        "epochs": epochs,
        "batch_size": batch_size,
        "lr": lr,
        "seed": seed,
        "n_train_sessions": n,
        "epoch_losses": epoch_losses,
        "training_dist_scale": training_dist_scale,
    }
    return TrainedLogBert(
        model=model,
        vocab=vocab,
        config=cfg,
        center=center,
        training_dist_scale=training_dist_scale,
        training=training_summary,
    )


def _compute_center(model: LogBertModel, all_inputs: Tensor, batch_size: int) -> Tensor:
    """Mean `<CLS>` embedding over the (unmasked) training corpus, with the Deep SVDD epsilon
    guard against near-zero coordinates trivially satisfying the hypersphere loss."""
    model.eval()
    sums = torch.zeros(model.config.d_model)
    n = all_inputs.shape[0]
    with torch.no_grad():
        for start in range(0, n, batch_size):
            batch = all_inputs[start : start + batch_size]
            _, cls_embedding = model(batch)
            sums += cls_embedding.sum(dim=0)
    center = sums / n
    eps = 0.1
    near_zero = center.abs() < eps
    center = torch.where(near_zero, torch.sign(center) * eps + (center == 0).float() * eps, center)
    return center.detach()


def _compute_dist_scale(
    model: LogBertModel, all_inputs: Tensor, center: Tensor, batch_size: int
) -> float:
    model.eval()
    n = all_inputs.shape[0]
    dists: list[Tensor] = []
    with torch.no_grad():
        for start in range(0, n, batch_size):
            batch = all_inputs[start : start + batch_size]
            _, cls_embedding = model(batch)
            dists.append(((cls_embedding - center) ** 2).sum(dim=1))
    all_dists = torch.cat(dists)
    scale = float(all_dists.mean())
    return max(scale, 1e-6)


# ---------------------------------------------------------------------------- scoring


@dataclass(slots=True)
class SessionScore:
    session_score: float
    explanation: dict[str, Any]


def score_sessions(
    trained: TrainedLogBert, sessions: Sequence[Session], *, batch_size: int = 256
) -> list[SessionScore]:
    """Score every session in `sessions`. Batches leave-one-out masked rows across sessions (not
    per-session forward passes) for throughput -- see module docstring for why leave-one-out
    rather than random masking is used at scoring time."""
    model, vocab, cfg = trained.model, trained.vocab, trained.config
    model.eval()

    all_inputs = _pad_batch(sessions, vocab, cfg)

    # 1) <CLS> embeddings for the *unmasked* sequences -- what the hypersphere distance scores.
    cls_embeddings: list[Tensor] = []
    with torch.no_grad():
        for start in range(0, len(sessions), batch_size):
            batch = all_inputs[start : start + batch_size]
            _, cls_emb = model(batch)
            cls_embeddings.append(cls_emb)
    all_cls = torch.cat(cls_embeddings) if cls_embeddings else torch.zeros((0, cfg.d_model))
    distances = ((all_cls - trained.center) ** 2).sum(dim=1) if len(sessions) else torch.zeros(0)

    # 2) Leave-one-out masked rows, flattened across every session, batched for the forward pass.
    row_session_idx: list[int] = []
    row_position: list[int] = []  # position within the real-token range (0-based)
    row_inputs: list[Tensor] = []
    for s_idx, session in enumerate(sessions):
        base = all_inputs[s_idx]
        for pos in range(len(session)):  # real tokens only, <CLS> is position 0 in base
            variant = base.clone()
            variant[pos + 1] = MASK_ID
            row_inputs.append(variant)
            row_session_idx.append(s_idx)
            row_position.append(pos)

    per_session_rows: list[list[dict[str, Any]]] = [[] for _ in sessions]
    if row_inputs:
        stacked = torch.stack(row_inputs)
        true_ids = torch.tensor(
            [
                vocab.encode(sessions[s_idx].events[pos].event_key)
                for s_idx, pos in zip(row_session_idx, row_position, strict=True)
            ],
            dtype=torch.long,
        )
        # +1: `pos` is 0-based within the real-token range, but <CLS> occupies model position 0.
        positions = torch.tensor(row_position, dtype=torch.long) + 1
        top_g = min(cfg.top_g, cfg.vocab_size)

        with torch.no_grad():
            for start in range(0, stacked.shape[0], batch_size):
                chunk = stacked[start : start + batch_size]
                chunk_positions = positions[start : start + chunk.shape[0]]
                chunk_true_ids = true_ids[start : start + chunk.shape[0]]

                logits, _ = model(chunk)  # (B, L, V)
                # Gather each row's own scored position in one vectorized indexing op rather than
                # a per-row Python loop -- this is the difference between a benchmark over a few
                # hundred thousand rows finishing in seconds vs. minutes.
                batch_idx = torch.arange(chunk.shape[0])
                pos_logits = logits[batch_idx, chunk_positions, :]  # (B, V)
                probs = torch.softmax(pos_logits, dim=-1)
                top_ids = torch.topk(probs, k=top_g, dim=-1).indices  # (B, top_g)
                hits = (top_ids == chunk_true_ids.unsqueeze(1)).any(dim=1)  # (B,)
                true_probs = probs.gather(1, chunk_true_ids.unsqueeze(1)).squeeze(1)  # (B,)
                log_probs = torch.log(true_probs.clamp(min=_MIN_PROB))

                hits_list = hits.tolist()
                true_probs_list = true_probs.tolist()
                log_probs_list = log_probs.tolist()

                for local_i in range(chunk.shape[0]):
                    global_i = start + local_i
                    s_idx = row_session_idx[global_i]
                    pos = row_position[global_i]
                    session = sessions[s_idx]
                    prev_key = (
                        CLS_TOKEN
                        if pos == 0
                        else vocab.normalize(session.events[pos - 1].event_key)
                    )
                    per_session_rows[s_idx].append(
                        {
                            "position": pos,
                            "from": prev_key,
                            "to": vocab.normalize(session.events[pos].event_key),
                            "hit": hits_list[local_i],
                            "prob": true_probs_list[local_i],
                            "log_prob": log_probs_list[local_i],
                            "line_no": session.events[pos].line_no,
                        }
                    )

    results: list[SessionScore] = []
    for s_idx, session in enumerate(sessions):
        rows = sorted(per_session_rows[s_idx], key=lambda r: r["position"])
        n_real = len(rows)
        dist = float(distances[s_idx]) if s_idx < len(distances) else 0.0
        normalized_dist = dist / trained.training_dist_scale
        anomaly_ratio = 0.0 if n_real == 0 else sum(1 for r in rows if not r["hit"]) / n_real
        session_score = anomaly_ratio + normalized_dist

        surprising = sorted(rows, key=lambda r: r["log_prob"])[:_TOP_SURPRISING]
        explanation: dict[str, Any] = {
            "surprising_transitions": [
                {"from": r["from"], "to": r["to"], "log_prob": r["log_prob"]} for r in surprising
            ],
            "session_score": session_score,
            "anomaly_ratio": anomaly_ratio,
            "hypersphere_distance": dist,
            "hypersphere_distance_normalized": normalized_dist,
            "n_positions": n_real,
            "top_g": cfg.top_g,
            "principal": session.principal,
        }
        results.append(SessionScore(session_score=session_score, explanation=explanation))
    return results


def score_session(trained: TrainedLogBert, session: Session) -> SessionScore:
    return score_sessions(trained, [session])[0]


# ---------------------------------------------------------------------------- persistence


def save(
    trained: TrainedLogBert,
    *,
    model_path: Path = DEFAULT_MODEL_PATH,
    meta_path: Path = DEFAULT_META_PATH,
    vocab_path: Path,
) -> None:
    model_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(trained.model.state_dict(), model_path)
    meta = {
        "version": 1,
        "config": trained.config.to_dict(),
        "center": trained.center.tolist(),
        "training_dist_scale": trained.training_dist_scale,
        "vocab_path": str(vocab_path),
        "training": trained.training,
    }
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")


def load(
    vocab: Vocabulary,
    *,
    model_path: Path = DEFAULT_MODEL_PATH,
    meta_path: Path = DEFAULT_META_PATH,
    device: str = "cpu",
) -> TrainedLogBert:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    config = LogBertConfig.from_dict(meta["config"])
    model = LogBertModel(config)
    state = torch.load(model_path, map_location=device, weights_only=True)
    model.load_state_dict(state)
    model.to(torch.device(device))
    center = torch.tensor(meta["center"], dtype=torch.float32)
    return TrainedLogBert(
        model=model,
        vocab=vocab,
        config=config,
        center=center,
        training_dist_scale=float(meta["training_dist_scale"]),
        training=meta.get("training", {}),
    )
