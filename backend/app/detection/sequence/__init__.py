"""L4 — sequence anomaly detection (docs/04 §L4). **Identity sources only.**

```
L1 rules  ->  L2 signal  ->  L3 entity-window ML  ->  L4 sequence (this layer)  ->  L5 graph
```

## Why identity logs, and only identity logs

Proxy logs are deliberately excluded from sequence modelling — this is a design position, not a
gap, and it is worth restating here next to the code that depends on it rather than only in
`docs/04-DETECTION.md`:

1. **Interleaved multi-user browsing produces unstable sequences.** A proxy log interleaves many
   independent concurrent tasks from one source IP behind NAT/shared egress; the resulting
   sequence has low repetitiveness, which is the documented failure mode for sequence-based log
   anomaly detection (DeepLog/LogBERT-style models assume one coherent "session grammar" per
   sequence, which multi-tab, multi-tenant proxy traffic does not have).
2. **Proxy attack signals are quantitative, not ordinal.** Beaconing is a timing statistic
   (`app.detection.signal.beaconing`, L2). Exfiltration is a volume statistic (L3's
   `bytes_out_sum`, `out_in_ratio`). DGA is a string statistic (`app.detection.signal.dga`, L2).
   None of these are expressed by *which event came after which* — a sequence model is the wrong
   tool for a problem that isn't ordinal, and would underperform the L2/L3 detectors already
   built for exactly this data.

Identity logs are the opposite on every count that matters here:

1. **Native discrete vocabulary.** `event_key` (`eventType:outcome.result`, already produced by
   `app.parsers.okta`) *is* the log key — no template mining (Drain3) needed, ~150 distinct
   tokens observed in practice (`vocabulary.py`).
2. **Per-principal sessions are genuinely grammatical.** One person's Okta activity in a 30-minute
   window is one coherent task (log in, MFA, SSO into an app, log out), not several interleaved
   ones.
3. **The attacks are ordering patterns.** `datagen/scenarios/s05_account_takeover.py` constructs
   an attack chain where every individual event is unremarkable in isolation and only the
   *sequence* — `user.mfa.factor.activate -> system.api_token.create` — is the signal. No L3
   feature vector, which discards order within its 1-hour window, can see this by construction.
   `docs/13` M9's acceptance criterion is exactly this contrast: a sequence model catching
   scenario 5 while L3 features do not is the proof this layer earns its slot in the funnel.

## Two models, one contract

`markov.py` (bigram/trigram baseline, fully interpretable) and `logbert.py` (2-layer transformer,
masked-log-key + hypersphere objectives) both consume `sessions.Session` objects built by
`sessions.build_sessions` and both produce the same explanation shape docs/04 specifies:
`{surprising_transitions: [{from, to, log_prob}], session_score}`. `train.py` fits both on the
benign corpus; `benchmark.py` scores both against labeled eval scenario files and reports F1 —
docs/04's governing rule applies here like everywhere else: LogBERT ships as primary only if it
beats the Markov baseline; if it does not, Markov ships and that is a reportable result, not a
failure.
"""

from __future__ import annotations
