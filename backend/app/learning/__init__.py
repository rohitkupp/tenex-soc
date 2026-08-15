"""The continuous-learning loop (docs/08 Part 2, M13). Six feedback consumers over
`analyst_feedback`, four of which need no retraining:

| # | Module | Consumer |
|---|---|---|
| 1 | `app.learning.calibration` | Calibration refit (isotonic, per detector) |
| 2 | `app.learning.weights` | Detector weight tuning (`detector_stats.fusion_weight`) |
| 3 | `app.learning.memory` | Agent few-shot memory (pgvector retrieval + context block) |
| 4 | `app.learning.suppression` | Suppression rule generation (never auto-applied) |
| 5 | `app.learning.benign_corpus` | Benign corpus expansion (retrain-triggering) |
| 6 | `app.learning.classifier` + `app.learning.retrain` | Classifier retraining + the gate |

`app.learning.feedback` is the orchestrator `POST /api/incidents/{id}/feedback`
(`app/api/learning.py`) calls, wiring all six together in the order and on the cadence docs/08
specifies. `app.learning.feedback_data` and `app.learning.metrics` are shared plumbing: label
derivation used by consumers 1, 2, and 6, and the read-side aggregation behind
`GET /api/learning/metrics`, respectively.

None of the six consumers calls the LLM (docs/08 M13's own constraint: "If the LLM is
unavailable... none of these six consumers requires an API call") — this package has no
dependency on `app/agent` or `anthropic` anywhere.
"""

from __future__ import annotations
