# 08 — Continuous Learning

**The response action graph and simulated enforcement plane (formerly Part 1 of this doc) were
removed entirely — docs/v2_migration change 20.** `response/` (`actions.yml`, `planner.py`,
`executor.py`, `verification.py`, and the rest of the package), the `response_plans` /
`enforcement_state` / `enforcement_journal` tables, the `responder` worker and `q.respond`, and
every plan/approve/rollback endpoint are gone. Autonomous containment rate is gone as a metric
along with them. The agent's `recommended_actions` survives, but its meaning changed: it is now
free-text investigation guidance for a human analyst, not action IDs from a catalog — see
docs/07-AGENT.md. The pipeline shortens accordingly: `agent` now publishes directly to `q.tier2`
(docs/01).

The continuous learning loop below is what remains, and — with the response/enforcement loop
gone — it is now the system's closing loop.

---

# Part 2 — Continuous learning

Feedback capture already exists (`analyst_feedback`). These six consumers are what turn capture
into learning. Four require no retraining.

## 1. Calibration refit — no retrain
Confirmed and rejected dispositions become labels. Refit the per-detector isotonic calibrator so
stated confidence tracks observed precision. Run nightly or on every 50 feedback events.
Measure with Brier score and a reliability diagram.

## 2. Detector weight tuning — no retrain
```
precision_d = TP_d / (TP_d + FP_d)
fusion_weight_d = clamp(precision_d / prior_precision, 0.25, 1.5)
```
Written to `detector_stats`. A detector whose signals analysts consistently dismiss gets
down-weighted in fusion. This is exactly how real SOC detection tuning works, and it is visible
and explainable.

## 3. Agent few-shot memory — no retrain
**Highest value per hour of implementation.** On a new incident, retrieve the `k=3` most similar
past incidents *with analyst-confirmed dispositions* via the existing pgvector index, and include
them in the agent's context:

```
<prior_analyst_decisions>
Similar incident (cosine 0.94), analyst disposition: false_positive
Reason: "Sanctioned nightly backup to corporate S3 bucket."
</prior_analyst_decisions>
```

RAG over the feedback store. No training, immediate effect, demonstrable in one session, and it
reuses infrastructure already built for recurrence detection.

## 4. Suppression rule generation — no retrain
On dismissal with a reason, generate a candidate Sigma exception rule or entity allowlist entry
and present it to the analyst for review. Accepted rules go to
`detection/rules/suppressions/` and apply to subsequent analyses.

Never auto-apply. Analyst review is the gate — that is how tuning works in a real SOC, and
auto-suppression is how you miss a breach.

## 5. Benign corpus expansion — retrain
`mark_benign_baseline = true` flags the incident's entity-windows for inclusion in the next
benign training corpus. Highest-fidelity loop for UEBA, because most false positives are
*weird but sanctioned*, and the fix is teaching the model that this shape of weird is normal.

Triggers retraining for the corpus-fitted L3 models (autoencoder, Isolation Forest, Mahalanobis —
`docs/04` §L3).

## 6. Classifier retraining — retrain
`corrected_technique` labels append to the LightGBM training set. Retrain on a schedule or at a
feedback-count threshold.

## Retrain gate

**Every retrain is gated by the regression harness (`docs/12`).**

```
train candidate → run golden dataset → compare to live model
  if precision, recall, citation_validity, or injection_resistance regress → reject
  else → write model_versions row, promote
```

The old model stays live on rejection. Record every attempt, promoted or not — the rejection
history is evidence the gate works.

## Metrics to surface

- Human–AI alignment % over time
- Per-detector precision, trending
- Calibration reliability diagram: stated vs. observed
- Model version history with the eval scores that gated each promotion
- Autonomous containment rate

## Demo honesty

One session will not produce enough feedback for retraining to visibly help. **Seed a synthetic
feedback history** (`make seed`) so the loop has something to consume and the curves are
demonstrable — and say so plainly in the README rather than implying the data is real.
