# 08 — Response Action Graph & Continuous Learning

Two closed loops. Together they are what make this a system rather than a report generator.

---

# Part 1 — Response action graph

## Action catalog

`response/actions.yml`. Each action is a node with preconditions, effects, and a rollback.

```yaml
- id: revoke_okta_sessions
  name: Revoke all active sessions
  target_type: user
  preconditions:
    - user_exists
    - has_active_sessions
  effects:
    - okta_session.active = false
  blast_radius: user            # user | host | org
  reversible: false             # user must re-authenticate
  rollback: null
  depends_on: []
  mitre_mitigation: M1018

- id: force_credential_reset
  name: Force password reset
  target_type: user
  preconditions:
    - user_exists
    - sessions_revoked          # ordering matters — resetting first leaves live sessions
  effects:
    - user.credential_reset_required = true
  blast_radius: user
  reversible: true
  rollback: clear_reset_flag
  depends_on: [revoke_okta_sessions]
  mitre_mitigation: M1027

- id: block_domain_at_proxy
  name: Block domain
  target_type: domain
  preconditions:
    - domain_not_allowlisted
  effects:
    - proxy_policy.blocked = true
  blast_radius: org             # affects every user — flag prominently in the UI
  reversible: true
  rollback: unblock_domain
  depends_on: []
  mitre_mitigation: M1037
```

Full catalog: `revoke_okta_sessions`, `force_credential_reset`, `deactivate_compromised_mfa_factor`,
`disable_api_key`, `block_domain_at_proxy`, `block_dst_ip`, `isolate_host`,
`suspend_user_account`, `quarantine_file`.

## Plan derivation

`response/planner.py`:

1. Map the agent's `recommended_actions` to catalog action IDs (reject anything unmapped).
2. Build the induced subgraph over those actions plus their transitive `depends_on`.
3. Topological sort → ordered plan. Cycles are a config bug; fail loudly.
4. Annotate each step with resolved preconditions, blast radius, and rollback availability.

Graph reasoning, not LLM ordering. The order is derivable from the dependency structure, so
derive it — the model is not needed and would be less reliable.

## LLM verification pass

A separate, narrow Claude call over the ordered plan. Not the investigating agent.

Input: the plan, the incident summary, and current enforcement state.
Checks:
- Does each precondition actually hold given current state?
- Is the blast radius proportionate to the incident's confidence and severity?
- Is there an irreversible action that should be gated behind a reversible one first?
- Is anything missing that the incident evidence implies?

Output: `{approved: bool, concerns: [...], suggested_reordering: [...], escalate_to_human: bool}`.

Stored in `response_plans.verification` and rendered in the UI. If `escalate_to_human`, the plan
is shown with a warning banner.

## Simulated enforcement plane

Stateful, in Postgres (`enforcement_state`). This is what makes the loop real.

Seeded from the analysis: every principal gets an Okta user record with sessions and factors,
every domain gets a proxy policy row, every host gets an inventory row.

Execution (`response/executor.py`), on approval only:

```
for action in plan.actions:
    before = read_state(action.target)
    if not check_preconditions(action, before):
        journal(action, failed, precondition_failure=...)
        halt()                      # plan stops; partial execution is recorded honestly
    after = apply_effects(action, before)
    journal(action, before, after, succeeded=True)
```

- Preconditions check **real state**, so a failing precondition genuinely blocks the plan
- Ordering is observable — revoking sessions before resetting credentials produces a different
  end state than the reverse, and the journal shows it
- **Rollback** reverse-iterates `enforcement_journal` restoring `before_state`

Label it plainly in the README: the enforcement plane is simulated; the graph reasoning,
precondition checking, ordering, verification, execution semantics, and rollback are real.

## Outcome verification — loop closure

After execution, re-run detection against post-remediation state and re-evaluate the incident's
signals:

| Result | Meaning |
|---|---|
| `contained` | all member signals resolve |
| `partially_contained` | some resolve |
| `failed` | none resolve, or the plan halted on a precondition |

Headline metric: **autonomous containment rate** — share of incidents fully contained after plan
execution. Show it on the dashboard.

Demo sequence for the recording: incident → plan → approve → state diff → re-detect → contained.
Sixty seconds, and it demonstrates a loop nobody else will have built.

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
