"""Pins the calibration-roster drift class shut (docs/04 §Fusion "Calibration roster invariant").

This is the third instance of one bug shape found in the same pass: a hand-typed list of
detectors silently drifting out of sync with the codebase's own single source of truth for
"every detector that exists." (1) two log generators drifted on timestamp format; (2)
`app.graph.pipeline_demo._run_l2` hand-listed four of the six L2 extractors, silently starving
`signal.stl_residual`/`signal.url_path_entropy` of ever getting a fitted calibrator; (3)
`app.graph.pipeline_demo._ml_model_pairs` hand-listed the pre-migration-19 L3 roster, silently
starving `ml.eif`/`ml.kth_nn` (which ship) while calibrating three models
(`ml.iforest`/`ml.mahalanobis`/`ml.ecod`) that never emit a production signal.

Three tests, cheapest/most-general first:

* `test_collect_signal_drafts_calls_every_l2_extractor` -- DB-free, no trained artifacts: proves
  `app.detection.evidence.run.collect_signal_drafts` (the single place the six L2 extractors are
  named, per that module's own docstring) still calls all six, by monkeypatching each `detect_*`
  to a uniquely-tagged fake and checking every tag comes back. Would have caught bug (2) directly.
* `test_ml_model_pairs_matches_shipped_model_fields` -- DB-free, no trained artifacts: proves
  `app.graph.pipeline_demo._ml_model_pairs` returns exactly
  `app.detection.ml.detect.SHIPPED_MODEL_FIELDS`'s keys, against a fake bundle (no `MLModelBundle.
  load()` needed). Would have caught bug (3) directly.
* `test_every_production_detector_has_a_fitted_calibrator_or_is_exempted` -- the broad invariant
  the two tests above exist to make true in the first place: every detector_key that can actually
  emit a `signals` row in production (Sigma rules + the six L2 extractors + the *shipped* L3
  models -- deliberately not the L5 graph features, which `app.pipeline.stages.correlate` never
  turns into signals today, and not the three benchmark-only L3 models) has a fitted calibrator
  in the shared `CalibratorStore`, or is named on `_EXEMPT_FROM_CALIBRATION` with a real, checked
  reason. `data/models/calibrators/` is gitignored and regenerable (`evals/config.py`'s own
  docstring) -- neither CI job populates it (`backend`'s `pytest` step runs with no trained
  artifacts at all; `eval-gate` fits its own *isolated* calibrators into a separate directory,
  `evals/pipeline.py::fit_isolated_calibrators`) -- so this test skips rather than false-fails on
  a fresh checkout, and is only load-bearing once someone has actually run
  `python -m app.graph.pipeline_demo fit-calibrators` against this checkout's own corpus, which is
  exactly the environment "someone adds a detector without refitting" describes.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

from app.detection.calibration import CalibratorStore
from app.detection.evidence import run as evidence_run
from app.detection.evidence.constants import (
    SIGNAL_BEACONING,
    SIGNAL_BURST,
    SIGNAL_DGA,
    SIGNAL_RARITY,
    SIGNAL_STL_RESIDUAL,
    SIGNAL_URL_PATH,
)
from app.detection.evidence.drafts import SignalDraft
from app.detection.ml.detect import ML_MODEL_FIELDS, SHIPPED_MODEL_FIELDS
from app.detection.sigma.runner import load_rules
from app.graph.pipeline_demo import _ml_model_pairs

_SIGNAL_LAYER_KEYS: frozenset[str] = frozenset(
    {
        SIGNAL_BEACONING,
        SIGNAL_DGA,
        SIGNAL_BURST,
        SIGNAL_RARITY,
        SIGNAL_STL_RESIDUAL,
        SIGNAL_URL_PATH,
    }
)


def _fake_draft(detector_key: str) -> list[SignalDraft]:
    return [
        SignalDraft(
            detector_key=detector_key,
            entity_type="user",
            entity_value="probe@corp.example",
            raw_score=1.0,
            confidence_raw=1.0,
            window_start=None,
            window_end=None,
            evidence_event_ids=[],
        )
    ]


def test_collect_signal_drafts_calls_every_l2_extractor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each of the six `detect_*` names `collect_signal_drafts` closes over is replaced with a
    fake that returns one uniquely-tagged draft; every tag must come back. `rows=[]` is fine --
    the fakes never look at it -- this test is about which *functions get called*, not their
    detection math (that's every `test_evidence_<name>.py`'s job)."""
    tags = {
        "detect_beaconing": "probe.beaconing",
        "detect_dga": "probe.dga",
        "detect_burst": "probe.burst",
        "detect_rarity": "probe.rarity",
        "detect_stl_residual": "probe.stl_residual",
        "detect_url_path": "probe.url_path",
    }
    for attr, tag in tags.items():
        if attr == "detect_dga":
            monkeypatch.setattr(
                evidence_run, attr, lambda rows, artifact, tag=tag: _fake_draft(tag)
            )
        else:
            monkeypatch.setattr(evidence_run, attr, lambda rows, tag=tag: _fake_draft(tag))

    drafts = evidence_run.collect_signal_drafts([], dga_artifact=None)  # type: ignore[arg-type]
    seen = {d.detector_key for d in drafts}
    assert seen == set(tags.values()), (
        f"expected all six probe tags, got {seen} -- collect_signal_drafts is missing a call to "
        "one of the six detect_* extractors"
    )


def test_ml_model_pairs_matches_shipped_model_fields() -> None:
    """`app.graph.pipeline_demo._ml_model_pairs` must track `SHIPPED_MODEL_FIELDS` exactly --
    not the full six-model benchmark roster, not a stale pre-migration-19 subset. A fake bundle
    (one sentinel object per `MLModelBundle` field) stands in for `MLModelBundle.load()`, so this
    needs no trained model artifacts."""

    class _FakeBundle:
        def __init__(self, fields: Sequence[str]) -> None:
            for field in fields:
                setattr(self, field, object())

    bundle: Any = _FakeBundle(ML_MODEL_FIELDS.values())
    pairs = _ml_model_pairs(bundle)

    keys = {key for key, _ in pairs}
    assert keys == set(SHIPPED_MODEL_FIELDS), (
        f"_ml_model_pairs returned {sorted(keys)}, expected exactly "
        f"{sorted(SHIPPED_MODEL_FIELDS)} (SHIPPED_MODEL_FIELDS)"
    )
    for key, model in pairs:
        assert model is getattr(bundle, SHIPPED_MODEL_FIELDS[key]), (
            f"{key} paired with the wrong bundle attribute"
        )


# ---------------------------------------------------------------------------- broad roster check

# Detectors that CAN emit a `signals` row in production but are not expected to have a fitted
# calibrator -- checked against a real `fit-calibrators` run, not assumed. Every entry needs a
# real, currently-true reason; an entry that stops being true (a detector that gets enough
# samples after a corpus/scenario change) should be deleted, not left stale. Measured directly
# against `python -m app.graph.pipeline_demo fit-calibrators` run over docs/11's eight scenarios
# (50k events each) plus the FP-control/canary pair -- see `calibration.insufficient_samples`/
# `calibration.single_class` log lines from that run.
_EXEMPT_FROM_CALIBRATION: frozenset[str] = frozenset(
    {
        # --- fired, but below MIN_SAMPLES_TO_FIT=8 in this harness's corpus ---
        "sigma.blocked_then_allowed",  # n=2
        "sigma.large_post_to_new_domain",  # n=1
        # --- fired (n=32), but every sample shared one label -- isotonic regression needs both
        # classes represented (`fit_calibrator`'s `calibration.single_class` policy), and this
        # harness's corpus apparently never lands a labeled-malicious url-entropy signal ---
        "signal.url_path_entropy",
        # --- zero samples: this rule's trigger condition never matched a single row across the
        # harness's eight scenarios + FP-control + canary. Spot-verified for two of these
        # (`dlp_engine_triggered`, `threat_name_present`): the scenario logs' `dlpengine`/
        # `threatname` columns exist but are blank on every row this harness's `datagen scenario`
        # invocation produced, even though those two rules' own docstrings say the *generator
        # module* (`datagen/scenarios/s01_c2_beaconing.py`'s `_C2_THREAT`, `s02_data_exfiltration.
        # py`'s `_DLP_FIELDS`) is capable of populating them -- a synthetic-corpus population gap
        # in this specific harness invocation, not a rule bug or the roster-drift bug this test
        # guards against, and out of this pass's scope to chase further (`datagen/**` ownership).
        # The other six are the same shape (a rule whose trigger fields --url category, risk
        # score, app name, credential-bearing URLs-- none of the eight canned scenarios happens
        # to set to a matching value) and were not each hand-verified line-by-line, but share the
        # identical zero-samples signature in the fit run's logs.
        "sigma.anonymizer_proxy_avoidance_category",
        "sigma.credentials_in_url",
        "sigma.direct_to_ip_request",
        "sigma.dlp_engine_triggered",
        "sigma.executable_archive_download_new_domain",
        "sigma.high_risk_score_allowed",
        "sigma.malicious_url_category",
        "sigma.threat_name_present",
    }
)


def _production_detector_universe() -> set[str]:
    """Every detector_key that can actually reach `signals` in the live pipeline today --
    Sigma rules (L1, `app.pipeline.stages.detect` via `run_rules`/`write_signals`), the six L2
    evidence extractors (`run_evidence_layer`), and the *shipped* L3 models
    (`score_entity_windows`, `SHIPPED_MODEL_FIELDS`). Deliberately excludes L5 graph features
    (`app.graph.features.graph_signals_for_incident`) and the three benchmark-only L3 models
    (`ml.iforest`/`ml.mahalanobis`/`ml.ecod`) -- `app.pipeline.stages.correlate` never calls the
    former, and `score_entity_windows` never scores the latter, so neither can produce a real
    `signals` row today regardless of calibration status."""
    rule_keys = {rule.detector_key for rule in load_rules()}
    return rule_keys | set(_SIGNAL_LAYER_KEYS) | set(SHIPPED_MODEL_FIELDS)


def test_every_production_detector_has_a_fitted_calibrator_or_is_exempted() -> None:
    store = CalibratorStore()
    if len(store) == 0:
        pytest.skip(
            "no calibrators fitted in this checkout -- data/models/calibrators/ is gitignored "
            "and regenerable (evals/config.py), and neither CI job populates the shared store "
            "(backend's pytest step has no trained artifacts at all; eval-gate fits its own "
            "isolated calibrators into a separate directory). Run `python -m app.graph."
            "pipeline_demo fit-calibrators` to make this check load-bearing."
        )

    universe = _production_detector_universe()
    calibrated = set(store.detector_keys())
    missing = sorted(universe - calibrated - _EXEMPT_FROM_CALIBRATION)
    assert not missing, (
        f"{missing} can emit a signal in production but have no fitted calibrator in "
        f"CalibratorStore and are not on _EXEMPT_FROM_CALIBRATION -- either refit "
        "(`python -m app.graph.pipeline_demo fit-calibrators`) or add a justified, checked "
        "exemption above"
    )
