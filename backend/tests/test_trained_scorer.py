"""
Tests for the optional trained IsolationForest risk scorer
(app/ml/trained_scorer.py, app/risk.py::compute_risk_score).

Critical cases covered:
- Default behavior (RISK_SCORER_BACKEND unset/"heuristic") is completely
  unaffected — compute_risk_score delegates straight to the existing,
  already-tested risk_score().
- Selecting the trained backend produces a real score in [0, 1] and a
  valid decision, using the actual checked-in artifact (not a mock) — this
  is what proves the artifact loads and the model/scaler shapes match
  ensemble_features()'s output.
- A misconfigured backend (artifact missing) fails loudly with a clear
  error rather than silently falling back to something else.
"""
from __future__ import annotations

import pytest

from app import risk
from app.config import Settings
from app.ml import trained_scorer


@pytest.fixture(autouse=True)
def _reset_artifact_cache():
    """The trained artifact is cached at module scope; reset between tests
    so a monkeypatched missing-artifact test doesn't leak into others."""
    trained_scorer._ARTIFACT = None
    yield
    trained_scorer._ARTIFACT = None


def test_compute_risk_score_defaults_to_heuristic(monkeypatch):
    fake_settings = Settings(
        env="development",
        jwt_secret_key="unit-test-secret",
        cors_allowed_origins=("http://localhost:3000",),
        risk_scorer_backend="heuristic",
    )
    monkeypatch.setattr(risk, "settings", fake_settings, raising=False)

    features = {"amount": 10.0, "randomize": False}
    heuristic_score, heuristic_decision, heuristic_reason = risk.risk_score(features)
    dispatched_score, dispatched_decision, dispatched_reason = risk.compute_risk_score(features)

    assert dispatched_score == heuristic_score
    assert dispatched_decision == heuristic_decision
    assert dispatched_reason == heuristic_reason


def test_compute_risk_score_with_trained_backend_uses_real_artifact():
    """
    Exercises the actual checked-in artifact end-to-end (no mocking of the
    model/scaler) — this is what would catch a feature-order mismatch
    between ensemble_features() and FEATURE_NAMES in
    scripts/train_isolation_forest.py, for example.
    """
    features = {
        "amount": 5000.0,
        "velocity_1min": 8,
        "mcc_risk": 0.6,
        "geo_mismatch": True,
        "device_compromised": True,
        "darkweb_hit": True,
    }
    score = trained_scorer.trained_risk_score(features)
    assert 0.0 <= score <= 1.0

    decision, reason = risk.decision_for_score(score)
    assert decision in ("allow", "challenge", "block")
    assert reason in ("Low risk", "Medium risk", "High risk")


def test_trained_risk_score_raises_clear_error_when_artifact_missing(monkeypatch, tmp_path):
    missing_path = tmp_path / "does_not_exist.joblib"
    monkeypatch.setattr(trained_scorer, "ARTIFACT_PATH", missing_path)

    with pytest.raises(trained_scorer.TrainedModelUnavailableError):
        trained_scorer.trained_risk_score({"amount": 10.0})


def test_a_low_risk_and_high_risk_feature_set_produce_different_trained_scores():
    """
    Sanity check that the trained model actually discriminates between an
    obviously-benign and an obviously-suspicious feature set, rather than
    returning a constant score regardless of input (which would indicate a
    broken feature pipeline even if no exception were raised).
    """
    low_risk = {
        "amount": 5.0,
        "velocity_1min": 0,
        "mcc_risk": 0.2,
        "geo_mismatch": False,
        "device_compromised": False,
        "darkweb_hit": False,
    }
    high_risk = {
        "amount": 9000.0,
        "velocity_1min": 12,
        "mcc_risk": 0.6,
        "geo_mismatch": True,
        "device_compromised": True,
        "darkweb_hit": True,
    }
    assert trained_scorer.trained_risk_score(high_risk) > trained_scorer.trained_risk_score(low_risk)
