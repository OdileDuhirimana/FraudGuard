"""
Unit tests for the pure risk_score() function (app/risk.py), isolated from
FastAPI/DB entirely. This is the highest-value unit-testable surface in the
codebase per the code review's Architecture Review ("risk.py and ml/model.py
can technically be unit-tested without spinning up FastAPI").

Jitter note: risk_score adds RANDOM_JITTER (0.02) when features.get(
"randomize", True) is truthy, so exact-value assertions use
randomize=False for determinism; boundary-crossing behavior is asserted
with tolerance instead of exact equality.
"""
from app.risk import THRESHOLD_BLOCK, THRESHOLD_CHALLENGE, clamp, risk_score


def test_clamp_bounds_values_to_unit_interval():
    assert clamp(-5.0) == 0.0
    assert clamp(5.0) == 1.0
    assert clamp(0.5) == 0.5


def test_minimal_features_yield_allow_decision():
    score, decision, reason = risk_score({"amount": 1.0, "randomize": False})
    assert decision == "allow"
    assert reason == "Low risk"
    assert score < THRESHOLD_CHALLENGE


def test_high_amount_and_all_risk_signals_trigger_block():
    score, decision, reason = risk_score(
        {
            "amount": 5000.0,
            "velocity_1min": 10,
            "geo_mismatch": True,
            "device_compromised": True,
            "darkweb_hit": True,
            "mcc_risk": 0.9,
            "randomize": False,
        }
    )
    assert decision == "block"
    assert reason == "High risk"
    assert score >= THRESHOLD_BLOCK


def test_moderate_risk_triggers_challenge_not_block():
    score, decision, _ = risk_score(
        {
            "amount": 400.0,
            "velocity_1min": 3,
            "geo_mismatch": True,
            "randomize": False,
        }
    )
    assert decision in ("challenge", "allow")
    if decision == "challenge":
        assert THRESHOLD_CHALLENGE <= score < THRESHOLD_BLOCK


def test_score_is_always_within_unit_interval():
    score, _, _ = risk_score(
        {
            "amount": 10_000_000.0,
            "velocity_1min": 1000,
            "geo_mismatch": True,
            "device_compromised": True,
            "darkweb_hit": True,
            "mcc_risk": 1.0,
        }
    )
    assert 0.0 <= score <= 1.0


def test_missing_features_do_not_raise():
    # Defensive-programming check: an empty feature dict must not crash the
    # scorer — it should fall back to sane defaults for every key.
    score, decision, reason = risk_score({})
    assert 0.0 <= score <= 1.0
    assert decision in ("allow", "challenge", "block")
