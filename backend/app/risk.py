from typing import Dict, Any, Tuple
import math
from .config import settings
from .ml.model import ensemble_ml_score

# --- Decision thresholds -----------------------------------------------
# Score bands that map the weighted-sum output to a decision. Like the
# feature weights below, these are hand-picked, not fit against labeled
# fraud outcomes — see the HONEST STATUS docstring on risk_score().
THRESHOLD_BLOCK = 0.85
THRESHOLD_CHALLENGE = 0.6

# Jitter added to the final score specifically to make the exact
# score->decision boundary harder to reverse-engineer by an attacker
# submitting many near-identical transactions and observing where the
# decision flips (threshold probing).
RANDOM_JITTER = 0.02

# --- Feature normalization constants ------------------------------------
# Divisor used to squash raw transaction amount into a 0..1 signal via
# tanh(amount / AMOUNT_NORMALIZATION_SCALE). Chosen so that a ~$500
# transaction sits near the middle of the curve for this demo's synthetic
# data; a real system would fit this against an actual amount distribution
# rather than picking a round number.
AMOUNT_NORMALIZATION_SCALE = 500.0

# Number of transactions in the last minute considered "maximally risky"
# for velocity scoring — velocity_1min / VELOCITY_SATURATION_COUNT is
# clamped to 1.0, i.e. 5+ transactions/minute from one user scores as the
# worst-case velocity signal.
VELOCITY_SATURATION_COUNT = 5.0

# Default MCC-risk prior applied when a transaction carries no MCC (or one
# ensemble_features.py doesn't recognize as elevated risk). Matches the
# "not risky" branch in ml/ensemble.py::ensemble_features so a missing MCC
# doesn't silently score as either the risky or the safest possible case.
DEFAULT_MCC_RISK = 0.2

# --- Ensemble weights ----------------------------------------------------
# Hand-picked weights for the final weighted sum. These sum to 1.0 by
# construction (0.25+0.2+0.1+0.1+0.05+0.05+0.15+0.1). Extracted into named
# constants (rather than left as inline literals in the weighted-sum
# expression) so a future calibration pass has one place to look, and so
# the relative importance assigned to each signal is legible without
# reverse-engineering it from the arithmetic.
WEIGHT_AMOUNT = 0.25
WEIGHT_VELOCITY = 0.2
WEIGHT_GEO_MISMATCH = 0.1
WEIGHT_DEVICE_COMPROMISED = 0.1
WEIGHT_DARKWEB_HIT = 0.05
WEIGHT_MCC_RISK = 0.05
WEIGHT_ISOLATION_FOREST = 0.15
WEIGHT_AUTOENCODER = 0.1


def clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


def risk_score(features: Dict[str, Any]) -> Tuple[float, str, str]:
    """
    Heuristic weighted-sum risk scorer.

    HONEST STATUS: this is not a trained ML model. Weights below are
    hand-picked, not fit against labeled fraud data. It is a reasonable,
    explainable placeholder for demonstrating the scoring *pipeline*
    (feature extraction -> score -> threshold -> decision -> alert), but
    the weights themselves have no statistical backing. See README
    "What's Mocked vs. Real" for the full accounting of what would need to
    change to make this a genuine ML system (labeled training data, a real
    IsolationForest/LightGBM model, offline evaluation metrics). See also
    scripts/train_isolation_forest.py and docs/ml_evaluation.md for an actual
    trained-model alternative with a real precision/recall/AUC evaluation,
    offered as an evaluated option rather than a replacement made silently
    load-bearing without evidence.
    """
    amount = float(features.get("amount", 0.0))
    velocity = int(features.get("velocity_1min", 0))
    geo_mismatch = 1.0 if features.get("geo_mismatch") else 0.0
    device_compromised = 1.0 if features.get("device_compromised") else 0.0
    darkweb = 1.0 if features.get("darkweb_hit") else 0.0
    mcc_risk = float(features.get("mcc_risk", DEFAULT_MCC_RISK))
    ml = ensemble_ml_score(features)
    s_if = float(ml.get("iforest", 0.0))
    s_ae = float(ml.get("autoencoder", 0.0))

    s_amount = clamp(math.tanh(amount / AMOUNT_NORMALIZATION_SCALE))
    s_velocity = clamp(min(1.0, velocity / VELOCITY_SATURATION_COUNT))
    s_geo = geo_mismatch
    s_device = device_compromised
    s_dark = darkweb

    score = clamp(
        WEIGHT_AMOUNT * s_amount
        + WEIGHT_VELOCITY * s_velocity
        + WEIGHT_GEO_MISMATCH * s_geo
        + WEIGHT_DEVICE_COMPROMISED * s_device
        + WEIGHT_DARKWEB_HIT * s_dark
        + WEIGHT_MCC_RISK * mcc_risk
        + WEIGHT_ISOLATION_FOREST * s_if
        + WEIGHT_AUTOENCODER * s_ae
    )

    # jitter to defend against threshold probing
    score = clamp(score + (RANDOM_JITTER if features.get("randomize", True) else 0.0))

    return score, *decision_for_score(score)


def decision_for_score(score: float) -> Tuple[str, str]:
    """
    Maps a 0..1 risk score to a (decision, reason) pair using the same
    thresholds regardless of which scorer produced the score. Extracted so
    `compute_risk_score` (below) can apply one consistent decision policy
    to either scorer's output rather than duplicating this if/elif chain —
    the thresholds themselves are a separate, documented approximation
    when applied to the trained model (see `compute_risk_score`'s
    docstring), but the *mapping logic* should not be duplicated.
    """
    if score >= THRESHOLD_BLOCK:
        return "block", "High risk"
    if score >= THRESHOLD_CHALLENGE:
        return "challenge", "Medium risk"
    return "allow", "Low risk"


def compute_risk_score(features: Dict[str, Any]) -> Tuple[float, str, str]:
    """
    Scorer dispatcher used by routers/fraud.py::score_transaction. Selects
    between the heuristic (`risk_score`, default) and the optional trained
    IsolationForest (`RISK_SCORER_BACKEND=isolation_forest`) — see
    config.py::Settings.risk_scorer_backend and
    app/ml/trained_scorer.py for why this is opt-in rather than a silent
    default change.

    CALIBRATION CAVEAT, stated plainly: THRESHOLD_BLOCK/THRESHOLD_CHALLENGE
    were chosen against the heuristic's score distribution, not the
    IsolationForest's. Reusing them here for the trained model's output is
    a reasonable approximation for demonstration purposes (both scorers are
    designed to produce a comparable 0..1 "higher = riskier" scale — see
    trained_scorer.py's squashing function), not a claim that the decision
    boundaries are equally well-calibrated for both scorers. A production
    switch to the trained model would need its own threshold-calibration
    pass against real outcome data, not a reused heuristic threshold.
    """
    if settings.risk_scorer_backend == "isolation_forest":
        from .ml.trained_scorer import trained_risk_score

        score = clamp(trained_risk_score(features))
    else:
        score, _, _ = risk_score(features)

    return score, *decision_for_score(score)
