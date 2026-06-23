from typing import Dict, Any, Tuple
import math
from .ml.model import ensemble_ml_score

# Simple thresholds and randomized jitter to reduce predictability
RANDOM_JITTER = 0.02
THRESHOLD_BLOCK = 0.85
THRESHOLD_CHALLENGE = 0.6


def clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


def risk_score(features: Dict[str, Any]) -> Tuple[float, str, str]:
    # Heuristic ensemble placeholder
    amount = float(features.get("amount", 0.0))
    velocity = int(features.get("velocity_1min", 0))
    geo_mismatch = 1.0 if features.get("geo_mismatch") else 0.0
    device_compromised = 1.0 if features.get("device_compromised") else 0.0
    darkweb = 1.0 if features.get("darkweb_hit") else 0.0
    mcc_risk = float(features.get("mcc_risk", 0.2))
    ml = ensemble_ml_score(features)
    s_if = float(ml.get("iforest", 0.0))
    s_ae = float(ml.get("autoencoder", 0.0))

    s_amount = clamp(math.tanh(amount / 500.0))
    s_velocity = clamp(min(1.0, velocity / 5.0))
    s_geo = geo_mismatch
    s_device = device_compromised
    s_dark = darkweb

    # weighted sum
    score = clamp(
        0.25 * s_amount
        + 0.2 * s_velocity
        + 0.1 * s_geo
        + 0.1 * s_device
        + 0.05 * s_dark
        + 0.05 * mcc_risk
        + 0.15 * s_if
        + 0.1 * s_ae
    )

    # jitter to defend against threshold probing
    score = clamp(score + (RANDOM_JITTER if features.get("randomize", True) else 0.0))

    if score >= THRESHOLD_BLOCK:
        return score, "block", "High risk"
    if score >= THRESHOLD_CHALLENGE:
        return score, "challenge", "Medium risk"
    return score, "allow", "Low risk"
