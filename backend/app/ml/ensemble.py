from typing import Any, Dict

# HONEST STATUS (see README "What's Mocked vs. Real"): this is a
# hand-written heuristic feature extractor, not a trained model. A real
# implementation would derive `mcc_risk` from a labeled dataset (e.g. MCC
# category fraud-rate priors) rather than a hardcoded set of "risky" codes.
# Replacing this with real trained models (LightGBM / Isolation Forest /
# Autoencoder / GNN) is intentionally out of scope for this remediation
# pass and is tracked as a roadmap item, not silently implied to exist.

# Merchant Category Codes treated as elevated-risk in this heuristic:
# 4829 = Money Transfer, 7995 = Betting/Gambling, 6051 = Quasi-Cash /
# Financial Institution (cash-equivalent). Named here (rather than left as
# an inline set literal) so the risk rationale for each code is visible at
# the definition site instead of requiring a lookup against the MCC
# standard to understand what the magic strings mean.
ELEVATED_RISK_MCCS = {"4829", "7995", "6051"}
ELEVATED_MCC_RISK_SCORE = 0.6
DEFAULT_MCC_RISK_SCORE = 0.2


def ensemble_features(tx: Dict[str, Any]) -> Dict[str, Any]:
    amount = tx.get("amount", 0.0)
    mcc = (tx.get("mcc") or "")
    ip = tx.get("ip")
    gps_lat = tx.get("gps_lat")
    gps_lon = tx.get("gps_lon")

    # Simple derived features
    mcc_risky = ELEVATED_MCC_RISK_SCORE if mcc in ELEVATED_RISK_MCCS else DEFAULT_MCC_RISK_SCORE
    geo_mismatch = bool(ip and gps_lat is not None and gps_lon is not None and tx.get("timezone_mismatch"))

    features = {
        "amount": amount,
        "mcc_risk": mcc_risky,
        "geo_mismatch": geo_mismatch,
        "device_compromised": bool(tx.get("device_compromised")),
        "darkweb_hit": bool(tx.get("darkweb_hit")),
        "velocity_1min": int(tx.get("velocity_1min", 0)),
        "randomize": True,
    }
    return features
