from typing import Dict, Any

# Placeholder ML ensemble: in production, plug real models (LightGBM, IF, Autoencoder, GNN)


def ensemble_features(tx: Dict[str, Any]) -> Dict[str, Any]:
    amount = tx.get("amount", 0.0)
    mcc = (tx.get("mcc") or "")
    ip = tx.get("ip")
    gps_lat = tx.get("gps_lat")
    gps_lon = tx.get("gps_lon")

    # Simple derived features
    mcc_risky = 0.6 if mcc in {"4829", "7995", "6051"} else 0.2
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
