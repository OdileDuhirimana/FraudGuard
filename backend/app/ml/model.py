import json
import os
from typing import Dict, Any, Optional
import numpy as np

_ARTIFACTS: Optional[Dict[str, Any]] = None


def load_artifacts() -> Optional[Dict[str, Any]]:
    global _ARTIFACTS
    if _ARTIFACTS is not None:
        return _ARTIFACTS
    path = os.getenv("FG_ML_ARTIFACTS", "")
    if path and os.path.exists(path):
        with open(path, "r") as f:
            _ARTIFACTS = json.load(f)
    else:
        _ARTIFACTS = None
    return _ARTIFACTS


def _vectorize(features: Dict[str, Any]) -> np.ndarray:
    keys = [
        "amount",
        "velocity_1min",
        "mcc_risk",
        "geo_mismatch",
        "device_compromised",
        "darkweb_hit",
    ]
    return np.array([float(features.get(k, 0.0)) for k in keys], dtype=np.float64)


def pca_recon_error(x: np.ndarray, art: Optional[Dict[str, Any]]) -> float:
    if not isinstance(art, dict) or "pca" not in art:
        # simple fallback: variance ratio on normalized vector
        return float(np.linalg.norm(x) / (1.0 + len(x)))
    p = art["pca"]
    mean = np.array(p.get("mean", [0.0] * len(x)), dtype=np.float64)
    comps = np.array(p.get("components", []), dtype=np.float64)  # shape (k, d)
    if comps.size == 0:
        return float(np.linalg.norm(x - mean))
    x0 = x - mean
    # project and reconstruct
    z = comps @ x0
    x_hat = comps.T @ z
    err = np.linalg.norm(x0 - x_hat)
    return float(err)


def iforest_score(x: np.ndarray, art: Optional[Dict[str, Any]]) -> float:
    # Isolation forest surrogate: distance from mean scaled by std
    if not isinstance(art, dict) or "scaler" not in art:
        return float(np.tanh(np.linalg.norm(x) / 5.0))
    s = art["scaler"]
    mean = np.array(s.get("mean", [0.0] * len(x)), dtype=np.float64)
    std = np.array(s.get("std", [1.0] * len(x)), dtype=np.float64)
    std = np.where(std == 0, 1.0, std)
    z = (x - mean) / std
    d = np.linalg.norm(z) / np.sqrt(len(z))
    return float(np.tanh(d / 2.0))


def ensemble_ml_score(features: Dict[str, Any]) -> Dict[str, float]:
    art = load_artifacts()
    x = _vectorize(features)
    s_if = iforest_score(x, art)
    s_pca = pca_recon_error(x, art)
    # normalize pca error into 0..1 range using a soft scaling
    s_pca_n = float(np.tanh(s_pca))
    return {"iforest": s_if, "autoencoder": s_pca_n}
