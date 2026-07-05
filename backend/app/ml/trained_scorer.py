"""
Optional trained-model risk scorer, loading the IsolationForest artifact
produced by scripts/train_isolation_forest.py.

Why this is opt-in (RISK_SCORER_BACKEND=isolation_forest, default remains
"heuristic"): app/risk.py's heuristic is what the existing, passing test
suite (test_risk_scoring_unit.py, test_scoring.py) asserts specific
threshold/decision behavior against — those tests encode real product
decisions about what "block" vs "challenge" means for THIS heuristic's
score distribution. Silently swapping the default scorer would invalidate
those tests' assumptions without any evidence the trained model's score
distribution should map to the same thresholds (THRESHOLD_BLOCK=0.85,
THRESHOLD_CHALLENGE=0.6 were tuned against the heuristic's output shape,
not the IsolationForest's). Offering the trained model as a selectable,
evaluated alternative — with its own honest evaluation report in
docs/ml_evaluation.md — is the responsible way to make it available
without asserting equivalence that hasn't been established.

If the artifact file is missing (e.g. scripts/train_isolation_forest.py
was never run), `load_artifact()` returns None and `trained_risk_score`
raises a clear, actionable error rather than silently falling back to
something else — a misconfigured RISK_SCORER_BACKEND should fail loudly,
not degrade quietly.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

ARTIFACT_PATH = Path(__file__).resolve().parent / "artifacts" / "isolation_forest.joblib"

_ARTIFACT: Optional[Dict[str, Any]] = None


class TrainedModelUnavailableError(RuntimeError):
    """Raised when RISK_SCORER_BACKEND=isolation_forest but no trained artifact exists."""


def load_artifact() -> Optional[Dict[str, Any]]:
    global _ARTIFACT
    if _ARTIFACT is not None:
        return _ARTIFACT
    if not ARTIFACT_PATH.exists():
        return None
    import joblib

    _ARTIFACT = joblib.load(ARTIFACT_PATH)
    return _ARTIFACT


def trained_risk_score(features: Dict[str, Any]) -> float:
    """
    Scores a feature dict (same shape as app/ml/ensemble.py::ensemble_features)
    using the trained IsolationForest, returning a 0..1 anomaly score where
    higher means more fraud-like — the same convention as
    app/risk.py::risk_score's return value, so callers can compare the two
    scorers directly.

    Note on normalization: unlike the training-time evaluation (which
    normalizes against the min/max of a whole test batch), a single live
    request has no "batch" to normalize against. `decision_function` scores
    are therefore passed through a fixed sigmoid-like squashing instead,
    which is a reasonable, monotonic approximation for a single-sample
    score — documented here rather than silently reusing the training
    normalization out of context.
    """
    artifact = load_artifact()
    if artifact is None:
        raise TrainedModelUnavailableError(
            "RISK_SCORER_BACKEND=isolation_forest but no trained artifact exists at "
            f"{ARTIFACT_PATH}. Run `python -m scripts.train_isolation_forest` from backend/ first."
        )

    import numpy as np

    model = artifact["model"]
    scaler = artifact["scaler"]
    feature_names = artifact["feature_names"]

    x = np.array([[float(features.get(name, 0.0)) for name in feature_names]])
    x_scaled = scaler.transform(x)
    raw_score = -model.decision_function(x_scaled)[0]  # higher = more anomalous
    # Squash to (0, 1) via a logistic function centered at 0 — decision_function
    # scores are typically small (roughly -0.5..0.5), so a scale factor keeps
    # the squash from saturating at both ends immediately.
    return float(1.0 / (1.0 + np.exp(-raw_score * 6.0)))
