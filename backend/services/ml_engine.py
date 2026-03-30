"""
ML Anomaly Detection Engine
============================
Uses IsolationForest on REAL trust scores derived from actual log events.
The model is retrained on each new batch of real data.
No fake scores are ever fed into this model.
"""

from sklearn.ensemble import IsolationForest
import numpy as np

_model = IsolationForest(contamination=0.15, random_state=42)


def detect_anomaly(trust_scores: list[int]) -> tuple[list[int], list[float]]:
    """
    Input:  list of real trust scores from actual log events
    Output: (is_anomaly list, raw_scores list)
            is_anomaly[i] = 1 if anomalous, 0 if normal
    """
    if len(trust_scores) < 5:
        return [0] * len(trust_scores), [0.0] * len(trust_scores)

    data = np.array(trust_scores).reshape(-1, 1)
    _model.fit(data)
    predictions = _model.predict(data)
    raw_scores = _model.decision_function(data)

    return (
        [1 if p == -1 else 0 for p in predictions],
        raw_scores.tolist()
    )