"""Step 3 — Train the Isolation Forest anomaly-detection model."""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from . import config


def train_isolation_forest(X_train: pd.DataFrame) -> IsolationForest:
    """Fit an Isolation Forest on normal traffic only.

    Isolation Forest builds an ensemble of random trees that isolate points
    by randomly splitting feature values. Anomalous points (packets whose
    feature values are unusual, e.g. an all-flags-off NULL scan or an
    XMAS-scan flag combination) tend to require far fewer random splits to
    isolate than normal points, giving them a shorter average path length
    and therefore a lower ("more anomalous") score.

    contamination="auto" lets scikit-learn set the decision threshold using
    the standard heuristic from the original Isolation Forest paper, since
    the training data here is (by construction) pure normal traffic.
    """
    model = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination="auto",
        random_state=config.RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train)
    return model


def predict(model: IsolationForest, X: pd.DataFrame):
    """Return (binary_predictions, anomaly_scores).

    binary_predictions: 1 = anomaly (predicted attack), 0 = normal.
    anomaly_scores: higher = more normal, lower = more anomalous
    (scikit-learn's decision_function convention).
    """
    raw_pred = model.predict(X)  # -1 = anomaly, 1 = normal
    binary_pred = np.where(raw_pred == -1, 1, 0)
    scores = model.decision_function(X)
    return binary_pred, scores
