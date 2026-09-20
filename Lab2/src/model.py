"""Step 3 — Train the intrusion-detection classifier.

Algorithm: Random Forest (sklearn.ensemble.RandomForestClassifier), as the
lab recommends. It is an ensemble of decision trees, each trained on a
bootstrap sample of the training rows with a random subset of features
considered at each split; the forest's prediction is the majority vote
across all trees. It handles the mix of scaled numeric features and
label-encoded categorical features used here without further tuning, and
exposes feature_importances_ for Step 5.
"""
from sklearn.ensemble import RandomForestClassifier

from . import config


def train_model(X_train, y_train) -> RandomForestClassifier:
    """Fit a Random Forest classifier on the preprocessed training data."""
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=config.RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    return model
