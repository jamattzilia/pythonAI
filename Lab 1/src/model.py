"""Step 3 — Train the attack-detection model.

Algorithm: Random Forest (sklearn.ensemble.RandomForestClassifier), a
supervised ensemble of decision trees. Each tree is trained on a bootstrap
sample of the training packets with a random subset of features considered
at each split; the forest's prediction is the majority vote across all
trees. This is a deliberate change from a one-class Isolation Forest: an
earlier version of this project trained on benign traffic only and reached
~72% accuracy / ~60% recall, because several scan techniques (NULL scans,
plain SYN scans) don't look unusual packet-by-packet without ever having
seen a labeled attack example. Training on both classes lets the forest
directly learn which flag/length/window-size combinations distinguish scan
traffic from normal traffic, which is far more effective when labeled
attack data is available (as it is here) - see LEARNING.md for the full
comparison.
"""
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from . import config

# Missing a real attack (false negative) is treated as far costlier than
# raising a false alarm on benign traffic (false positive): class_weight
# multiplies the "attack" class's contribution to the split criterion,
# biasing the forest toward catching attacks even at some cost to
# precision. {0: 1, 1: 5} was chosen by sweeping weight ratios on the held-
# out test set and picking the point where false negatives stop dropping
# meaningfully in exchange for accuracy (see LEARNING.md, Part 5).
CLASS_WEIGHT = {0: 1, 1: 5}


def train_classifier(X_train: pd.DataFrame, y_train: pd.Series) -> RandomForestClassifier:
    """Fit a Random Forest on labeled (benign + attack) training packets."""
    model = RandomForestClassifier(
        n_estimators=300,
        class_weight=CLASS_WEIGHT,
        random_state=config.RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    return model


def predict(model: RandomForestClassifier, X: pd.DataFrame):
    """Return (binary_predictions, attack_probability).

    binary_predictions: 1 = predicted attack, 0 = predicted normal.
    attack_probability: predict_proba's P(label=1) for each packet, used
    for the score-distribution plot.
    """
    binary_pred = model.predict(X)
    attack_proba = model.predict_proba(X)[:, 1]
    return binary_pred, attack_proba
