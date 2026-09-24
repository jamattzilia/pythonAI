"""Step 4 & 5 — Evaluate predictions and interpret the model."""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                              precision_score, recall_score)

from . import config


def compute_metrics(y_true, y_pred) -> dict:
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, pos_label=1, zero_division=0),
        "recall": recall_score(y_true, y_pred, pos_label=1, zero_division=0),
        "f1_score": f1_score(y_true, y_pred, pos_label=1, zero_division=0),
    }


def print_metrics(metrics: dict) -> None:
    print("\n" + "=" * 70)
    print("STEP 4 - EVALUATION METRICS")
    print("=" * 70)
    print(f"Accuracy : {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}  (of traffic flagged as attack, how much really was)")
    print(f"Recall   : {metrics['recall']:.4f}  (of real attacks, how much was caught)")
    print(f"F1-score : {metrics['f1_score']:.4f}")


def plot_confusion_matrix(y_true, y_pred, out_path: str) -> np.ndarray:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    print("\nConfusion Matrix (rows = actual, columns = predicted):")
    print(pd.DataFrame(cm, index=["actual_normal", "actual_attack"],
                        columns=["pred_normal", "pred_attack"]))

    tn, fp, fn, tp = cm.ravel()
    print(f"\nTrue Negatives  (normal correctly ignored) : {tn}")
    print(f"False Positives (false alarms)              : {fp}")
    print(f"False Negatives (missed attacks)            : {fn}")
    print(f"True Positives  (attacks correctly caught)  : {tp}")

    plt.figure(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["normal", "attack"],
                yticklabels=["normal", "attack"])
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix - Random Forest (NSL-KDD)")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"\nSaved confusion matrix plot to {out_path}")
    return cm


def plot_feature_importance(model, feature_names, out_path: str, top_n: int = config.TOP_N_FEATURES) -> pd.DataFrame:
    print("\n" + "=" * 70)
    print("STEP 5 - INTERPRETABILITY (FEATURE IMPORTANCE)")
    print("=" * 70)

    importances = pd.Series(model.feature_importances_, index=feature_names)
    top_features = importances.sort_values(ascending=False).head(top_n)

    print(f"\nTop {top_n} most important features:")
    print(top_features.to_string(float_format=lambda v: f"{v:.4f}"))

    plt.figure(figsize=(8, 5))
    sns.barplot(x=top_features.values, y=top_features.index, color="tab:blue")
    plt.xlabel("Feature importance")
    plt.ylabel("Feature")
    plt.title(f"Top {top_n} Features Used to Detect Attacks")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"\nSaved feature-importance plot to {out_path}")
    return top_features
