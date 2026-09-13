"""Step 4 & 5 — Evaluate predictions and analyze detected anomalies."""
import json
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
    print(f"Precision: {metrics['precision']:.4f}  (of packets flagged as attack, how many really were)")
    print(f"Recall   : {metrics['recall']:.4f}  (of real attack packets, how many were caught)")
    print(f"F1-score : {metrics['f1_score']:.4f}")


def plot_confusion_matrix(y_true, y_pred, out_path: str) -> np.ndarray:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    print("\nConfusion Matrix (rows = actual, columns = predicted):")
    print(pd.DataFrame(cm, index=["actual_normal", "actual_attack"],
                        columns=["pred_normal", "pred_attack"]))

    tn, fp, fn, tp = cm.ravel()
    print(f"\nTrue Negatives  (normal correctly ignored) : {tn}")
    print(f"False Positives (normal flagged as attack)  : {fp}")
    print(f"False Negatives (attack missed)              : {fn}")
    print(f"True Positives  (attack correctly detected)  : {tp}")

    plt.figure(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["normal", "attack"],
                yticklabels=["normal", "attack"])
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix - Isolation Forest")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"\nSaved confusion matrix plot to {out_path}")
    return cm


def plot_score_distribution(scores, y_true, out_path: str) -> None:
    plt.figure(figsize=(7, 4))
    scores = np.asarray(scores)
    y_true = np.asarray(y_true)
    sns.histplot(scores[y_true == 0], color="tab:blue", label="normal",
                 stat="density", kde=True, alpha=0.5)
    sns.histplot(scores[y_true == 1], color="tab:red", label="attack",
                 stat="density", kde=True, alpha=0.5)
    plt.axvline(0, color="black", linestyle="--", linewidth=1,
                label="decision threshold")
    plt.xlabel("Isolation Forest anomaly score (lower = more anomalous)")
    plt.ylabel("Density")
    plt.title("Anomaly Score Distribution by True Label")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"Saved anomaly-score distribution plot to {out_path}")


def analyze_detections(X_test, y_test, y_pred, attack_type_test) -> pd.DataFrame:
    print("\n" + "=" * 70)
    print("STEP 5 - RESULTS ANALYSIS")
    print("=" * 70)

    results = pd.DataFrame({
        "attack_type": attack_type_test.values,
        "actual": y_test.values,
        "predicted": y_pred,
    })

    n_detected = int((y_pred == 1).sum())
    print(f"\nTotal packets flagged as anomalous: {n_detected} / {len(y_pred)}")

    per_type = results.groupby("attack_type").apply(
        lambda g: pd.Series({
            "packets": len(g),
            "detected": int((g["predicted"] == 1).sum()),
            "detection_rate": (g["predicted"] == 1).mean(),
        })
    ).sort_values("detection_rate")

    print("\nDetection rate by traffic type (benign row = false-positive rate):")
    print(per_type.to_string(float_format=lambda v: f"{v:.3f}"))

    fp_examples = results[(results.actual == 0) & (results.predicted == 1)].head(5)
    fn_examples = results[(results.actual == 1) & (results.predicted == 0)].head(5)
    tp_examples = results[(results.actual == 1) & (results.predicted == 1)].head(5)

    print(f"\nExample true positives (correctly detected attacks):\n{tp_examples}")
    print(f"\nExample false positives (benign flagged as attack):\n{fp_examples}")
    print(f"\nExample false negatives (attacks missed):\n{fn_examples}")

    return per_type


def save_summary(metrics: dict, cm, per_type: pd.DataFrame, n_train: int,
                  n_test: int, n_anomalies: int, out_path: str) -> None:
    summary = {
        "algorithm": "Isolation Forest (sklearn.ensemble.IsolationForest)",
        "n_train_samples": n_train,
        "n_test_samples": n_test,
        "n_detected_anomalies": n_anomalies,
        "metrics": metrics,
        "confusion_matrix": {
            "tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
            "fn": int(cm[1, 0]), "tp": int(cm[1, 1]),
        },
        "detection_rate_by_type": per_type["detection_rate"].round(4).to_dict(),
    }
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved run summary to {out_path}")
