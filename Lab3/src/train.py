"""Step 2 — Train the IoT/DDoS botnet-traffic classifier and save it.

Algorithm: Random Forest (scikit-learn RandomForestClassifier), as the
assignment recommends. No feature scaling is applied: trees split on raw
per-feature thresholds, so they are invariant to feature scale, and skipping
it also keeps the deployed app simpler (one fewer artifact to keep in sync
between training and inference).
"""
import json
import os

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                              precision_score, recall_score)

from . import config, data_loader, preprocessing

N_ESTIMATORS = 200
TOP_N_FEATURES = 10


def train_model(X_train, y_train) -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        random_state=config.RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    return model


def evaluate(model, X_test, y_test) -> dict:
    y_pred = model.predict(X_test)
    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, pos_label=1, zero_division=0),
        "recall": recall_score(y_test, y_pred, pos_label=1, zero_division=0),
        "f1_score": f1_score(y_test, y_pred, pos_label=1, zero_division=0),
    }
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    return metrics, cm, y_pred


def plot_confusion_matrix(cm, out_path: str) -> None:
    plt.figure(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["safe", "threat"], yticklabels=["safe", "threat"])
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix - IoT Botnet Traffic Classifier")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"Saved confusion matrix plot to {out_path}")


def plot_feature_importance(model, feature_names, out_path: str, top_n: int = TOP_N_FEATURES) -> pd.Series:
    importances = pd.Series(model.feature_importances_, index=feature_names)
    top = importances.sort_values(ascending=False).head(top_n)
    plt.figure(figsize=(8, 5))
    sns.barplot(x=top.values, y=top.index, color="tab:blue")
    plt.xlabel("Feature importance")
    plt.ylabel("Feature")
    plt.title(f"Top {top_n} Flow Features Used to Detect Threats")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"Saved feature-importance plot to {out_path}")
    return top


def run() -> None:
    os.makedirs(config.MODELS_DIR, exist_ok=True)
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)

    # STEP 1 - Load & explore
    df = data_loader.load_raw_data()
    data_loader.explore(df)

    # STEP 1b - Clean & prepare
    print("\n" + "=" * 70)
    print("STEP 1b - DATA CLEANING & FEATURE PREPARATION")
    print("=" * 70)
    X_train, X_test, y_train, y_test, feature_names = preprocessing.prepare(df)
    print(f"After cleaning: {len(X_train) + len(X_test)} usable flow records, "
          f"{len(feature_names)} features")
    print(f"Features: {feature_names}")
    print(f"Training set: {len(X_train)} flows ({(y_train == 1).sum()} threat, "
          f"{(y_train == 0).sum()} safe)")
    print(f"Testing set:  {len(X_test)} flows ({(y_test == 1).sum()} threat, "
          f"{(y_test == 0).sum()} safe)")

    # STEP 2 - Train & evaluate
    print("\n" + "=" * 70)
    print("STEP 2 - MODEL TRAINING (Random Forest)")
    print("=" * 70)
    model = train_model(X_train, y_train)
    print(f"Trained RandomForestClassifier(n_estimators={N_ESTIMATORS}) on "
          f"{len(X_train)} labeled flows.")

    metrics, cm, _ = evaluate(model, X_test, y_test)
    print("\nEvaluation metrics (test set):")
    print(f"Accuracy : {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall   : {metrics['recall']:.4f}")
    print(f"F1-score : {metrics['f1_score']:.4f}")
    tn, fp, fn, tp = cm.ravel()
    print(f"\nConfusion matrix: TN={tn} FP={fp} FN={fn} TP={tp}")

    plot_confusion_matrix(cm, os.path.join(config.OUTPUT_DIR, "confusion_matrix.png"))
    top_features = plot_feature_importance(
        model, feature_names, os.path.join(config.OUTPUT_DIR, "feature_importance.png"))
    print("\nTop features:")
    print(top_features.to_string(float_format=lambda v: f"{v:.4f}"))

    # Save the model bundle: the fitted estimator + everything app.py needs
    # to reproduce identical preprocessing at inference time.
    bundle = {
        "model": model,
        "feature_names": feature_names,
        "metrics": metrics,
        "n_estimators": N_ESTIMATORS,
        "training_rows": len(X_train),
    }
    joblib.dump(bundle, config.MODEL_PATH)
    print(f"\nSaved model bundle to {config.MODEL_PATH}")

    with open(os.path.join(config.OUTPUT_DIR, "metrics.json"), "w") as f:
        json.dump({**metrics, "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}, f, indent=2)

    print("\n" + "=" * 70)
    print("DONE - model saved to models/iot_botnet_model.pkl")
    print("Run the dashboard with: streamlit run app.py")
    print("=" * 70)


if __name__ == "__main__":
    run()
