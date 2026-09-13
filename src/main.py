"""AI-Based Network Anomaly Detection - end-to-end pipeline.

Dataset → Data Exploration → Data Preparation → Train/Test Data →
ML Model → Anomaly Detection → Evaluation → Analysis

Dataset: AB-TRAP (c2dc/AB-TRAP) Local Area Network testbed.
  - Attack capture: packets from real port-scanning tools (nmap, hping3,
    masscan, unicornscan, zmap) run against several LAN targets.
  - Bonafide capture: packets from genuine background traffic on the same
    network with no attack running.
Algorithm: Isolation Forest (unsupervised anomaly detection).
"""
import os

from . import config, data_loader, evaluate, model, preprocessing


def run() -> None:
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)

    # STEP 1 - Download & explore
    attack_packets, attack_labels, bonafide_packets = data_loader.load_raw_data()
    data_loader.explore(attack_packets, attack_labels, bonafide_packets)

    # STEP 2 - Prepare data for ML
    print("\n" + "=" * 70)
    print("STEP 2 - DATA PREPARATION")
    print("=" * 70)
    labeled = preprocessing.build_labeled_dataset(attack_packets, attack_labels, bonafide_packets)
    features = preprocessing.preprocess_features(labeled)
    print(f"Final feature matrix: {features.shape[0]} rows x "
          f"{features.shape[1] - 2} features (+ label + attack_type)")
    print(f"Features used: {[c for c in features.columns if c not in ('label', 'attack_type')]}")
    print(f"Class balance -> benign: {(features.label == 0).sum()}, "
          f"attack: {(features.label == 1).sum()}")

    X_train, X_test, y_train, y_test, _, attack_type_test = \
        preprocessing.split_for_anomaly_detection(features)
    print(f"\nTraining set (benign only): {X_train.shape[0]} packets")
    print(f"Testing set (unseen benign + all attack packets): {X_test.shape[0]} packets")

    # STEP 3 - Train the model
    print("\n" + "=" * 70)
    print("STEP 3 - MODEL TRAINING (Isolation Forest)")
    print("=" * 70)
    clf = model.train_isolation_forest(X_train)
    print(f"Trained IsolationForest(n_estimators={clf.n_estimators}, "
          f"contamination={clf.contamination}) on {X_train.shape[0]} normal packets.")

    # STEP 4 - Predict & evaluate
    y_pred, scores = model.predict(clf, X_test)
    metrics = evaluate.compute_metrics(y_test, y_pred)
    evaluate.print_metrics(metrics)
    cm = evaluate.plot_confusion_matrix(
        y_test, y_pred, os.path.join(config.OUTPUT_DIR, "confusion_matrix.png"))
    evaluate.plot_score_distribution(
        scores, y_test, os.path.join(config.OUTPUT_DIR, "anomaly_scores.png"))

    # STEP 5 - Analyze results
    per_type = evaluate.analyze_detections(X_test, y_test, y_pred, attack_type_test)
    evaluate.save_summary(
        metrics, cm, per_type, X_train.shape[0], X_test.shape[0],
        int((y_pred == 1).sum()), os.path.join(config.OUTPUT_DIR, "summary.json"))

    print("\n" + "=" * 70)
    print("DONE - see the outputs/ folder for the confusion matrix, anomaly")
    print("score plot and a JSON summary of this run.")
    print("=" * 70)


if __name__ == "__main__":
    run()
