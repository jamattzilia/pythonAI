"""AI-Based Network Intrusion Detection System (NIDS) - end-to-end pipeline.

Dataset: NSL-KDD (KDDTrain+.txt / KDDTest+.txt).
Algorithm: Random Forest (supervised binary classification: normal vs. attack).

Steps: Load & explore -> Preprocess (binarize label, encode categoricals,
scale features) -> Train -> Evaluate (Accuracy/Precision/Recall/F1,
Confusion Matrix) -> Interpret (top-10 feature importance).
"""
import os

from . import config, data_loader, evaluate, model, preprocessing


def run() -> None:
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)

    # STEP 1 - Load & explore
    train_df, test_df = data_loader.load_raw_data()
    data_loader.explore(train_df, test_df)
    train_df = data_loader.drop_difficulty_level(train_df)
    test_df = data_loader.drop_difficulty_level(test_df)

    # STEP 2 - Preprocess
    print("\n" + "=" * 70)
    print("STEP 2 - DATA PREPROCESSING")
    print("=" * 70)
    X_train, X_test, y_train, y_test, feature_names = preprocessing.prepare(train_df, test_df)
    print(f"Features: {len(feature_names)} columns "
          f"({len(config.CATEGORICAL_COLUMNS)} categorical, label-encoded; "
          f"rest numeric, standardized)")
    print(f"Training set: {X_train.shape[0]} rows "
          f"({(y_train == 1).sum()} attack, {(y_train == 0).sum()} normal)")
    print(f"Testing set:  {X_test.shape[0]} rows "
          f"({(y_test == 1).sum()} attack, {(y_test == 0).sum()} normal)")

    # STEP 3 - Train
    print("\n" + "=" * 70)
    print("STEP 3 - MODEL TRAINING (Random Forest)")
    print("=" * 70)
    clf = model.train_model(X_train, y_train)
    print(f"Trained RandomForestClassifier(n_estimators={clf.n_estimators}) "
          f"on {X_train.shape[0]} labeled rows.")

    # STEP 4 - Evaluate
    print(f"\nDecision threshold: {config.DECISION_THRESHOLD} "
          f"(lowered from the default 0.5 to minimize false negatives - see model.py)")
    y_pred, attack_proba = model.predict(clf, X_test)
    metrics = evaluate.compute_metrics(y_test, y_pred)
    evaluate.print_metrics(metrics)
    evaluate.plot_confusion_matrix(
        y_test, y_pred, os.path.join(config.OUTPUT_DIR, "confusion_matrix.png"))

    # STEP 5 - Interpret
    evaluate.plot_feature_importance(
        clf, feature_names, os.path.join(config.OUTPUT_DIR, "feature_importance.png"))

    print("\n" + "=" * 70)
    print("DONE - see the outputs/ folder for the confusion matrix and")
    print("feature-importance plots.")
    print("=" * 70)


if __name__ == "__main__":
    run()
