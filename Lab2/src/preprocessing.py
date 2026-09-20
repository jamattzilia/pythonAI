"""Step 2 — Turn the raw NSL-KDD records into a model-ready feature matrix.

Every transformation here is fit on the TRAINING set only, then applied
to both train and test - this is what the lab means by "the test dataset
must undergo the exact same preprocessing steps as the training dataset"
and "fit the scaler on the training dataset only." Fitting anything
(scaler, category vocabulary) on the test set would leak information the
model would never have in a real deployment, and would make the reported
metrics overly optimistic.
"""
from typing import List, Tuple

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from . import config


def binarize_label(df: pd.DataFrame) -> pd.DataFrame:
    """Add a binary Label column: 0 = normal, 1 = any attack.

    NSL-KDD's attack_type has ~20-40 distinct attack names (many of them
    only in the test set - see data_loader.explore). For this lab the task
    is binary intrusion detection (normal vs. attack), so every non-normal
    label collapses to class 1 regardless of which specific attack it is.
    """
    df = df.copy()
    df[config.LABEL_COLUMN] = (df[config.TARGET_COLUMN] != "normal").astype(int)
    return df


def encode_categoricals(train_df: pd.DataFrame, test_df: pd.DataFrame,
                         columns: List[str]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Label-encode categorical columns using a vocabulary built from TRAIN only.

    NSL-KDD's `service` column famously contains a handful of values in the
    test set (e.g. rare services) that never appear in training. A plain
    sklearn LabelEncoder.fit(test) or fitting on the concatenation of both
    sets would silently leak test-set category information into training.
    Instead, each column's category codes are assigned from the sorted
    training vocabulary; any category the test set contains that training
    never saw is mapped to one extra "unseen" code appended after the
    training categories, so the model handles it explicitly rather than
    crashing or being told about it in advance.
    """
    train_df = train_df.copy()
    test_df = test_df.copy()

    for col in columns:
        categories = sorted(train_df[col].unique())
        code_map = {category: code for code, category in enumerate(categories)}
        unseen_code = len(categories)  # reserved for categories not in training

        train_df[col] = train_df[col].map(code_map).astype(np.int64)
        test_df[col] = test_df[col].map(code_map).fillna(unseen_code).astype(np.int64)

    return train_df, test_df


def scale_features(X_train: pd.DataFrame, X_test: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, StandardScaler]:
    """Standardize all numeric features, fitting the scaler on X_train only."""
    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(
        scaler.fit_transform(X_train), columns=X_train.columns, index=X_train.index)
    X_test_scaled = pd.DataFrame(
        scaler.transform(X_test), columns=X_test.columns, index=X_test.index)
    return X_train_scaled, X_test_scaled, scaler


def prepare(train_df: pd.DataFrame, test_df: pd.DataFrame):
    """Run the full Step 2 pipeline and return model-ready arrays.

    Returns X_train, X_test, y_train, y_test, feature_names.
    """
    train_df = binarize_label(train_df)
    test_df = binarize_label(test_df)

    train_df, test_df = encode_categoricals(train_df, test_df, config.CATEGORICAL_COLUMNS)

    feature_cols = [c for c in train_df.columns
                    if c not in (config.TARGET_COLUMN, config.LABEL_COLUMN)]

    X_train_raw = train_df[feature_cols]
    X_test_raw = test_df[feature_cols]
    y_train = train_df[config.LABEL_COLUMN]
    y_test = test_df[config.LABEL_COLUMN]

    X_train, X_test, _ = scale_features(X_train_raw, X_test_raw)

    return X_train, X_test, y_train, y_test, feature_cols
