"""Step 1b — Clean the raw flow records and engineer the model-ready features.

CICFlowMeter (the tool that produced this CSV) writes " Flow Bytes/s" and
" Flow Packets/s" as inf whenever a flow's duration rounds to zero (a
division by zero) - a well-known quirk of this dataset family. Handling that
correctly, dropping host/port/time metadata that would leak this one
capture's specific setup, and binarizing the label are all done here so
train.py and app.py apply byte-for-byte identical preprocessing.
"""
from typing import List, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from . import config


def clean_features(df: pd.DataFrame) -> pd.DataFrame:
    """Drop identifying columns, fix infinities, and drop incomplete rows."""
    df = df.copy()
    df = df.drop(columns=[c for c in config.DROP_COLUMNS if c in df.columns])
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    return df


def binarize_label(df: pd.DataFrame) -> pd.DataFrame:
    """Add a binary target: 0 = benign traffic, 1 = DDoS/botnet threat."""
    df = df.copy()
    df[config.TARGET_COLUMN] = (df[config.LABEL_COLUMN] != "BENIGN").astype(int)
    return df


def feature_columns(df: pd.DataFrame) -> List[str]:
    return [c for c in df.columns if c not in (config.LABEL_COLUMN, config.TARGET_COLUMN)]


def prepare(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, List[str]]:
    """Run the full cleaning + labeling pipeline and return a stratified split.

    Returns X_train, X_test, y_train, y_test, feature_names.
    """
    df = clean_features(df)
    df = binarize_label(df)

    feat_cols = feature_columns(df)
    X = df[feat_cols]
    y = df[config.TARGET_COLUMN]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=config.TEST_SIZE, random_state=config.RANDOM_STATE, stratify=y)

    return X_train, X_test, y_train, y_test, feat_cols


def transform_for_inference(raw_df: pd.DataFrame, feature_names: List[str]) -> pd.DataFrame:
    """Prepare an arbitrary uploaded CSV (e.g. in the Streamlit app) the same
    way training data was prepared, WITHOUT dropping rows or requiring a
    Label column - every uploaded row must get a prediction, and unlabeled
    live logs have no Label column at all.

    Missing engineered columns are filled with 0 (only happens if the
    uploaded file uses a slightly different flow-export schema); infinities
    are clipped to a large finite value instead of dropped, since an
    uploaded flow that would have been discarded during training still needs
    a verdict when a user is testing the deployed app live.
    """
    df = raw_df.copy()
    df.columns = [c.strip() for c in df.columns]
    df = df.drop(columns=[c for c in config.DROP_COLUMNS if c in df.columns])
    if config.LABEL_COLUMN in df.columns:
        df = df.drop(columns=[config.LABEL_COLUMN])

    for col in feature_names:
        if col not in df.columns:
            df[col] = 0
    df = df[feature_names]

    df = df.apply(pd.to_numeric, errors="coerce")
    df = df.replace([np.inf, -np.inf], np.finfo(np.float64).max)
    df = df.fillna(0)
    return df
