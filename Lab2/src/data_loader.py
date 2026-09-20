"""Step 1 — Load the NSL-KDD dataset and run exploratory data analysis."""
import os

import pandas as pd
import requests

from . import config


def _download(url: str, dest_path: str) -> None:
    if os.path.exists(dest_path):
        return
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    print(f"Downloading {url}")
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    with open(dest_path, "wb") as f:
        f.write(response.content)


def download_dataset() -> None:
    """Fetch KDDTrain+.txt / KDDTest+.txt into data/ if not already present."""
    _download(config.TRAIN_URL, config.TRAIN_PATH)
    _download(config.TEST_URL, config.TEST_PATH)


def load_raw_data():
    """Load the train/test files with the lab-specified column names.

    The files have no header row, so the column names are passed manually,
    exactly as the assignment requires.
    """
    download_dataset()
    train_df = pd.read_csv(config.TRAIN_PATH, header=None, names=config.COLUMN_NAMES)
    test_df = pd.read_csv(config.TEST_PATH, header=None, names=config.COLUMN_NAMES)
    return train_df, test_df


def explore(train_df: pd.DataFrame, test_df: pd.DataFrame) -> None:
    """Print the Step 1 exploratory data analysis the lab asks for."""
    print("=" * 70)
    print("STEP 1 - DATA LOADING & EXPLORATORY DATA ANALYSIS")
    print("=" * 70)

    print(f"\nTraining set: {train_df.shape[0]} rows x {train_df.shape[1]} columns")
    print(f"Testing set:  {test_df.shape[0]} rows x {test_df.shape[1]} columns")

    print(f"\nUnique attack_type values in TRAIN ({train_df[config.TARGET_COLUMN].nunique()} total):")
    print(train_df[config.TARGET_COLUMN].value_counts())

    test_only = set(test_df[config.TARGET_COLUMN].unique()) - set(train_df[config.TARGET_COLUMN].unique())
    print(f"\nAttack types present in TEST but never seen in TRAIN "
          f"({len(test_only)}): {sorted(test_only)}")
    print("(These are exactly why a NIDS must be evaluated on held-out, "
          "truly unseen attack types - see README.md control question 3.)")

    print(f"\nMissing values - train: {train_df.isna().sum().sum()}, "
          f"test: {test_df.isna().sum().sum()}")


def drop_difficulty_level(df: pd.DataFrame) -> pd.DataFrame:
    """Drop 'difficulty_level' (dataset metadata, not a traffic feature)."""
    return df.drop(columns=["difficulty_level"])
