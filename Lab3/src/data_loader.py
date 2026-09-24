"""Step 1a — Download and load the raw network-flow dataset."""
import os

import numpy as np
import pandas as pd
import requests

from . import config


def download_dataset() -> None:
    """Fetch the raw CICIDS2017 DDoS-capture CSV into data/raw/ if missing."""
    if os.path.exists(config.RAW_CSV_PATH):
        return
    os.makedirs(config.RAW_DATA_DIR, exist_ok=True)
    print(f"Downloading {config.RAW_CSV_URL}")
    response = requests.get(config.RAW_CSV_URL, timeout=120)
    response.raise_for_status()
    with open(config.RAW_CSV_PATH, "wb") as f:
        f.write(response.content)


def load_raw_data() -> pd.DataFrame:
    """Load the raw CSV and strip the stray leading spaces CICFlowMeter puts
    in every column name (e.g. " Flow Duration")."""
    download_dataset()
    df = pd.read_csv(config.RAW_CSV_PATH)
    df.columns = [c.strip() for c in df.columns]
    return df


def explore(df: pd.DataFrame) -> None:
    """Print the Step 1 exploratory summary."""
    print("=" * 70)
    print("STEP 1 - DATA LOADING & EXPLORATION")
    print("=" * 70)
    print(f"\nRaw flow records: {df.shape[0]} rows x {df.shape[1]} columns")
    print(f"\nLabel distribution:\n{df[config.LABEL_COLUMN].value_counts()}")

    numeric = df.select_dtypes(include=[np.number])
    inf_count = int(np.isinf(numeric).sum().sum())
    nan_count = int(df.isna().sum().sum())
    print(f"\nInfinite values (Flow Bytes/s or Flow Packets/s on near-zero-"
          f"duration flows): {inf_count}")
    print(f"Missing (NaN) values: {nan_count}")
    print("(Both are handled in preprocessing.clean_features: infinities are "
          "treated as missing, then rows with any missing value are dropped.)")
