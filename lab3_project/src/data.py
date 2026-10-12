"""Download (once) and load the raw CICIDS2017 Friday-DDoS flow capture."""
import os

import pandas as pd
import requests

from . import config


def load_raw() -> pd.DataFrame:
    if not os.path.exists(config.RAW_CSV_PATH):
        os.makedirs(config.RAW_DATA_DIR, exist_ok=True)
        print(f"Downloading {config.RAW_CSV_URL}")
        response = requests.get(config.RAW_CSV_URL, timeout=120)
        response.raise_for_status()
        with open(config.RAW_CSV_PATH, "wb") as f:
            f.write(response.content)
    df = pd.read_csv(config.RAW_CSV_PATH)
    df.columns = [c.strip() for c in df.columns]
    return df
