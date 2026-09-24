"""One-off generator for data/sample_network_log.csv.

A small (60-row, ~10 KB), realistic network log for demoing/testing the
Streamlit dashboard without uploading the full ~34 MB raw dataset - useful
because some hosting setups (reverse proxies, PaaS routers) reject large
uploads with an HTTP 413 before the app's own code ever runs, and there is
no reason a demo upload needs to be that big anyway. Sampled directly from
the real CICIDS2017 capture (30 real BENIGN + 30 real DDoS flows, shuffled),
so it is genuine traffic, not synthetic.

Run: python scripts/make_sample_log.py
"""
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src import config, data_loader

N_PER_CLASS = 30
SEED = 7


if __name__ == "__main__":
    df = data_loader.load_raw_data()
    sample = pd.concat([
        df[df[config.LABEL_COLUMN] == "BENIGN"].sample(N_PER_CLASS, random_state=SEED),
        df[df[config.LABEL_COLUMN] == "DDoS"].sample(N_PER_CLASS, random_state=SEED),
    ]).drop(columns=[config.LABEL_COLUMN]).sample(frac=1, random_state=SEED).reset_index(drop=True)

    os.makedirs(config.DATA_DIR, exist_ok=True)
    sample.to_csv(config.SAMPLE_LOG_PATH, index=False)
    print(f"Wrote {len(sample)} sample flows ({N_PER_CLASS} benign + {N_PER_CLASS} DDoS) "
          f"to {config.SAMPLE_LOG_PATH}")
