"""One-off generator for data/low_and_slow_evasion.csv.

This is the Step 4 "Evasion Testing" deliverable: a hand-crafted network log
simulating a low-and-slow DDoS (Slowloris-style) attack, designed to evade a
model trained on this dataset's actual DDoS traffic.

Why this should evade the model: in the real CICIDS2017 Friday-DDoS capture
(see README.md), the DDoS class is a high-bandwidth flood - its flows carry
large backward byte counts and large max packet lengths (median ~11.6 KB
transferred back, max packet length ~5.7 KB) over moderate durations. A
low-and-slow attacker deliberately avoids that exact signature: it opens many
connections and trickles a handful of tiny packets over a very long duration
to exhaust server resources (e.g. connection slots) without ever moving much
data - the opposite footprint the trained model learned to call "threat".
Each simulated flow below has a long duration, only a few packets, and tiny
byte counts, so its Flow Bytes/s and Flow Packets/s land far below anything
the model saw for either class during training.

Run: python scripts/make_evasion_set.py
"""
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src import config

RNG = np.random.default_rng(42)
N_ROWS = 40


def make_rows(n: int) -> pd.DataFrame:
    duration_us = RNG.uniform(60_000_000, 180_000_000, n)          # 60-180 s, held open deliberately
    fwd_packets = RNG.integers(3, 9, n)                              # a handful of keep-alive packets
    bwd_packets = RNG.integers(0, 3, n)                              # server barely responds
    fwd_bytes = RNG.integers(20, 121, n)                             # partial headers, not full requests
    bwd_bytes = RNG.integers(0, 61, n)
    total_packets = fwd_packets + bwd_packets
    total_bytes = fwd_bytes + bwd_bytes
    duration_s = duration_us / 1_000_000

    rows = pd.DataFrame({
        "Source IP": [f"192.168.1.{RNG.integers(10, 60)}" for _ in range(n)],   # simulated compromised IoT devices
        "Source Port": RNG.integers(1024, 65535, n),
        "Destination IP": "192.168.10.50",                                        # simulated web server target
        "Destination Port": 80,
        "Protocol": 6,                                                            # TCP
        "Timestamp": "07/07/2017 04:15",
        "Flow Duration": duration_us.astype(int),
        "Total Fwd Packets": fwd_packets,
        "Total Backward Packets": bwd_packets,
        "Total Length of Fwd Packets": fwd_bytes,
        "Total Length of Bwd Packets": bwd_bytes,
        "Flow Bytes/s": total_bytes / duration_s,
        "Flow Packets/s": total_packets / duration_s,
        "Fwd PSH Flags": RNG.integers(0, 2, n),
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": 0,
        "Bwd URG Flags": 0,
        "Fwd Header Length": fwd_packets * 20,
        "Bwd Header Length": bwd_packets * 20,
        "Fwd Packets/s": fwd_packets / duration_s,
        "Bwd Packets/s": bwd_packets / duration_s,
        "Min Packet Length": RNG.integers(0, 20, n),
        "Max Packet Length": RNG.integers(40, 81, n),
        "FIN Flag Count": 0,
        "SYN Flag Count": 0,
        "RST Flag Count": 0,
        "PSH Flag Count": RNG.integers(0, 2, n),
        "ACK Flag Count": 1,
        "URG Flag Count": 0,
        "CWE Flag Count": 0,
        "ECE Flag Count": 0,
    })
    return rows


if __name__ == "__main__":
    df = make_rows(N_ROWS)
    os.makedirs(config.DATA_DIR, exist_ok=True)
    df.to_csv(config.EVASION_CSV_PATH, index=False)
    print(f"Wrote {len(df)} low-and-slow evasion rows to {config.EVASION_CSV_PATH}")
    print(df[["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
              "Flow Bytes/s", "Flow Packets/s"]].describe())
