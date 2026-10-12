"""Generate data/evasion_v2_distributed_slow.csv - the attack against THIS version.

The improved detector catches Lab3's v1 low-and-slow attack mainly because
40 slow connections hit ONE server in ONE minute - a concentration benign
traffic never reaches. v2 keeps exactly the same per-connection profile
(60-180 s, a handful of tiny packets) but spreads the same 40 connections
across 4 servers and 10 minutes, so no server ever sees more than 1-2 slow
connections per minute - well inside normal benign levels.

The catch for the attacker: a slow-connection DoS works by holding MANY
connections to one server open at the same time to exhaust its connection
pool. Spread this thin, it no longer does meaningful damage. Forcing the
attacker into a far weaker attack is the defensive win - see README.md.

Run: python scripts/make_evasion_v2.py
"""
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src import config

SERVERS = ["192.168.10.50", "192.168.10.51", "192.168.10.3", "192.168.10.15"]
MINUTES = [f"07/07/2017 04:{m:02d}" for m in range(20, 30)]


def make_rows(seed: int = 2026) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    slots = [(s, m) for s in SERVERS for m in MINUTES]       # 40 (server, minute) slots
    n = len(slots)
    duration_us = rng.uniform(60e6, 180e6, n)
    fwd_pkts = rng.integers(3, 9, n)
    bwd_pkts = rng.integers(0, 3, n)
    fwd_bytes = rng.integers(20, 121, n)
    bwd_bytes = rng.integers(0, 61, n)
    secs = duration_us / 1e6
    return pd.DataFrame({
        "Source IP": [f"172.20.{rng.integers(0, 256)}.{rng.integers(1, 255)}" for _ in range(n)],
        "Source Port": rng.integers(1024, 65535, n),
        "Destination IP": [s for s, _ in slots],
        "Destination Port": 80,
        "Protocol": 6,
        "Timestamp": [m for _, m in slots],
        "Flow Duration": duration_us.astype(int),
        "Total Fwd Packets": fwd_pkts,
        "Total Backward Packets": bwd_pkts,
        "Total Length of Fwd Packets": fwd_bytes,
        "Total Length of Bwd Packets": bwd_bytes,
        "Flow Bytes/s": (fwd_bytes + bwd_bytes) / secs,
        "Flow Packets/s": (fwd_pkts + bwd_pkts) / secs,
        "Fwd PSH Flags": rng.integers(0, 2, n),
        "Bwd PSH Flags": 0, "Fwd URG Flags": 0, "Bwd URG Flags": 0,
        "Fwd Header Length": fwd_pkts * 20,
        "Bwd Header Length": bwd_pkts * 20,
        "Fwd Packets/s": fwd_pkts / secs,
        "Bwd Packets/s": bwd_pkts / secs,
        "Min Packet Length": rng.integers(0, 20, n),
        "Max Packet Length": rng.integers(40, 81, n),
        "FIN Flag Count": 0, "SYN Flag Count": 0, "RST Flag Count": 0,
        "PSH Flag Count": rng.integers(0, 2, n),
        "ACK Flag Count": 1, "URG Flag Count": 0, "CWE Flag Count": 0, "ECE Flag Count": 0,
    })


if __name__ == "__main__":
    df = make_rows()
    df.to_csv(config.EVASION_V2_PATH, index=False)
    per_slot = df.groupby(["Destination IP", "Timestamp"]).size()
    print(f"Wrote {len(df)} flows to {config.EVASION_V2_PATH} "
          f"(max {per_slot.max()} per server per minute)")
