"""Synthetic slow-connection attacks injected into TRAINING data only.

The real capture contains only volumetric DDoS, so Lab3's model had never
seen a single low-and-slow example. These synthetic bursts give it one -
but with deliberately different parameters from the held-out evasion test
(data/evasion_v1_low_and_slow.csv) so that test still measures
generalization, not memorization:

                    training bursts (here)        held-out v1 test
  duration          35-110 s                      60-180 s
  packets fwd/bwd   2-6 / 0-1                     3-8 / 0-2
  attacked server   192.168.10.3 / .15 / .9       192.168.10.50
  attacker IPs      10.0.x.x                      192.168.1.x
  conns per minute  20-35                         40

Synthetic rows are labelled "SlowDoS" and never enter any test set.
"""
import numpy as np
import pandas as pd

SYNTHETIC_LABEL = "SlowDoS"
TARGET_SERVERS = ["192.168.10.3", "192.168.10.15", "192.168.10.9"]


def make_slow_attack_bursts(windows, n_bursts: int = 14, seed: int = 1234) -> pd.DataFrame:
    """Return raw-schema rows (same columns as the CICIDS CSV, incl. Label)
    for `n_bursts` slow-connection floods, each aimed at one server within
    one of the given one-minute `windows` (pd.Timestamps)."""
    rng = np.random.default_rng(seed)
    windows = list(windows)
    bursts = []
    for _ in range(n_bursts):
        n = int(rng.integers(20, 36))
        window = windows[int(rng.integers(0, len(windows)))]
        server = TARGET_SERVERS[int(rng.integers(0, len(TARGET_SERVERS)))]

        duration_us = rng.uniform(35e6, 110e6, n)
        fwd_pkts = rng.integers(2, 7, n)
        bwd_pkts = rng.integers(0, 2, n)
        fwd_bytes = rng.integers(10, 91, n)
        bwd_bytes = bwd_pkts * rng.integers(0, 40, n)
        secs = duration_us / 1e6

        bursts.append(pd.DataFrame({
            "Source IP": [f"10.0.{rng.integers(0, 256)}.{rng.integers(1, 255)}" for _ in range(n)],
            "Source Port": rng.integers(1024, 65535, n),
            "Destination IP": server,
            "Destination Port": 80,
            "Protocol": 6,
            "Timestamp": window.strftime("%d/%m/%Y %H:%M"),
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
            "Min Packet Length": rng.integers(0, 10, n),
            "Max Packet Length": rng.integers(20, 61, n),
            "FIN Flag Count": 0, "SYN Flag Count": 0, "RST Flag Count": 0,
            "PSH Flag Count": rng.integers(0, 2, n),
            "ACK Flag Count": 1, "URG Flag Count": 0, "CWE Flag Count": 0, "ECE Flag Count": 0,
            "Label": SYNTHETIC_LABEL,
        }))
    return pd.concat(bursts, ignore_index=True)
