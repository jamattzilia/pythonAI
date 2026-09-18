"""Step 1 — Download and load the AB-TRAP network dataset.

The dataset is not committed to the repository (the raw attack capture is
~20 MB). It is downloaded once from the AB-TRAP GitHub repository and cached
under data/.
"""
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
    """Fetch the raw AB-TRAP CSV files into data/ if not already present."""
    _download(config.ATTACK_DATASET_URL, config.ATTACK_DATASET_PATH)
    _download(config.ATTACK_LABELS_URL, config.ATTACK_LABELS_PATH)
    _download(config.BONAFIDE_DATASET_URL, config.BONAFIDE_DATASET_PATH)


def load_raw_data():
    """Load the three raw CSV files as pandas DataFrames.

    Returns
    -------
    attack_packets : DataFrame
        Raw packets captured while attack tools (nmap, hping3, masscan,
        unicornscan, zmap) were scanning the LAN testbed.
    attack_labels : DataFrame
        Mapping of attacker IP -> attack tool/technique name.
    bonafide_packets : DataFrame
        Raw packets captured on the same network with no attack running.
    """
    download_dataset()
    attack_packets = pd.read_csv(config.ATTACK_DATASET_PATH)
    attack_labels = pd.read_csv(config.ATTACK_LABELS_PATH)
    bonafide_packets = pd.read_csv(config.BONAFIDE_DATASET_PATH)
    return attack_packets, attack_labels, bonafide_packets


def explore(attack_packets, attack_labels, bonafide_packets) -> None:
    """Print a short data-exploration summary (Step 1 of the lab)."""
    print("=" * 70)
    print("STEP 1 - DATA EXPLORATION")
    print("=" * 70)

    print(f"\nAttack capture:   {attack_packets.shape[0]:>7} packets, "
          f"{attack_packets.shape[1]} columns")
    print(f"Bonafide capture: {bonafide_packets.shape[0]:>7} packets, "
          f"{bonafide_packets.shape[1]} columns")

    same_cols = list(attack_packets.columns) == list(bonafide_packets.columns)
    print(f"\nBoth captures share the same columns: {same_cols}")

    print("\nColumns (Wireshark/tshark packet fields):")
    print(list(attack_packets.columns))

    print(f"\nAttack tools/techniques represented ({attack_labels['label'].nunique()} distinct):")
    print(sorted(attack_labels["label"].unique().tolist()))

    total_missing_attack = attack_packets.isna().sum().sum()
    total_missing_bonafide = bonafide_packets.isna().sum().sum()
    print(f"\nMissing values - attack capture: {total_missing_attack}, "
          f"bonafide capture: {total_missing_bonafide}")
    print("(Missing values occur on non-IPv4/non-TCP packets, e.g. IPv6 "
          "frames that don't populate ip.*/tcp.* fields; these are filled "
          "with 0 during preprocessing.)")
