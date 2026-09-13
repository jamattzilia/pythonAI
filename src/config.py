"""Paths and constants for the network anomaly detection project."""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")

# Source dataset: AB-TRAP (https://github.com/c2dc/AB-TRAP)
# Local Area Network testbed captures TCP port-scanning attacks (nmap, hping3,
# masscan, unicornscan, zmap) against several targets, plus a separate capture
# of genuine ("bonafide") background LAN/Internet traffic recorded on the same
# network with no attacks running.
RAW_BASE_URL = "https://raw.githubusercontent.com/c2dc/AB-TRAP/main"

ATTACK_DATASET_URL = f"{RAW_BASE_URL}/1_Attack%20dataset/Local%20Area%20Network/data/attack_dataset.csv"
ATTACK_LABELS_URL = f"{RAW_BASE_URL}/1_Attack%20dataset/Local%20Area%20Network/data/attack_labels_sbseg.csv"
BONAFIDE_DATASET_URL = f"{RAW_BASE_URL}/2_Bonafide%20dataset/data/bonafide_dataset_20191121.csv.gz"

ATTACK_DATASET_PATH = os.path.join(DATA_DIR, "attack_dataset.csv")
ATTACK_LABELS_PATH = os.path.join(DATA_DIR, "attack_labels.csv")
BONAFIDE_DATASET_PATH = os.path.join(DATA_DIR, "bonafide_dataset.csv.gz")

RANDOM_STATE = 42
TEST_SIZE = 0.30  # fraction of the BENIGN packets held out for testing
