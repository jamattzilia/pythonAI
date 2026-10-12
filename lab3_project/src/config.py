"""Paths, schema and tuning constants for the improved IoT botnet detector."""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
RAW_DATA_DIR = os.path.join(DATA_DIR, "raw")
MODELS_DIR = os.path.join(BASE_DIR, "models")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")

# Same real dataset as Lab3 (CICIDS2017 Friday-afternoon DDoS capture) - see
# README.md for why it substitutes for N-BaIoT/Bot-IoT in this environment.
RAW_CSV_URL = (
    "https://raw.githubusercontent.com/StarterArcher/CICIDS2017/master/"
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)
RAW_CSV_PATH = os.path.join(RAW_DATA_DIR, "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

SAMPLE_LOG_PATH = os.path.join(DATA_DIR, "sample_network_log.csv")
# Held-out attack logs - never used for training:
EVASION_V1_PATH = os.path.join(DATA_DIR, "evasion_v1_low_and_slow.csv")       # Lab3's original evasion test
EVASION_V2_PATH = os.path.join(DATA_DIR, "evasion_v2_distributed_slow.csv")   # new attack against this version

MODEL_PATH = os.path.join(MODELS_DIR, "hybrid_detector.pkl")

LABEL_COLUMN = "Label"
TARGET_COLUMN = "is_threat"
BENIGN_LABEL = "BENIGN"

# Used only to group flows into context windows - never as model features,
# so the model can't memorize this capture's specific hosts.
ID_COLUMNS = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Timestamp"]
TIMESTAMP_FORMAT = "%d/%m/%Y %H:%M"

FLOW_FEATURES = [
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Bytes/s",
    "Flow Packets/s", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count",
]

# A connection is "long and quiet" if it stays open > 60 s while moving
# < 10 bytes/s. Calibrated on the real capture: ~850 benign flows match this
# on their own, so the pattern alone is NOT an attack - concentration is.
LONG_FLOW_US = 60_000_000
QUIET_BYTES_PER_S = 10.0

# Time-based evaluation: train on traffic up to this minute, test on later
# traffic (the DDoS runs 03:56-04:16, so both sides contain attack flows).
TIME_SPLIT_AT = "2017-07-07 04:06"

THREAT_THRESHOLD = 0.5
SUSPICIOUS_THRESHOLD = 0.2

RANDOM_STATE = 42
TEST_SIZE = 0.30
N_ESTIMATORS = 200
SPARSE_VIEW_ROWS = 2_000    # training rows re-cut into small pseudo-logs (see train.sparse_views)
