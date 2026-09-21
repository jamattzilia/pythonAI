"""Paths, dataset source and constants for the IoT Botnet Traffic Classifier."""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
RAW_DATA_DIR = os.path.join(DATA_DIR, "raw")
MODELS_DIR = os.path.join(BASE_DIR, "models")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")

# Dataset: CICIDS2017 "Friday-WorkingHours-Afternoon-DDos" capture (Canadian
# Institute for Cybersecurity), a public mirror on GitHub. It contains real,
# labeled network FLOW records (not raw packets) - each row already
# summarizes one connection's duration, packet counts, byte counts and TCP
# flags, i.e. exactly the "network flow statistics (packet size, flow
# duration, byte counts)" feature family this project's topic calls for.
#
# Note on scope: the assignment's example datasets for this topic (N-BaIoT /
# Bot-IoT, normally obtained from UCI or Kaggle) are not reachable from this
# sandboxed environment (outbound access is restricted to a small allowlist
# that does not include archive.ics.uci.edu or kaggle.com). CICIDS2017's DDoS
# capture is the closest fully-public, GitHub-hosted substitute with the same
# flow-statistics feature family and the same underlying task (binary
# DDoS/botnet-vs-benign flow classification) - see README.md for the full
# rationale and for how to swap in real N-BaIoT/Bot-IoT data instead.
RAW_CSV_URL = (
    "https://raw.githubusercontent.com/StarterArcher/CICIDS2017/master/"
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)
RAW_CSV_PATH = os.path.join(RAW_DATA_DIR, "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

# Small, hand-crafted "low-and-slow" DDoS log used for the assignment's
# required Step 4 evasion test. It is committed to the repo (it is our own
# authored test case, not raw dataset content) - see make_evasion_set.py.
EVASION_CSV_PATH = os.path.join(DATA_DIR, "low_and_slow_evasion.csv")

MODEL_PATH = os.path.join(MODELS_DIR, "iot_botnet_model.pkl")

# Columns dropped before modelling: identifiers/metadata that would let the
# model key off this one capture's specific hosts/ports/time window instead
# of learning general flow behavior (see preprocessing.py for the rationale).
DROP_COLUMNS = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Timestamp"]
LABEL_COLUMN = "Label"
TARGET_COLUMN = "is_threat"

RANDOM_STATE = 42
TEST_SIZE = 0.30
