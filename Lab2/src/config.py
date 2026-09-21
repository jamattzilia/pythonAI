"""Paths, column names and constants for the NSL-KDD NIDS project."""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")

# NSL-KDD (github.com/jmnwong/NSL-KDD-Dataset) — a well-known mirror of the
# canonical KDDTrain+.txt / KDDTest+.txt files used as the standard NIDS
# benchmark. Files are plain CSV with no header row.
RAW_BASE_URL = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master"
TRAIN_URL = f"{RAW_BASE_URL}/KDDTrain%2B.txt"
TEST_URL = f"{RAW_BASE_URL}/KDDTest%2B.txt"

TRAIN_PATH = os.path.join(DATA_DIR, "KDDTrain+.txt")
TEST_PATH = os.path.join(DATA_DIR, "KDDTest+.txt")

# Column names as specified by the lab (41 features + label + difficulty).
COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "attack_type", "difficulty_level",
]

CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]
TARGET_COLUMN = "attack_type"
LABEL_COLUMN = "label"

RANDOM_STATE = 42
TOP_N_FEATURES = 10

# Random Forest's predict_proba() threshold for calling a packet an attack.
# Lowered from the default 0.5 to minimize false negatives - see
# model.predict() and README.md for the sweep that justifies this value.
DECISION_THRESHOLD = 0.015
