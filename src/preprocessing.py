"""Step 2 — Prepare the AB-TRAP packet captures for Machine Learning.

Feature-selection rationale (adapted from the AB-TRAP project itself, see
c2dc/AB-TRAP "3_Training models" notebooks):

- Link-layer / capture bookkeeping fields are dropped (frame_info.*, eth.type):
  they describe the capture, not the traffic.
- ip.src / ip.dst / ip.version / ip.proto / ip.flags / tcp.flags are dropped
  so the model learns *behavioural* packet shape rather than memorising
  specific hosts (which would not generalise to new attackers/targets).
- Columns that are constant (zero variance) in this capture are dropped
  because they carry no information: ip.hdr_len, ip.tos, ip.flags.rb,
  ip.flags.mf, ip.frag_offset.
- ip.ttl, tcp.srcport/dstport, tcp.seq/ack and checksums are dropped so the
  model is agnostic to which service/port was targeted and does not key off
  values that are effectively random per-connection.

What remains is a compact behavioural fingerprint of each packet: total
length, header length, the individual TCP flag bits, window size, urgent
pointer, IP id and DSCP field. Port-scanning tools each set very
characteristic, unusual combinations of these (e.g. a NULL scan sends no
flags at all, a XMAS scan sets FIN+PSH+URG, SYN scans only set SYN), which is
exactly what makes them stand out as anomalies against normal traffic.
"""
from typing import Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from . import config

_DROP_LINK_LAYER = [
    "frame_info.time", "frame_info.encap_type", "frame_info.time_epoch",
    "frame_info.number", "frame_info.len", "frame_info.cap_len", "eth.type",
]
_DROP_HOST_IDENTIFYING = [
    "ip.flags", "ip.src", "ip.dst", "ip.version", "ip.proto", "tcp.flags",
]
_DROP_ZERO_VARIANCE = [
    "ip.hdr_len", "ip.tos", "ip.flags.rb", "ip.flags.mf", "ip.frag_offset",
]
_DROP_PORT_AND_RANDOM = [
    "ip.checksum", "ip.ttl", "tcp.checksum", "tcp.dstport", "tcp.srcport",
    "tcp.seq", "tcp.ack", "tcp.options.mss_val",
]

DROP_COLUMNS = (
    _DROP_LINK_LAYER + _DROP_HOST_IDENTIFYING + _DROP_ZERO_VARIANCE + _DROP_PORT_AND_RANDOM
)

# Packet fields that arrive as hexadecimal strings (e.g. "0x0000b2c5") and
# must be converted to integers before they can be used as ML features.
HEX_COLUMNS = ["ip.id", "ip.dsfield"]

LABEL_COLUMN = "label"


def _hex_to_int(series: pd.Series) -> pd.Series:
    return series.apply(lambda v: int(v, 16) if isinstance(v, str) else v)


def build_labeled_dataset(attack_packets: pd.DataFrame,
                           attack_labels: pd.DataFrame,
                           bonafide_packets: pd.DataFrame) -> pd.DataFrame:
    """Merge captures into one DataFrame with a binary target column.

    label = 1 -> packet belongs to a port-scanning attack
    label = 0 -> packet is genuine ("bonafide") background traffic

    The attack-tool name (e.g. "nmap_tcp_syn") is kept in a separate
    ``attack_type`` column for the results-analysis step, but it is never
    used as a model feature.
    """
    attack = attack_packets.merge(attack_labels, how="inner",
                                   left_on="ip.src", right_on="ip")
    attack = attack.drop(columns=["ip"])
    attack = attack.rename(columns={LABEL_COLUMN: "attack_type"})
    attack[LABEL_COLUMN] = 1

    benign = bonafide_packets.copy()
    benign["attack_type"] = "benign"
    benign[LABEL_COLUMN] = 0

    combined = pd.concat([attack, benign], ignore_index=True, sort=False)
    return combined


def preprocess_features(df: pd.DataFrame) -> pd.DataFrame:
    """Apply hex decoding, drop non-informative columns and fill NaNs."""
    df = df.copy()
    for col in HEX_COLUMNS:
        df[col] = _hex_to_int(df[col])

    feature_df = df.drop(columns=[c for c in DROP_COLUMNS if c in df.columns])
    feature_df = feature_df.fillna(0)

    numeric_cols = [c for c in feature_df.columns
                    if c not in (LABEL_COLUMN, "attack_type")]
    feature_df[numeric_cols] = feature_df[numeric_cols].astype(np.int64)
    return feature_df


def split_for_anomaly_detection(feature_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame,
                                                                     pd.Series, pd.Series,
                                                                     pd.Series, pd.Series]:
    """Split into train/test sets the way one-class anomaly detection expects.

    Isolation Forest is trained ONLY on normal ("benign") traffic, so it
    learns what normal looks like. The held-out benign packets plus every
    attack packet then form the test set the model has never seen -
    satisfying the lab's requirement that testing data must not be used to
    train the model, while still giving a realistic anomaly-detection setup
    (in production you rarely have pre-labelled attack traffic to train on).

    Returns X_train, X_test, y_train, y_test, attack_type_train, attack_type_test
    (attack_type_* are kept only for the results-analysis step).
    """
    feature_cols = [c for c in feature_df.columns
                    if c not in (LABEL_COLUMN, "attack_type")]

    benign_df = feature_df[feature_df[LABEL_COLUMN] == 0]
    attack_df = feature_df[feature_df[LABEL_COLUMN] == 1]

    benign_train, benign_test = train_test_split(
        benign_df, test_size=config.TEST_SIZE, random_state=config.RANDOM_STATE)

    test_df = pd.concat([benign_test, attack_df], ignore_index=True)
    test_df = test_df.sample(frac=1, random_state=config.RANDOM_STATE).reset_index(drop=True)

    X_train = benign_train[feature_cols]
    y_train = benign_train[LABEL_COLUMN]
    X_test = test_df[feature_cols]
    y_test = test_df[LABEL_COLUMN]

    return X_train, X_test, y_train, y_test, benign_train["attack_type"], test_df["attack_type"]
