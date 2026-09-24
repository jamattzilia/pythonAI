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
exactly the signal a supervised classifier learns to key off (see model.py).
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


def split_train_test(feature_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame,
                                                          pd.Series, pd.Series,
                                                          pd.Series, pd.Series]:
    """Stratified 70/30 train/test split for supervised training.

    Both benign AND attack packets are used to train the model (this is a
    supervised classifier, not a one-class anomaly detector) - but training
    and testing data are still strictly disjoint, split with
    ``train_test_split``. Stratifying on ``label`` keeps the benign/attack
    ratio (and therefore every attack technique's minimum representation)
    consistent between the two splits, which matters here because several
    attack techniques (e.g. masscan_tcp_syn) have only ~1,000 packets total.

    Returns X_train, X_test, y_train, y_test, attack_type_train, attack_type_test
    (attack_type_* are kept only for the results-analysis step, never used
    as a model feature).
    """
    feature_cols = [c for c in feature_df.columns
                    if c not in (LABEL_COLUMN, "attack_type")]
    X = feature_df[feature_cols]
    y = feature_df[LABEL_COLUMN]
    attack_type = feature_df["attack_type"]

    X_train, X_test, y_train, y_test, at_train, at_test = train_test_split(
        X, y, attack_type, test_size=config.TEST_SIZE,
        random_state=config.RANDOM_STATE, stratify=y)

    return X_train, X_test, y_train, y_test, at_train, at_test
