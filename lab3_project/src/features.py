"""Feature engineering shared by training and the dashboard.

Lab3 scored each flow in isolation, which is exactly why a low-and-slow
attack beat it: one slow connection really does look like idle benign
traffic. This module adds *context* features - what else was happening to
the same server, and from the same source, in the same one-minute window -
so the model can see coordination that no single flow reveals.
"""
from typing import List

import numpy as np
import pandas as pd

from . import config

DERIVED_FEATURES = ["duration_s", "bytes_per_packet", "is_long_quiet"]

# Raw volume counters (flows per server/client per minute, distinct ports per
# client) are deliberately NOT features: in a time-based evaluation the model
# latched onto "attacker sends >= ~2,000 flows/minute" and missed every attack
# flow in the minute the DDoS wound down (1,348 misses vs 79 for Lab3's
# model). Shape features below don't encode how loud the attack is.
CONTEXT_FEATURES = [
    "dst_unique_sources_in_window", # distinct clients hitting this server this minute
    "dst_long_quiet_in_window",     # long, near-idle connections held open to this server
    "dst_long_quiet_ratio",         # ...as a share of all its flows
    "dst_median_duration_s",        # typical connection length to this server
]

MODEL_FEATURES = config.FLOW_FEATURES + DERIVED_FEATURES + CONTEXT_FEATURES


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    return df


def clean_training_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Training: CICFlowMeter writes inf rates for ~0-duration flows; treat as
    missing and drop those rows (4 of 225,745)."""
    df = normalize_columns(df).replace([np.inf, -np.inf], np.nan)
    return df.dropna(subset=config.FLOW_FEATURES).reset_index(drop=True)


def coerce_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    """Inference: every uploaded row must get a verdict, so nothing is
    dropped - missing columns become 0, infinities are clipped."""
    df = normalize_columns(df)
    for col in config.FLOW_FEATURES:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df[config.FLOW_FEATURES] = (
        df[config.FLOW_FEATURES].replace([np.inf, -np.inf], np.finfo(np.float64).max).fillna(0)
    )
    return df


def add_window(df: pd.DataFrame) -> pd.DataFrame:
    """One-minute window per flow. Logs without (parseable) timestamps are
    treated as a single window, so context still means "within this upload"."""
    df = df.copy()
    if "Timestamp" in df.columns:
        ts = pd.to_datetime(df["Timestamp"], format=config.TIMESTAMP_FORMAT, errors="coerce")
        df["window"] = ts.dt.floor("min").fillna(pd.Timestamp(0))
    else:
        df["window"] = pd.Timestamp(0)
    return df


def add_derived(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    packets = df["Total Fwd Packets"] + df["Total Backward Packets"]
    total_bytes = df["Total Length of Fwd Packets"] + df["Total Length of Bwd Packets"]
    df["duration_s"] = df["Flow Duration"] / 1_000_000
    df["bytes_per_packet"] = np.where(packets > 0, total_bytes / packets.clip(lower=1), 0.0)
    df["is_long_quiet"] = (
        (df["Flow Duration"] > config.LONG_FLOW_US) & (df["Flow Bytes/s"] < config.QUIET_BYTES_PER_S)
    ).astype(int)
    return df


def add_context(df: pd.DataFrame) -> pd.DataFrame:
    """Per-(server, minute) aggregates. IPs are used only as grouping keys,
    never as features. An optional `log_id` column keeps separate logs apart
    (used in training to simulate small, sampled uploads)."""
    df = df.copy()
    dst = df["Destination IP"].astype(str) if "Destination IP" in df.columns else pd.Series("?", index=df.index)
    src = df["Source IP"].astype(str) if "Source IP" in df.columns else pd.Series("?", index=df.index)

    keys = ["_dst", "window"] + (["log_id"] if "log_id" in df.columns else [])
    by_dst = df.assign(_dst=dst, _src=src).groupby(keys)
    dst_flows = by_dst["Flow Duration"].transform("size")
    df["dst_unique_sources_in_window"] = by_dst["_src"].transform("nunique")
    df["dst_long_quiet_in_window"] = by_dst["is_long_quiet"].transform("sum")
    df["dst_long_quiet_ratio"] = df["dst_long_quiet_in_window"] / dst_flows
    df["dst_median_duration_s"] = by_dst["duration_s"].transform("median")
    return df


def build_features(df: pd.DataFrame, training: bool) -> pd.DataFrame:
    """Full pipeline. Returns the input rows plus all MODEL_FEATURES columns
    (identifier/label columns are kept for grouping, splitting and display)."""
    df = clean_training_rows(df) if training else coerce_flow_features(df)
    return add_context(add_derived(add_window(df)))


def feature_matrix(df: pd.DataFrame, features: List[str] = MODEL_FEATURES) -> pd.DataFrame:
    return df[features].astype(float)
