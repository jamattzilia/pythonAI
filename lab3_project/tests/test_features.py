import numpy as np
import pandas as pd

from src import config, features


def make_flows(n, dst="10.0.0.1", ts="07/07/2017 04:00", duration_us=1_000, bytes_s=1_000.0, src_prefix="1.1.1."):
    df = pd.DataFrame({col: 1.0 for col in config.FLOW_FEATURES}, index=range(n))
    df["Flow Duration"] = duration_us
    df["Flow Bytes/s"] = bytes_s
    df["Destination IP"] = dst
    df["Source IP"] = [f"{src_prefix}{i}" for i in range(n)]
    df["Timestamp"] = ts
    return df


def test_long_quiet_flag():
    loud = make_flows(1)
    slow = make_flows(1, duration_us=90_000_000, bytes_s=2.0)
    out = features.build_features(pd.concat([loud, slow], ignore_index=True), training=False)
    assert out["is_long_quiet"].tolist() == [0, 1]


def test_context_counts_are_per_server_and_minute():
    df = pd.concat([
        make_flows(5, dst="A", duration_us=90_000_000, bytes_s=1.0),
        make_flows(3, dst="B"),
        make_flows(2, dst="A", ts="07/07/2017 04:01"),
    ], ignore_index=True)
    out = features.build_features(df, training=False)

    a0 = out[(out["Destination IP"] == "A") & (out["Timestamp"] == "07/07/2017 04:00")]
    assert (a0["dst_long_quiet_in_window"] == 5).all()
    assert (a0["dst_long_quiet_ratio"] == 1.0).all()
    assert (a0["dst_unique_sources_in_window"] == 5).all()
    assert (out.loc[out["Destination IP"] == "B", "dst_long_quiet_in_window"] == 0).all()
    a1 = out[(out["Destination IP"] == "A") & (out["Timestamp"] == "07/07/2017 04:01")]
    assert (a1["dst_long_quiet_in_window"] == 0).all()


def test_missing_ids_and_timestamps_still_score():
    df = make_flows(4).drop(columns=["Timestamp", "Destination IP", "Source IP"])
    out = features.build_features(df, training=False)
    assert len(out) == 4
    assert not out[features.MODEL_FEATURES].isna().any().any()


def test_inference_keeps_bad_rows_training_drops_them():
    df = make_flows(3)
    df.loc[0, "Flow Bytes/s"] = np.inf
    df.loc[1, "Flow Packets/s"] = np.nan
    df = df.drop(columns=["URG Flag Count"])            # missing column at inference

    scored = features.build_features(df, training=False)
    assert len(scored) == 3
    assert np.isfinite(features.feature_matrix(scored).to_numpy()).all()

    train_df = make_flows(3)
    train_df.loc[0, "Flow Bytes/s"] = np.inf
    assert len(features.build_features(train_df, training=True)) == 2


def test_no_ip_or_volume_columns_are_features():
    banned = {"Source IP", "Destination IP", "Timestamp", "dst_flows_in_window", "src_flows_in_window"}
    assert banned.isdisjoint(features.MODEL_FEATURES)


def test_log_id_keeps_pseudo_logs_apart():
    df = make_flows(6, dst="A", duration_us=90_000_000, bytes_s=1.0)
    df = features.add_derived(features.add_window(features.coerce_flow_features(df)))
    out = features.add_context(df.assign(log_id=[0, 0, 0, 1, 1, 1]))
    assert (out["dst_long_quiet_in_window"] == 3).all()
