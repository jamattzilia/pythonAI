"""Hybrid detector: Random Forest score + a calibrated slow-connection rule.

Verdicts (most severe wins):
  Threat     - the rule fired, or model probability >= THREAT_THRESHOLD
  Suspicious - model probability in [SUSPICIOUS_THRESHOLD, THREAT_THRESHOLD)
  Safe       - otherwise
Every flow carries a human-readable reason, so an analyst can see *why*.
"""
import numpy as np
import pandas as pd

from . import config, features


def calibrate_rule_threshold(benign_feats: pd.DataFrame) -> int:
    """Smallest per-(server, minute) long-quiet count never reached by benign
    training traffic - zero rule false positives on training data by design."""
    per_window = benign_feats.loc[benign_feats["is_long_quiet"] == 1, "dst_long_quiet_in_window"]
    return int(per_window.max() if len(per_window) else 0) + 1


def rule_hits(feats: pd.DataFrame, threshold: int) -> pd.Series:
    """Slowloris guard: a long, near-idle connection to a server that has an
    abnormal number of such connections open in the same minute."""
    return (feats["is_long_quiet"] == 1) & (feats["dst_long_quiet_in_window"] >= threshold)


def assign_verdicts(proba: np.ndarray, rule: np.ndarray) -> np.ndarray:
    return np.select(
        [rule, proba >= config.THREAT_THRESHOLD, proba >= config.SUSPICIOUS_THRESHOLD],
        ["Threat", "Threat", "Suspicious"],
        default="Safe",
    )


def explain(row, rule_threshold: int) -> str:
    if row["rule_hit"]:
        return (f"Slow-connection flood: {int(row['dst_long_quiet_in_window'])} long, near-idle "
                f"connections to this server in one minute (benign max: {rule_threshold - 1})")
    p = row["threat_probability"]
    if p >= config.THREAT_THRESHOLD:
        return f"Flow statistics match DDoS traffic (p={p:.2f})"
    if p >= config.SUSPICIOUS_THRESHOLD:
        return f"Borderline model score (p={p:.2f}) - worth a look"
    return ""


class HybridDetector:
    def __init__(self, bundle: dict):
        self.model = bundle["model"]
        self.feature_names = bundle["feature_names"]
        self.rule_threshold = bundle["rule_threshold"]
        self.bundle = bundle

    def score(self, raw_df: pd.DataFrame) -> pd.DataFrame:
        feats = features.build_features(raw_df, training=False)
        proba = self.model.predict_proba(features.feature_matrix(feats, self.feature_names))[:, 1]
        out = feats.copy()
        out["threat_probability"] = proba.round(4)
        out["rule_hit"] = rule_hits(feats, self.rule_threshold).to_numpy()
        out["verdict"] = assign_verdicts(proba, out["rule_hit"].to_numpy())
        out["reason"] = out.apply(explain, axis=1, rule_threshold=self.rule_threshold)
        return out


def server_summary(scored: pd.DataFrame) -> pd.DataFrame:
    """One row per destination server: how hard it's being hit, and how."""
    dst = scored["Destination IP"] if "Destination IP" in scored.columns else pd.Series("?", index=scored.index)
    g = scored.assign(_dst=dst.astype(str)).groupby("_dst")
    summary = pd.DataFrame({
        "flows": g.size(),
        "threat_flows": g["verdict"].apply(lambda v: int((v == "Threat").sum())),
        "suspicious_flows": g["verdict"].apply(lambda v: int((v == "Suspicious").sum())),
        "long_quiet_conns": g["is_long_quiet"].sum().astype(int),
        "slow_flood_rule": g["rule_hit"].any(),
        "max_threat_probability": g["threat_probability"].max(),
    })
    summary.index.name = "Destination IP"
    return summary.sort_values(["threat_flows", "suspicious_flows", "flows"], ascending=False)
