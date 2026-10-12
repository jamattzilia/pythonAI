import numpy as np
import pandas as pd

from src import detector


def test_rule_threshold_is_one_above_benign_max():
    benign = pd.DataFrame({
        "is_long_quiet":            [1, 1, 0, 1],
        "dst_long_quiet_in_window": [3, 7, 50, 7],   # 50 ignored: that flow isn't long-quiet
    })
    assert detector.calibrate_rule_threshold(benign) == 8


def test_rule_threshold_with_no_long_quiet_benign():
    benign = pd.DataFrame({"is_long_quiet": [0, 0], "dst_long_quiet_in_window": [0, 0]})
    assert detector.calibrate_rule_threshold(benign) == 1


def test_rule_needs_both_slow_flow_and_concentration():
    feats = pd.DataFrame({
        "is_long_quiet":            [1, 1, 0],
        "dst_long_quiet_in_window": [30, 5, 30],
    })
    assert detector.rule_hits(feats, threshold=23).tolist() == [True, False, False]


def test_verdict_tiers():
    proba = np.array([0.9, 0.3, 0.05, 0.05, 0.2, 0.5])
    rule = np.array([False, False, False, True, False, False])
    assert detector.assign_verdicts(proba, rule).tolist() == [
        "Threat", "Suspicious", "Safe", "Threat", "Suspicious", "Threat",
    ]


def test_explain_mentions_rule_and_score():
    rule_row = {"rule_hit": True, "dst_long_quiet_in_window": 40, "threat_probability": 0.1}
    assert "40" in detector.explain(rule_row, 23) and "22" in detector.explain(rule_row, 23)
    assert "p=0.30" in detector.explain({"rule_hit": False, "threat_probability": 0.3}, 23)
    assert detector.explain({"rule_hit": False, "threat_probability": 0.01}, 23) == ""
