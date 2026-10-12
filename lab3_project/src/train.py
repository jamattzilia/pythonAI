"""Train the improved detector and compare it against Lab3's original model.

Both are evaluated under identical conditions:
  1. random stratified 70/30 split  (Lab3's original protocol)
  2. time-based split at 04:06      (train on the past, test on the future -
                                     closer to deployment, harder to inflate)
  3. two held-out attack logs never used in training:
       v1 - Lab3's low-and-slow evasion log (40 slow conns, 1 server, 1 minute)
       v2 - the same slow connections spread across 4 servers x 10 minutes

  baseline = Lab3: Random Forest on the 26 per-flow features, no augmentation
  improved = Random Forest on per-flow + derived + context features, trained
             with synthetic slow-attack bursts, plus the calibrated rule layer

Run: python -m src.train
"""
import json
import os
import platform

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
from matplotlib.colors import LinearSegmentedColormap
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from . import augment, config, data, detector, features

# Reference palette (validated: lightness, chroma, CVD and contrast all pass).
BASELINE_COLOR, IMPROVED_COLOR = "#2a78d6", "#eb6834"
SURFACE, INK, INK_2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e4e3dd"
SEQ_BLUE = LinearSegmentedColormap.from_list("seq_blue", ["#cde2fb", "#6da7ec", "#2a78d6", "#1c5cab", "#104281"])


# ------------------------------------------------------------------ data ---
def prepare_dataset() -> pd.DataFrame:
    raw = data.load_raw()
    ts = pd.to_datetime(raw["Timestamp"], format=config.TIMESTAMP_FORMAT)
    split_at = pd.Timestamp(config.TIME_SPLIT_AT)
    # Synthetic bursts go only into training-period minutes, so the time-split
    # test period stays 100% real traffic.
    train_minutes = sorted(ts[ts <= split_at].dt.floor("min").unique())
    synth = augment.make_slow_attack_bursts(train_minutes)
    combined = pd.concat(
        [raw.assign(is_synthetic=False), synth.assign(is_synthetic=True)], ignore_index=True
    )
    feats = features.build_features(combined, training=True)
    feats[config.TARGET_COLUMN] = (feats[config.LABEL_COLUMN] != config.BENIGN_LABEL).astype(int)
    print(f"Dataset: {(~feats.is_synthetic).sum():,} real flows + {feats.is_synthetic.sum():,} "
          f"synthetic slow-attack flows (training only)")
    return feats


def splits(feats: pd.DataFrame) -> dict:
    real, synth = feats[~feats.is_synthetic], feats[feats.is_synthetic]
    tr_idx, te_idx = train_test_split(
        real.index, test_size=config.TEST_SIZE, random_state=config.RANDOM_STATE,
        stratify=real[config.TARGET_COLUMN],
    )
    early = real["window"] <= pd.Timestamp(config.TIME_SPLIT_AT)
    return {
        "random": (real.loc[tr_idx], real.loc[te_idx], synth),
        "time": (real[early], real[~early], synth),
    }


# ---------------------------------------------------------------- models ---
def fit_rf(X, y) -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=config.N_ESTIMATORS, random_state=config.RANDOM_STATE, n_jobs=-1)
    return model.fit(X, y)


def binary_metrics(y_true, y_pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1_score": f1_score(y_true, y_pred, zero_division=0),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def sparse_views(rows: pd.DataFrame, n_rows: int, seed: int) -> pd.DataFrame:
    """Re-cut rows into small pseudo-logs (30-600 random flows each) and
    recompute the context features inside each one.

    Context features assume the log is a complete capture. A user who uploads
    a 60-row sample sees ~1 flow per server per minute, so without this the
    model met context values it never saw in training and downgraded real DDoS
    flows to Suspicious/Safe (0/30 Threat on the demo sample log)."""
    rng = np.random.default_rng(seed)
    sample = rows.sample(n=min(n_rows, len(rows)), random_state=seed)
    sizes = rng.integers(30, 601, size=len(sample) // 30 + 1)
    log_id = np.repeat(np.arange(len(sizes)), sizes)[: len(sample)]
    return features.add_context(sample.assign(log_id=log_id)).drop(columns="log_id")


def train_pair(train_real, synth):
    """Baseline (Lab3 recipe) and improved model on the same real training rows."""
    y_real = train_real[config.TARGET_COLUMN]
    baseline = fit_rf(train_real[config.FLOW_FEATURES], y_real)

    sparse = sparse_views(train_real, config.SPARSE_VIEW_ROWS, config.RANDOM_STATE)
    improved_train = pd.concat([train_real, synth, sparse])
    improved = fit_rf(features.feature_matrix(improved_train), improved_train[config.TARGET_COLUMN])
    rule_threshold = detector.calibrate_rule_threshold(
        train_real[train_real[config.TARGET_COLUMN] == 0])
    return baseline, improved, rule_threshold


def evaluate_split(baseline, improved, rule_threshold, test) -> dict:
    y = test[config.TARGET_COLUMN]
    base_pred = baseline.predict(test[config.FLOW_FEATURES])
    proba = improved.predict_proba(features.feature_matrix(test))[:, 1]
    hybrid = detector.assign_verdicts(proba, detector.rule_hits(test, rule_threshold).to_numpy())
    result = {
        "baseline": binary_metrics(y, base_pred),
        "improved": binary_metrics(y, (hybrid == "Threat").astype(int)),
        "improved_suspicious_flows": int((hybrid == "Suspicious").sum()),
    }
    # Same test flows, but seen as small sampled uploads (context recomputed
    # per pseudo-log). Different seed from the training views.
    sampled = sparse_views(test, len(test), seed=config.RANDOM_STATE + 1)
    s_proba = improved.predict_proba(features.feature_matrix(sampled))[:, 1]
    s_hybrid = detector.assign_verdicts(s_proba, detector.rule_hits(sampled, rule_threshold).to_numpy())
    result["improved_sampled_logs"] = binary_metrics(
        sampled[config.TARGET_COLUMN], (s_hybrid == "Threat").astype(int))
    return result


def evaluate_attack_log(path, baseline, hybrid: detector.HybridDetector) -> dict:
    raw = pd.read_csv(path)
    base_X = features.coerce_flow_features(raw)[config.FLOW_FEATURES]
    base_detected = int((baseline.predict_proba(base_X)[:, 1] >= config.THREAT_THRESHOLD).sum())
    scored = hybrid.score(raw)
    return {
        "flows": len(raw),
        "baseline_detected": base_detected,
        "improved_threat": int((scored.verdict == "Threat").sum()),
        "improved_suspicious": int((scored.verdict == "Suspicious").sum()),
        "improved_rule_hits": int(scored.rule_hit.sum()),
        "improved_max_probability": float(scored.threat_probability.max()),
    }


# ----------------------------------------------------------------- plots ---
def _style(ax):
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(MUTED)
    ax.tick_params(colors=INK_2, labelsize=9)
    ax.set_axisbelow(True)


def plot_comparison(results: dict, path: str) -> None:
    labels = ["Random-split\nF1", "Time-split\nF1", "v1 slow attack\n(held out)", "v2 distributed\nslow attack"]
    v1, v2 = results["evasion_v1"], results["evasion_v2"]
    base = [results["random"]["baseline"]["f1_score"], results["time"]["baseline"]["f1_score"],
            v1["baseline_detected"] / v1["flows"], v2["baseline_detected"] / v2["flows"]]
    imp = [results["random"]["improved"]["f1_score"], results["time"]["improved"]["f1_score"],
           v1["improved_threat"] / v1["flows"], v2["improved_threat"] / v2["flows"]]

    fig, ax = plt.subplots(figsize=(9, 4.6), facecolor=SURFACE)
    x, w = np.arange(len(labels)), 0.36
    for offset, vals, color, name in [(-w / 2, base, BASELINE_COLOR, "Lab3 baseline"),
                                      (w / 2, imp, IMPROVED_COLOR, "Improved (lab3_project)")]:
        bars = ax.bar(x + offset, vals, w - 0.02, color=color, label=name, edgecolor=SURFACE, linewidth=2)
        for i, (b, v) in enumerate(zip(bars, vals)):
            text = f"{v:.3f}" if i < 2 else f"{v:.0%}"
            if i == 3 and color == IMPROVED_COLOR and v2["improved_suspicious"]:
                text += f"\n(+{v2['improved_suspicious'] / v2['flows']:.0%} Suspicious)"
            ax.text(b.get_x() + b.get_width() / 2, v + 0.02, text,
                    ha="center", va="bottom", fontsize=8.5, color=INK_2)
    ax.set_xticks(x, labels)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Score / share of attack flows flagged as Threat", color=INK_2, fontsize=9)
    ax.set_title("Lab3 baseline vs. improved detector", color=INK, fontsize=12, loc="left")
    ax.legend(frameon=False, fontsize=9, loc="upper right", labelcolor=INK_2)
    _style(ax)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.grid(axis="x", visible=False)
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)


def plot_confusion(results: dict, path: str) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.9), facecolor=SURFACE)
    for ax, split in zip(axes, ["random", "time"]):
        m = results[split]["improved"]
        cm = np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]])
        ax.imshow(cm, cmap=SEQ_BLUE)
        for i in range(2):
            for j in range(2):
                dark_cell = cm[i, j] > cm.max() * 0.55
                ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", fontsize=11,
                        color=SURFACE if dark_cell else INK)
        ax.set_xticks([0, 1], ["Safe", "Threat"])
        ax.set_yticks([0, 1], ["Safe", "Threat"])
        ax.set_xlabel("Predicted", color=INK_2, fontsize=9)
        ax.set_ylabel("Actual", color=INK_2, fontsize=9)
        title = "Random split" if split == "random" else "Time split (train <= 04:06)"
        ax.set_title(title, color=INK, fontsize=10, loc="left")
        ax.tick_params(colors=INK_2, labelsize=9, length=0)
        for s in ax.spines.values():
            s.set_visible(False)
    fig.suptitle("Improved detector - confusion matrices", color=INK, fontsize=12, x=0.02, ha="left")
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)


def plot_importance(model, path: str, top_n: int = 15) -> pd.Series:
    imp = pd.Series(model.feature_importances_, index=features.MODEL_FEATURES).sort_values(ascending=False)
    top = imp.head(top_n)[::-1]
    fig, ax = plt.subplots(figsize=(8, 5.2), facecolor=SURFACE)
    colors = [IMPROVED_COLOR if f in features.CONTEXT_FEATURES + features.DERIVED_FEATURES else BASELINE_COLOR
              for f in top.index]
    ax.barh(top.index, top.values, color=colors, edgecolor=SURFACE, linewidth=2)
    ax.set_xlabel("Feature importance", color=INK_2, fontsize=9)
    ax.set_title(f"Top {top_n} features - improved model", color=INK, fontsize=12, loc="left")
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=BASELINE_COLOR, label="Per-flow (Lab3)"),
                       Patch(color=IMPROVED_COLOR, label="New: context / derived")],
              frameon=False, fontsize=9, loc="lower right", labelcolor=INK_2)
    _style(ax)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)
    return imp


# ------------------------------------------------------------------ main ---
def fmt(m: dict) -> str:
    return (f"acc={m['accuracy']:.4f} prec={m['precision']:.4f} rec={m['recall']:.4f} "
            f"f1={m['f1_score']:.4f} | FP={m['fp']:,} FN={m['fn']:,}")


def run() -> None:
    os.makedirs(config.MODELS_DIR, exist_ok=True)
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    feats = prepare_dataset()
    results = {}

    for name, (train_real, test, synth) in splits(feats).items():
        print(f"\n=== {name} split: train {len(train_real):,} real (+{len(synth)} synthetic), "
              f"test {len(test):,} ===")
        baseline, improved, rule_threshold = train_pair(train_real, synth)
        results[name] = evaluate_split(baseline, improved, rule_threshold, test)
        results[name]["rule_threshold"] = rule_threshold
        print(f"  baseline : {fmt(results[name]['baseline'])}")
        print(f"  improved : {fmt(results[name]['improved'])}  "
              f"(+{results[name]['improved_suspicious_flows']} Suspicious)")
        print(f"  improved, as small sampled logs: {fmt(results[name]['improved_sampled_logs'])}")
        if name == "random":
            deploy = (baseline, improved, rule_threshold, results[name])

    baseline, improved, rule_threshold, deployed_metrics = deploy
    bundle = {
        "model": improved,
        "feature_names": features.MODEL_FEATURES,
        "rule_threshold": rule_threshold,
        "metrics": deployed_metrics["improved"],
        "time_split_metrics": results["time"]["improved"],
        "n_estimators": config.N_ESTIMATORS,
        "versions": {"python": platform.python_version(), "sklearn": sklearn.__version__},
    }
    hybrid = detector.HybridDetector(bundle)

    print("\n=== held-out attack logs (never trained on) ===")
    for key, path in [("evasion_v1", config.EVASION_V1_PATH), ("evasion_v2", config.EVASION_V2_PATH)]:
        results[key] = evaluate_attack_log(path, baseline, hybrid)
        r = results[key]
        print(f"  {key}: {r['flows']} attack flows | baseline caught {r['baseline_detected']} | "
              f"improved: {r['improved_threat']} Threat, {r['improved_suspicious']} Suspicious "
              f"(rule hits {r['improved_rule_hits']}, max p={r['improved_max_probability']:.3f})")

    bundle["attack_tests"] = {k: results[k] for k in ("evasion_v1", "evasion_v2")}
    joblib.dump(bundle, config.MODEL_PATH)
    with open(os.path.join(config.OUTPUT_DIR, "metrics.json"), "w") as f:
        json.dump(results, f, indent=2, default=float)

    plot_comparison(results, os.path.join(config.OUTPUT_DIR, "comparison.png"))
    plot_confusion(results, os.path.join(config.OUTPUT_DIR, "confusion_matrices.png"))
    imp = plot_importance(improved, os.path.join(config.OUTPUT_DIR, "feature_importance.png"))
    print("\nTop 8 features (improved model):")
    print(imp.head(8).to_string(float_format=lambda v: f"{v:.4f}"))
    print(f"\nRule threshold (calibrated on benign training traffic): {rule_threshold} "
          f"long-quiet connections per server per minute")
    print(f"Saved {config.MODEL_PATH} and outputs/ (metrics.json, comparison.png, "
          f"confusion_matrices.png, feature_importance.png)")


if __name__ == "__main__":
    run()
