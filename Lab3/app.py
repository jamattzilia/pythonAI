"""Step 3 — Streamlit dashboard for the IoT Botnet Traffic Classifier.

Run with: streamlit run app.py

Loads the trained model bundle (models/iot_botnet_model.pkl), lets the user
upload a CSV of network flow records, runs every row through the model with
the exact same preprocessing used during training, and renders a threat
dashboard: summary counts, a safe/threat chart, per-flow verdicts with
threat probability, and a downloadable results file.
"""
import os

import joblib
import pandas as pd
import streamlit as st

from src import config, preprocessing

st.set_page_config(page_title="IoT Botnet Traffic Classifier", page_icon="🛡️", layout="wide")


@st.cache_resource
def load_model_bundle():
    if not os.path.exists(config.MODEL_PATH):
        return None
    return joblib.load(config.MODEL_PATH)


def classify(bundle, raw_df: pd.DataFrame) -> pd.DataFrame:
    X = preprocessing.transform_for_inference(raw_df, bundle["feature_names"])
    proba = bundle["model"].predict_proba(X)[:, 1]
    pred = (proba >= 0.5).astype(int)

    results = raw_df.reset_index(drop=True).copy()
    results["Threat Probability"] = proba.round(4)
    results["Verdict"] = ["🚨 Threat" if p == 1 else "✅ Safe" for p in pred]
    return results


# ---------------------------------------------------------------- header ---
st.title("🛡️ IoT Botnet Traffic Classifier")
st.caption(
    "Upload a CSV of network flow records (CICFlowMeter-style columns: Flow Duration, "
    "packet/byte counts, TCP flags, ...) to classify each flow as **Safe** or a **Threat** "
    "(DDoS / botnet traffic)."
)

bundle = load_model_bundle()
if bundle is None:
    st.error(
        "No trained model found at `models/iot_botnet_model.pkl`. "
        "Train it first: `python -m src.train`"
    )
    st.stop()

with st.sidebar:
    st.header("Model info")
    st.metric("Algorithm", "Random Forest")
    st.metric("Trees", bundle["n_estimators"])
    st.metric("Training flows", f"{bundle['training_rows']:,}")
    st.divider()
    st.subheader("Held-out test performance")
    m = bundle["metrics"]
    st.metric("Accuracy", f"{m['accuracy']:.4f}")
    st.metric("Precision", f"{m['precision']:.4f}")
    st.metric("Recall", f"{m['recall']:.4f}")
    st.metric("F1-score", f"{m['f1_score']:.4f}")
    st.divider()
    st.subheader("Evasion test case")
    st.caption(
        "A hand-crafted **low-and-slow DDoS** log is included at "
        "`data/low_and_slow_evasion.csv` for the live self-attack demo - "
        "load or upload it below and see what happens."
    )
    if os.path.exists(config.EVASION_CSV_PATH):
        with open(config.EVASION_CSV_PATH, "rb") as f:
            st.download_button(
                "Download evasion test CSV", f, file_name="low_and_slow_evasion.csv",
                mime="text/csv",
            )

# ------------------------------------------------------------- uploader ---
st.caption(
    "Demo tip: the two bundled sample logs below are a few KB each and load "
    "instantly. Uploading the full ~34 MB raw dataset isn't necessary for the "
    "demo, and some hosting setups reject uploads that large with an HTTP 413 "
    "before this app ever sees the file."
)

col_a, col_b = st.columns(2)
with col_a:
    load_sample = st.button("📋 Load bundled sample log (60 real flows)", use_container_width=True)
with col_b:
    load_evasion = st.button("🕵️ Load low-and-slow evasion log", use_container_width=True)

uploaded = st.file_uploader("...or upload your own network log (CSV)", type="csv")

if load_sample:
    st.session_state["active_source"] = ("Bundled sample log", config.SAMPLE_LOG_PATH)
elif load_evasion:
    st.session_state["active_source"] = ("Low-and-slow evasion log", config.EVASION_CSV_PATH)
elif uploaded is not None:
    st.session_state["active_source"] = (uploaded.name, uploaded)

active = st.session_state.get("active_source")
if active is None:
    st.info("Load a bundled sample or upload a network log CSV to see the threat dashboard.")
    st.stop()

source_label, source = active
try:
    raw_df = pd.read_csv(source)
except Exception as exc:
    st.error(f"Could not read '{source_label}' as CSV: {exc}")
    st.stop()

if len(raw_df) == 0:
    st.warning(f"'{source_label}' has no rows.")
    st.stop()

st.caption(f"Classifying: **{source_label}** ({len(raw_df)} flows)")

results = classify(bundle, raw_df)
n_total = len(results)
n_threat = int((results["Verdict"] == "🚨 Threat").sum())
n_safe = n_total - n_threat

# ------------------------------------------------------------ dashboard ---
st.subheader("Threat dashboard")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total flows", f"{n_total:,}")
c2.metric("Flagged as threat", f"{n_threat:,}")
c3.metric("Flagged as safe", f"{n_safe:,}")
c4.metric("Threat rate", f"{n_threat / n_total:.1%}")

if n_threat > 0:
    st.error(f"🚨 {n_threat} flow(s) flagged as botnet/DDoS traffic.")
else:
    st.success("✅ No threats detected in this upload.")

col_chart, col_hist = st.columns(2)
with col_chart:
    st.caption("Safe vs. Threat")
    st.bar_chart(pd.Series({"Safe": n_safe, "Threat": n_threat}))
with col_hist:
    st.caption("Threat probability distribution")
    bin_edges = [i / 10 for i in range(11)]
    bin_labels = [f"{bin_edges[i]:.1f}-{bin_edges[i + 1]:.1f}" for i in range(10)]
    binned = pd.cut(results["Threat Probability"], bins=bin_edges, labels=bin_labels,
                     include_lowest=True)
    st.bar_chart(binned.value_counts().reindex(bin_labels, fill_value=0))

st.subheader("Per-flow results")
display_cols = [c for c in [
    "Source IP", "Destination IP", "Destination Port", "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets", "Flow Bytes/s", "Flow Packets/s",
    "Threat Probability", "Verdict",
] if c in results.columns]
st.dataframe(
    results[display_cols].sort_values("Threat Probability", ascending=False),
    use_container_width=True, height=420,
)

st.download_button(
    "Download results as CSV",
    results.to_csv(index=False).encode("utf-8"),
    file_name="classified_flows.csv",
    mime="text/csv",
)

with st.expander("Why might a flow be misclassified? (evasion notes)"):
    st.markdown(
        "This model was trained on real DDoS flood traffic, where attack flows "
        "are identifiable by **large packet/byte volumes** over a **short-to-moderate "
        "duration**. A **low-and-slow** attack (e.g. Slowloris-style) deliberately "
        "avoids that footprint: a handful of tiny packets trickled over a very long "
        "connection. Those flows can land in a region of feature space the model "
        "never saw an attack example for during training, and get missed (a **false "
        "negative**) - try uploading `data/low_and_slow_evasion.csv` (downloadable in "
        "the sidebar) to see this live. See README.md for the full write-up and how "
        "this could be fixed."
    )
