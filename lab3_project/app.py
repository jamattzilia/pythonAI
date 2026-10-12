"""Hybrid IoT/DDoS threat dashboard (improved Lab3).

Run: streamlit run app.py   (train first: python -m src.train)
"""
import os

import joblib
import pandas as pd
import streamlit as st

from src import config, detector

st.set_page_config(page_title="Hybrid Threat Detector", layout="wide")

VERDICT_ORDER = ["Threat", "Suspicious", "Safe"]
SHOW_COLUMNS = ["verdict", "threat_probability", "reason", "Source IP", "Destination IP",
                "Destination Port", "Timestamp", "Flow Duration", "Flow Bytes/s"]
DEMO_LOGS = {
    "Sample log (mixed real traffic)": config.SAMPLE_LOG_PATH,
    "Attack v1 - low-and-slow, one server": config.EVASION_V1_PATH,
    "Attack v2 - slow, spread over 4 servers": config.EVASION_V2_PATH,
}


@st.cache_resource
def load_detector():
    if not os.path.exists(config.MODEL_PATH):
        return None
    return detector.HybridDetector(joblib.load(config.MODEL_PATH))


def pct(x):
    return f"{x:.2%}"


hybrid = load_detector()
if hybrid is None:
    st.error("No trained model found. Run `python -m src.train` first.")
    st.stop()

# ---------------- sidebar: model card ----------------
b = hybrid.bundle
with st.sidebar:
    st.header("Model card")
    st.caption(f"Random Forest ({b['n_estimators']} trees) + slow-connection rule")
    for title, m in [("Random split (30% test)", b["metrics"]), ("Time split (train <= 04:06)", b["time_split_metrics"])]:
        st.markdown(f"**{title}**")
        st.markdown(
            f"F1 {m['f1_score']:.4f} · recall {pct(m['recall'])}  \n"
            f"False positives {m['fp']:,} · false negatives {m['fn']:,}"
        )
    st.markdown("**Slow-flood rule**")
    st.markdown(f"Fires at >= {hybrid.rule_threshold} long, near-idle connections "
                f"to one server in one minute (benign max {hybrid.rule_threshold - 1}).")
    tests = b.get("attack_tests", {})
    if tests:
        st.markdown("**Held-out attack logs**")
        for key, label in [("evasion_v1", "v1 concentrated"), ("evasion_v2", "v2 distributed")]:
            t = tests.get(key)
            if t:
                st.markdown(f"{label}: {t['improved_threat']}/{t['flows']} Threat, "
                            f"{t['improved_suspicious']} Suspicious")
    st.caption(f"Thresholds: Threat p >= {config.THREAT_THRESHOLD}, "
               f"Suspicious p >= {config.SUSPICIOUS_THRESHOLD}")

# ---------------- input ----------------
st.title("Hybrid Threat Detector")
st.write("Upload a CICFlowMeter CSV, or load one of the demo logs. Each flow gets a verdict "
         "(**Threat / Suspicious / Safe**) and a reason; servers under attack are summarised below.")

cols = st.columns(len(DEMO_LOGS))
for col, (label, path) in zip(cols, DEMO_LOGS.items()):
    if col.button(label, use_container_width=True, disabled=not os.path.exists(path)):
        st.session_state["source"] = (label, path)

uploaded = st.file_uploader("...or upload a network log (CSV)", type="csv")
if uploaded is not None:
    st.session_state["source"] = (uploaded.name, uploaded)

if "source" not in st.session_state:
    st.info("Pick a demo log or upload a CSV to start.")
    st.stop()

name, src = st.session_state["source"]
try:
    raw = pd.read_csv(src, low_memory=False)
except Exception as exc:  # noqa: BLE001 - show any parse error to the user
    st.error(f"Could not read {name}: {exc}")
    st.stop()

with st.spinner(f"Scoring {len(raw):,} flows..."):
    scored = hybrid.score(raw)

# ---------------- results ----------------
st.subheader(f"Results - {name}")
counts = scored["verdict"].value_counts().reindex(VERDICT_ORDER, fill_value=0)
m1, m2, m3, m4 = st.columns(4)
m1.metric("Flows analysed", f"{len(scored):,}")
m2.metric("Threat", f"{counts['Threat']:,}")
m3.metric("Suspicious", f"{counts['Suspicious']:,}")
m4.metric("Safe", f"{counts['Safe']:,}")

if counts["Threat"]:
    rule_n = int(scored["rule_hit"].sum())
    st.error(f"{counts['Threat']:,} threatening flows detected"
             + (f" - {rule_n:,} of them by the slow-connection flood rule." if rule_n else "."))
elif counts["Suspicious"]:
    st.warning(f"No confirmed threats, but {counts['Suspicious']:,} flows are borderline - review them.")
else:
    st.success("No threats detected.")

st.markdown("#### Servers")
st.caption("Per destination: a server with many long, near-idle connections is a slow-DoS target "
           "even when each connection looks harmless on its own.")
st.dataframe(detector.server_summary(scored), use_container_width=True)

st.markdown("#### Flows")
show = st.multiselect("Show verdicts", VERDICT_ORDER, default=["Threat", "Suspicious"])
view = scored[scored["verdict"].isin(show)]
view = view.sort_values("threat_probability", ascending=False)
st.dataframe(view[[c for c in SHOW_COLUMNS if c in view.columns]].head(5000),
             use_container_width=True, hide_index=True)
if len(view) > 5000:
    st.caption(f"Showing the top 5,000 of {len(view):,} flows - download for the full list.")

out = scored.drop(columns=["window"], errors="ignore")
st.download_button("Download all verdicts (CSV)", out.to_csv(index=False).encode(),
                   file_name="verdicts.csv", mime="text/csv")
