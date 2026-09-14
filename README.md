# pythonAI — AI-Based Network Anomaly Detection

Laboratory Work 1 (Artificial Intelligence in Cybersecurity): a Python
program that uses Machine Learning to detect abnormal / potentially
malicious network activity in a real network-traffic dataset.

## Dataset

**[AB-TRAP](https://github.com/c2dc/AB-TRAP)** (Attack/Bonafide Traffic
capture Project), Local Area Network testbed data:

| Source | Content |
|---|---|
| `1_Attack dataset/Local Area Network` | Raw packets captured while real scanning tools (**nmap**, **hping3**, **masscan**, **unicornscan**, **zmap** — 23 distinct scan techniques) were run against multiple targets on an isolated LAN testbed. |
| `2_Bonafide dataset` | Raw packets captured on the same network with **no attack running** (genuine background traffic). |

Chosen because it is a real, labeled, packet-level capture of network
reconnaissance/intrusion activity (TCP port scanning is one of the
scanning/reconnaissance behaviors called out in the lab background) paired
with a matching sample of normal traffic from the same environment — exactly
the "normal vs. attack" structure the lab requires. Each row is one network
packet described by ~40 fields extracted with `tshark` (IP/TCP header
fields, flags, lengths, etc.).

The raw CSVs (~20 MB) are **not** committed to this repository; running the
project downloads them once from GitHub into `data/` (see Step 1 below).

## Project layout

```
src/
  config.py        paths, dataset URLs, constants
  data_loader.py   Step 1: download + load + explore the raw captures
  preprocessing.py Step 2: merge labels, feature selection, hex decoding, train/test split
  model.py         Step 3: Isolation Forest training + prediction
  evaluate.py       Step 4-5: metrics, confusion matrix, plots, anomaly analysis
  main.py          orchestrates the full pipeline
outputs/           generated on each run: confusion_matrix.png, anomaly_scores.png, summary.json
```

## How to run

```bash
python -m venv .venv && source .venv/bin/activate      # optional
pip install -r requirements.txt
python -m src.main
```

The first run downloads ~24 MB of data into `data/` (cached for later runs)
and prints the full pipeline log to the console; plots and a JSON summary
are written to `outputs/`.

## Method

- **Features (15):** `ip.id`, `ip.flags.df`, `ip.len`, `ip.dsfield`,
  `tcp.len`, `tcp.hdr_len`, `tcp.flags.{fin,syn,reset,push,ack,urg,cwr}`,
  `tcp.window_size`, `tcp.urgent_pointer`.
  Bookkeeping fields (capture timestamps/frame numbers), host-identifying
  fields (`ip.src`/`ip.dst`, so the model can't just memorize known
  attacker/target addresses), zero-variance fields, and easily-spoofed or
  effectively-random fields (`ip.ttl`, ports, sequence/ack numbers,
  checksums) are dropped — see the top of `preprocessing.py` for the full
  rationale. What remains is a behavioural fingerprint of each packet:
  different scan types (SYN, NULL, XMAS, ACK, ...) set very distinctive,
  unusual combinations of these fields.
- **Model:** `sklearn.ensemble.IsolationForest` — trained **only on benign
  traffic**, so it learns what "normal" looks like; anything that doesn't
  fit the learned pattern (i.e. every attack packet, which the model never
  sees during training) is flagged as an anomaly. This is the standard setup
  for unsupervised anomaly detection and satisfies the lab's requirement
  that test data must never be used for training.
- **Train/test split:** 70% of benign packets → training; the remaining 30%
  of benign packets + all attack packets → test set (labels are used only
  to compute evaluation metrics afterward, never during training).
- **Evaluation:** Accuracy, Precision, Recall, F1-score, and a Confusion
  Matrix, computed by comparing predictions on the test set against the true
  benign/attack labels.
- **Analysis:** detection rate broken down by attack tool/technique, plus
  concrete examples of true positives, false positives and false negatives.
