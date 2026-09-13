# Study Guide — AI-Based Network Anomaly Detection (Lab 1)

This is a from-scratch explanation of everything in this project: the lab's
requirements, the dataset, why every preprocessing decision was made, how
Isolation Forest actually works, what the metrics mean, what the real
results say, and a defense/Q&A section to prepare you to explain it live.

---

## 1. The assignment in one paragraph

Build a Python program that trains a Machine Learning model to tell normal
network traffic apart from attack traffic, using a real, labeled
cybersecurity dataset. Train on one portion of the data, test on data the
model never saw, and report real Accuracy / Precision / Recall / F1-score
plus a Confusion Matrix. Analyze what got detected, what got missed, and
produce at least one visualization. The final question the lab asks you to
answer:

> **Can a Machine Learning model implemented in Python detect abnormal or
> potentially malicious network activity in a real cybersecurity dataset?**

Short answer this project demonstrates: **yes, but unevenly** — it depends
heavily on how "loud" the attack is. See §7.

---

## 2. The dataset: AB-TRAP

**Source:** [github.com/c2dc/AB-TRAP](https://github.com/c2dc/AB-TRAP)
("Attack/Bonafide TRAffic Project"), a network-security research testbed
that produces labeled packet captures for training intrusion-detection
models.

We use the **Local Area Network** testbed data, which has two halves:

| Capture | What's in it | Packets |
|---|---|---|
| `1_Attack dataset/Local Area Network` | Real traffic from 5 scanning tools (**nmap**, **hping3**, **masscan**, **unicornscan**, **zmap**) run against targets on an isolated LAN, covering 22 distinct scan *techniques* (SYN, FIN, NULL, XMAS, ACK, full connect, window, maimon...) | 86,480 |
| `2_Bonafide dataset` | Genuine background traffic captured on the same network with **no attack running** | 103,094 |

Why this dataset fits the lab: it is real captured traffic (not synthetic),
it is labeled (every attack packet is tagged with which tool/technique
produced it, via `attack_labels_sbseg.csv` which maps attacker IP →
technique), and the "attack" here — network port scanning — is explicitly
one of the behaviors the lab's background section names ("scanning,
brute-force attempts, denial-of-service activity...").

**What one row is.** Each row is a single network *packet*, not a flow.
The AB-TRAP authors captured raw `.pcap` files and ran `tshark` to export
~40 header fields per packet (`frame_info.*`, `ip.*`, `tcp.*` — things like
IP TTL, packet length, TCP flags, window size). This is a lower-level, more
granular unit than the flow-based records you'd see in UNSW-NB15 or
CIC-IDS2017 (which aggregate a whole connection into one row).

**Missing values.** Both captures contain non-IPv4 or non-TCP packets
(mostly IPv6 traffic), which leaves the `ip.*`/`tcp.*` columns empty for
those rows (141,841 missing cells in the attack capture, 377,663 in the
bonafide capture — several per row across ~40 columns). These are filled
with 0 in `preprocessing.py`, which is safe here because 0 is not a valid
value for any of the fields we keep (see §3), so it can't be confused with
a real measurement.

---

## 3. Data preparation — feature engineering

### 3.1 Building the label

`preprocessing.build_labeled_dataset()`:
1. Merges the attack packets with `attack_labels` on `ip.src == ip` → every
   attack packet now carries the *name* of the technique that produced it
   (kept in an `attack_type` column, e.g. `"nmap_tcp_syn"`).
2. Stacks attack packets (`label=1`) on top of bonafide packets (`label=0`,
   `attack_type="benign"`) into one 189,574-row table.

### 3.2 Why these 40 raw columns become 15 features

`preprocessing.py` drops columns in four groups, each for a different
reason:

| Group | Columns | Why dropped |
|---|---|---|
| **Capture bookkeeping** | `frame_info.time`, `frame_info.encap_type`, `frame_info.time_epoch`, `frame_info.number`, `frame_info.len`, `frame_info.cap_len`, `eth.type` | These describe *when/how tshark captured the packet*, not the traffic itself. |
| **Host-identifying** | `ip.src`, `ip.dst`, `ip.version`, `ip.proto`, `ip.flags`, `tcp.flags` | Keeping source/destination IP would let the model "cheat" by memorizing which specific addresses were attackers in this one testbed — it would then fail completely on a new network. `ip.flags`/`tcp.flags` are dropped because we already keep their **individual bits** (`ip.flags.df`, `tcp.flags.syn`, etc.), which is more informative than the packed value. |
| **Zero variance** | `ip.hdr_len`, `ip.tos`, `ip.flags.rb`, `ip.flags.mf`, `ip.frag_offset` | Constant in this capture (verified by AB-TRAP's own analysis) — a feature that never changes carries zero information for a model. |
| **Ports & pseudo-random values** | `ip.checksum`, `ip.ttl`, `tcp.checksum`, `tcp.srcport`, `tcp.dstport`, `tcp.seq`, `tcp.ack`, `tcp.options.mss_val` | Checksums/seq/ack numbers are effectively random per-connection. TTL was dropped because in *this* testbed every scanner is 2 router-hops away (TTL always arrives as 62) — keeping it would just teach the model this network's topology, not "what a scan looks like". Ports are dropped so detection isn't tied to which service was targeted. |

**What's left — the actual feature vector (15 columns):**

| Feature | Meaning |
|---|---|
| `ip.id` | IP identification field (used for fragment reassembly) |
| `ip.flags.df` | "Don't Fragment" bit |
| `ip.len` | Total IP packet length |
| `ip.dsfield` | Differentiated Services field (QoS marking) |
| `tcp.len` | TCP payload length |
| `tcp.hdr_len` | TCP header length |
| `tcp.flags.fin` | FIN flag bit |
| `tcp.flags.syn` | SYN flag bit |
| `tcp.flags.reset` | RST flag bit |
| `tcp.flags.push` | PSH flag bit |
| `tcp.flags.ack` | ACK flag bit |
| `tcp.flags.urg` | URG flag bit |
| `tcp.flags.cwr` | Congestion Window Reduced bit |
| `tcp.window_size` | TCP receive window advertised |
| `tcp.urgent_pointer` | Urgent pointer field |

Two of these (`ip.id`, `ip.dsfield`) arrive from `tshark` as hex strings
like `"0x0000b2c5"` and are converted to integers (`_hex_to_int`) before
they can be used numerically.

**Why this feature set works for scan detection:** normal TCP traffic
follows a predictable flag pattern (a handshake sets SYN, then ACK, then
data flows with PSH+ACK). Scanners intentionally send abnormal flag
combinations to provoke revealing responses without completing a real
connection — a NULL scan sets *no* flags, a XMAS scan sets FIN+PSH+URG
simultaneously, which never happens in legitimate traffic. That is exactly
the kind of "shape" these 15 fields capture.

---

## 4. Train/test split — the anomaly-detection paradigm

This is the single most important design decision in the project, and the
one most worth being able to explain:

> **The model is trained on *only* benign traffic.** 70% of the bonafide
> packets go into training; the remaining 30% of bonafide packets **plus
> every attack packet** go into the test set.

This is different from ordinary supervised classification (where you'd
train on a mix of both classes). It's the standard setup for **unsupervised
/ one-class anomaly detection**: the model never gets to see what an attack
"looks like" — it only learns the shape of normal traffic, then flags
anything at test time that doesn't fit that shape. Labels are used only
*after* the fact, to score how well it did.

Two reasons this is the right choice here, and worth saying out loud in a
defense:
1. **It matches real-world deployment.** In production you usually have
   abundant normal traffic to learn from, but you can't enumerate every
   attack technique in advance (there will always be a new scan tool). A
   model trained this way can flag *novel* anomalies, not just the 22
   techniques in this dataset.
2. **It satisfies the lab's requirement more strictly** — test data isn't
   just "not used to fit the final model," attack data is never seen at
   any point before evaluation.

The trade-off (worth naming, not hiding): a *supervised* classifier trained
on both classes (which is what AB-TRAP's own research notebooks do, with
Random Forest/Decision Tree/etc.) would likely score higher on this
particular dataset, because it gets to directly learn "these flag patterns
= attack." Isolation Forest instead has to infer that from "does this
deviate from normal" alone, which is harder but generalizes better to
attacks it has never seen labeled examples of.

---

## 5. The model: Isolation Forest

**Core idea.** Isolation Forest builds many random binary trees. At each
node, it picks a random feature and a random split value between that
feature's min and max, splitting the data in two. It repeats this
recursively until every point is alone in its own leaf. The key insight:

> **Anomalies are easier to isolate than normal points.**

A normal packet sits in a dense cluster of similar packets — many random
splits are needed before it's finally alone. An anomalous packet (say, a
NULL scan with every flag at 0, when almost nothing else in the traffic
looks like that) tends to get separated from the rest of the data in just
one or two splits, because there's *so little else like it* nearby in
feature space. **Anomaly score is based on average path length** to isolate
a point across all trees in the forest: short path → anomalous, long path →
normal.

**In this project's code (`model.py`):**
```python
model = IsolationForest(
    n_estimators=200,      # number of random trees in the forest
    max_samples="auto",    # subsample size per tree (256, per the original paper)
    contamination="auto",  # let sklearn set the score threshold automatically
    random_state=42,
)
model.fit(X_train)          # X_train is BENIGN packets only
raw = model.predict(X_test) # -1 = anomaly, 1 = normal
scores = model.decision_function(X_test)  # continuous score; 0 is the cutoff
```
`predict()` gives the binary anomaly/normal call; `decision_function()`
gives the underlying continuous score, which is what's plotted in
`outputs/anomaly_scores.png` (see §7).

**Why Isolation Forest specifically** (the lab explicitly suggests it as
one option): it needs no labels to train, scales roughly linearly with
data size (important here — 72k+ training packets), makes no assumption
that the data is Gaussian/spherical (unlike, say, a simple distance-based
method), and its output is directly interpretable as "how anomalous."

---

## 6. Evaluation metrics — what they mean *here*

For every packet in the test set, the outcome is one of four things:

| | Predicted normal | Predicted attack |
|---|---|---|
| **Actually normal** | True Negative (TN) — correctly ignored | False Positive (FP) — false alarm |
| **Actually attack** | False Negative (FN) — attack slipped through | True Positive (TP) — attack caught |

```
Accuracy  = (TP + TN) / (TP + TN + FP + FN)   → overall % correct
Precision = TP / (TP + FP)                     → of what we flagged, how much was real
Recall    = TP / (TP + FN)                     → of real attacks, how much did we catch
F1-score  = 2 · Precision · Recall / (Precision + Recall)   → harmonic mean of the two
```

**Why you can't just look at Accuracy in security:** the classes are
imbalanced (103,094 benign vs 22,373 attack packets in the full dataset —
about 82%/18%). A model that predicted "normal" for everything would still
score ~82% accuracy while catching zero attacks. That's why the lab
requires Precision/Recall/F1 alongside accuracy — they expose exactly this
failure mode. In a real security operations context, **Recall (catching
attacks) and Precision (not drowning analysts in false alarms) pull in
opposite directions**, and which one matters more depends on the cost of
each mistake: missing a real intrusion (FN) is usually far more expensive
than one extra alert an analyst has to dismiss (FP), which is why many
IDS deployments deliberately tune toward higher recall even at the cost of
some precision.

---

## 7. This project's actual results (from a real run)

```
Training set (benign only):            72,165 packets
Testing set (benign + all attacks):    53,302 packets

Accuracy : 0.7158
Precision: 0.6850
Recall   : 0.5978
F1-score : 0.6384

Confusion Matrix
                 pred_normal   pred_attack
actual_normal        24,778         6,151
actual_attack         8,998        13,375
```

![Confusion matrix](outputs/confusion_matrix.png)
![Anomaly score distribution](outputs/anomaly_scores.png)

**Reading the confusion matrix:** of 22,373 attack packets in the test set,
13,375 were correctly flagged (Recall ≈ 60%) and 8,998 slipped through as
false negatives. Of 30,929 genuine benign packets, 6,151 were incorrectly
flagged as attacks (a ~20% false-positive rate) — visible in the score
plot as the blue ("normal") distribution's left tail bleeding across the
`0.0` decision threshold.

### Detection rate by attack technique — the most important finding

```
attack_type              packets   detected   detection_rate
hping_tcp_null              1000          0            0.000
nmap_tcp_null                1001          0            0.000
hping_tcp_syn                1001          1            0.001
nmap_tcp_ack                 1000         22            0.022
hping_tcp_ack                1000         26            0.026
nmap_tcp_window              1000         29            0.029
nmap_tcp_syn                 1001        178            0.178
benign (false-positive rate)30929       6151            0.199
zmap_tcp_syn                 1250        250            0.200
unicornscan_tcp_ack          1014        268            0.264
masscan_tcp_syn              1003        502            0.500
unicornscan_tcp_conn         1026       1023            0.997
nmap_tcp_conn                1002       1001            0.999
nmap_tcp_fin                 1001       1001            1.000
hping_tcp_xmas               1000       1000            1.000
hping_tcp_fin                1000       1000            1.000
nmap_tcp_xmas                1001       1001            1.000
nmap_tcp_maimon              1000       1000            1.000
unicornscan_tcp_fxmas        1014       1014            1.000
unicornscan_tcp_fin          1014       1014            1.000
unicornscan_tcp_null         1014       1014            1.000
unicornscan_tcp_syn          1017       1017            1.000
unicornscan_tcp_xmas         1014       1014            1.000
```

This is the real story of the project, and it's genuinely explainable, not
just a number:

- **Caught ~100% of the time:** FIN, XMAS, maimon and full-connect (`conn`)
  scans. FIN/XMAS/maimon set flag combinations (FIN alone, or FIN+PSH+URG)
  that essentially never occur in normal traffic — they isolate in very
  few random splits, so Isolation Forest scores them as strongly
  anomalous. `conn` scans complete a full TCP handshake per port, which at
  high scan rates produces a burst of small, uniform packets unlike normal
  application traffic.
- **Missed almost entirely:** NULL scans (0% detected) and plain SYN scans
  from `hping3`/`nmap` (≈0–18%). A NULL scan (zero flags set) and a lone
  SYN packet are each, individually, *not that unusual* — real traffic
  contains plenty of SYN packets (that's how every legitimate connection
  starts), and a single flagless packet doesn't look dramatically
  different from other short/malformed packets that occur naturally. This
  model looks at **one packet at a time** with no notion of rate or
  sequence, so a scanner that sends technically-normal-looking packets one
  at a time (rather than an unusual flag combination) is essentially
  invisible to it.
- **In between (masscan, zmap, unicornscan variants at 20–50%):** these
  are high-speed scanners; some of their packets have quirks (unusual
  window sizes, non-standard TCP options) that occasionally isolate, but
  not consistently.

**The honest conclusion:** yes, ML can detect network attacks from raw
packet features — but *what* it can detect depends entirely on whether the
attack's packets look statistically different from normal traffic in the
features you gave it. A per-packet, content-only model like this one is
strong against scans with unusual flag signatures and blind to
low-and-slow or protocol-conformant scans (NULL, plain SYN) that would
need *timing/rate/sequence* features (e.g. "how many distinct ports did
this source IP touch in 10 seconds") to catch — which is exactly the kind
of flow-level feature production IDS/NIDS systems add on top of this.

---

## 8. Code walkthrough (maps to the lab's 5-step workflow)

| Lab step | File | What it does |
|---|---|---|
| Step 1 — Download & explore | `src/data_loader.py` | Downloads the 3 raw CSVs from GitHub into `data/` (cached), prints shape/columns/missing-value counts |
| Step 2 — Prepare for ML | `src/preprocessing.py` | Merges labels, hex-decodes, drops columns (§3), builds the train/test split (§4) |
| Step 3 — Train the model | `src/model.py` | Fits `IsolationForest` on benign-only training data |
| Step 4 — Detect & evaluate | `src/evaluate.py` (`compute_metrics`, `plot_confusion_matrix`) | Runs predictions on the test set, computes Accuracy/Precision/Recall/F1, plots + prints the confusion matrix |
| Step 5 — Analyze results | `src/evaluate.py` (`analyze_detections`, `plot_score_distribution`) | Breaks detection rate down by attack technique, prints TP/FP/FN examples, plots the anomaly-score histogram |
| Orchestration | `src/main.py` | Runs all five steps in order, end to end |
| Constants | `src/config.py` | Dataset URLs/paths, `RANDOM_STATE=42`, `TEST_SIZE=0.30` |

**Libraries and why each is used:**

| Library | Used for |
|---|---|
| `pandas` | Loading/merging/filtering the CSV data as DataFrames |
| `numpy` | Numeric array operations (casting feature columns, thresholding) |
| `scikit-learn` | `IsolationForest`, `train_test_split`, all four evaluation metrics, `confusion_matrix` |
| `matplotlib` / `seaborn` | The confusion-matrix heatmap and anomaly-score histogram |
| `requests` | Downloading the dataset CSVs from GitHub on first run |

---

## 9. Mapping this project onto the required Word report

Use this as a checklist while writing the `.docx` deliverable (this repo
gives you the code and the real numbers; the report needs *your own*
screenshots of running it):

1. **Student info** — fill in yourself.
2. **Dataset** — name: *AB-TRAP (Local Area Network testbed)*; source:
   `github.com/c2dc/AB-TRAP`; description and "why chosen" are in §2 above;
   screenshot: run `python -m src.main` and capture the Step 1 console
   output.
3. **Environment & libraries** — Python version (`python --version`),
   PyCharm/VS Code, the table in §8.
4. **Data exploration** — screenshot the Step 1 output block (shape,
   columns, attack techniques, missing values).
5. **Data preparation** — explain §3 in your own words; screenshot the
   Step 2 output block (final feature list, class balance, train/test
   sizes).
6. **ML model** — explain Isolation Forest (§5) and the parameters printed
   in the Step 3 output.
7. **Anomaly detection** — screenshot the Step 4 metrics + confusion matrix
   console output, and include `outputs/confusion_matrix.png`.
8. **Evaluation** — the metrics table from §6/§7 plus the confusion matrix
   image.
9. **Results analysis** — the per-technique detection table from §7 plus
   the TP/FP/FN examples the program prints; include
   `outputs/anomaly_scores.png`.
10. **Conclusion** — your own reflection; §7's "honest conclusion"
    paragraph gives you a defensible starting point, but write it in your
    own voice.

---

## 10. Defense Q&A — likely questions and how to answer them

**Q: Why Isolation Forest instead of a supervised classifier?**
A: The lab suggests it explicitly, it needs no labels to train (realistic
for detecting *unknown* attacks), and it directly models "how different is
this from normal" — which is what anomaly detection means. A supervised
model (Random Forest, Decision Tree, etc.) trained on both classes would
likely score higher *on this dataset* but only recognizes attack patterns
it was explicitly shown.

**Q: Why train only on benign traffic — isn't that "cheating" by ignoring
half your labels?**
A: It's the opposite — it's the harder, more realistic setup. The model
never sees an attack example during training, only during evaluation. This
means results reflect the model's ability to generalize to *unseen*
anomalies, not memorize known attack signatures. See §4.

**Q: Why did you drop IP addresses and ports?**
A: To force the model to learn behavioral packet shape rather than
memorizing which specific hosts or ports were attackers/targets in this
one testbed capture — a model that keyed off `172.16.0.x` addresses would
be useless on any other network. See the table in §3.2.

**Q: Why is Recall only ~60%? Doesn't that mean the model failed?**
A: No — it means the model failed on *specific kinds* of scans, not
randomly. §7's per-technique table shows it: FIN/XMAS/maimon/connect scans
are caught almost 100% of the time because their flag combinations are
statistically bizarre; NULL and plain SYN scans are caught rarely because,
packet-by-packet, they don't look very different from ordinary traffic.
That's a real, explainable limitation of a *per-packet* feature set, not a
broken model.

**Q: What would improve Recall on the missed scan types?**
A: Add rate/behavioral features computed per source IP over a time window
(e.g., distinct destination ports contacted in the last N seconds), since
NULL/SYN scans are only obviously anomalous in *aggregate* — one
flagless packet looks normal, but 1,000 of them from one host in one
second doesn't. That requires flow/session-level aggregation instead of
single packets.

**Q: What does the anomaly score actually mean?**
A: It's `IsolationForest.decision_function()` — related to how many random
splits, on average across 200 trees, it takes to isolate that packet from
the rest of the training data. Below 0 (the default cutoff) is flagged as
anomalous; the more negative, the more anomalous. See the histogram in
`outputs/anomaly_scores.png` and §7.

**Q: How did you choose the 70/30 split and `n_estimators=200`?**
A: 70/30 is a conventional holdout ratio, big enough to hold out a
meaningful benign test set while still leaving 72k+ packets to train on.
`n_estimators=200` (more than scikit-learn's default of 100) was chosen to
stabilize the averaged path-length score, since anomaly scoring is
sensitive to the variance of a small forest; `contamination="auto"` lets
scikit-learn set the score threshold using the heuristic from the original
Isolation Forest paper rather than us guessing an attack proportion.

**Q: Why is accuracy not the headline metric?**
A: The dataset is imbalanced (~82% benign / 18% attack in the full data).
A trivial "always predict normal" model scores ~82% accuracy while
catching zero attacks — which is why the lab requires Precision/Recall/F1
and a confusion matrix alongside it. See §6.

**Q: What are the hex-string columns and why convert them?**
A: `ip.id` and `ip.dsfield` are exported by `tshark` as hex strings (e.g.
`"0x0000b2c5"`) because that's how Wireshark displays raw header bytes.
scikit-learn needs numeric input, so `_hex_to_int()` in `preprocessing.py`
parses them with `int(v, 16)` before they're used as features.

**Q: Could this scale to a live network / real-time detection?**
A: The per-packet feature extraction (parsing `tshark`/packet headers) is
cheap and could run inline; Isolation Forest inference is fast (just
walking a fixed set of trees). The real limitation for production use is
the same one raised above — this feature set can't see rate-based attacks,
so a real deployment would pair this per-packet model with flow-level
aggregation.

---

## 11. Glossary

| Term | Meaning |
|---|---|
| **Anomaly detection** | Flagging data points that differ from a learned notion of "normal," without necessarily having labeled examples of every abnormal case |
| **Isolation Forest** | An ensemble of random trees that scores points by how few random splits it takes to isolate them; short path = anomalous |
| **Contamination** | The estimated proportion of anomalies in the data, used to set the decision threshold |
| **Decision function / anomaly score** | Continuous output of Isolation Forest; negative/low = more anomalous |
| **Confusion matrix** | 2×2 table of TP/TN/FP/FN counts comparing predictions to ground truth |
| **Precision** | Of everything flagged as an attack, the fraction that really was one |
| **Recall (sensitivity)** | Of all real attacks, the fraction that got flagged |
| **F1-score** | Harmonic mean of precision and recall — balances both into one number |
| **False positive (FP)** | Benign traffic incorrectly flagged as an attack ("false alarm") |
| **False negative (FN)** | An attack that was missed |
| **TCP flags (SYN/ACK/FIN/RST/PSH/URG)** | Control bits in a TCP header that manage connection state; scanners abuse unusual combinations of these to probe hosts without completing a real connection |
| **Port scan** | Reconnaissance technique that probes many ports/hosts to discover open services; the "attack" behavior in this dataset |
| **Flow vs. packet** | A *packet* is one unit sent on the wire; a *flow* aggregates all packets of one connection into a single record — this project uses packet-level data, most published IDS datasets (UNSW-NB15, CIC-IDS2017) use flow-level data |
| **Bonafide traffic** | AB-TRAP's term for genuine, non-attack background traffic |
| **Contamination-free training** | Training a model exclusively on the "normal" class, as done here |
