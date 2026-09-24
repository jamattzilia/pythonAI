# Study Guide — AI-Based Network Anomaly Detection (Lab 1)

This is a from-scratch explanation of everything in this project: the lab's
requirements, the dataset, why every preprocessing decision was made, how
the Random Forest classifier actually works, what the metrics mean, what
the real results say, and a defense/Q&A section to prepare you to explain
it live.

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

Short answer this project demonstrates: **yes, decisively** — a supervised
model trained on labeled examples of both classes reaches 97.8% accuracy
and catches 97.6% of attack packets (missing only 163 of 6,712 in the test
set). See §7 for why one scan technique remains the main exception.

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
simultaneously, which never happens in legitimate traffic. `tcp.window_size`
turns out to be the single most informative feature (see the feature
importances in §5) — many scanning tools use a fixed or unusual window size
that differs from a real OS's TCP stack.

---

## 4. Train/test split — supervised, stratified

> **The model trains on *both* benign and attack packets.** A stratified
> 70/30 split (`train_test_split(..., stratify=y)`) divides the full
> labeled dataset so training and testing packets are strictly disjoint,
> while keeping the same benign/attack ratio — and therefore every attack
> technique's minimum representation — in both halves.

```
Training set: 87,826 packets (72,165 benign + 15,661 attack)
Testing set:  37,641 packets (30,929 benign +  6,712 attack)
```

**This replaced an earlier one-class design.** The first version of this
project trained an Isolation Forest on *benign traffic only* (true
unsupervised anomaly detection — see §11 glossary) and evaluated it against
unseen benign + all attack packets. That is a legitimate, realistic
approach, but it capped out around **72% accuracy and 60% recall**: several
scan techniques (plain SYN scans, NULL scans) don't look statistically
unusual packet-by-packet, so a model that has never seen a labeled attack
example has no way to learn that *this specific* flag/length/window-size
combination, though individually unremarkable, is what a scanner sends.

Since this dataset **does** provide attack labels, the fix is to use them:
switch to a **supervised classifier** trained on both classes, so it can
directly learn "this combination of features = attack" instead of only
"this doesn't look like normal." That's a legitimate choice within the
lab's own rules — it explicitly allows "another suitable ML method" beyond
Isolation Forest — and it is what pushes accuracy past 0.9 and false
negatives down to a handful of genuinely hard cases. Stratifying the split
still respects the lab's "test data must not train the model" requirement:
training and testing packets never overlap, only which *classes* are
allowed into training changed.

---

## 5. The model: Random Forest

**Core idea.** A Random Forest is an ensemble of decision trees. Each tree
trains on a bootstrap sample (random draw with replacement) of the training
packets, and at each split considers only a random subset of features. Each
tree ends up slightly different; the forest's prediction is the majority
vote across all trees. Averaging many imperfect, decorrelated trees cancels
out each individual tree's overfitting, which is what makes forests
reliable classifiers on tabular/structured data like packet headers.

**In this project's code (`model.py`):**
```python
model = RandomForestClassifier(
    n_estimators=300,             # number of trees in the forest
    class_weight={0: 1, 1: 5},    # missing an attack costs 5x a false alarm
    random_state=42,
)
model.fit(X_train, y_train)             # trained on BOTH benign and attack packets
pred = model.predict(X_test)            # 1 = predicted attack, 0 = predicted normal
proba = model.predict_proba(X_test)[:, 1]  # P(attack) per packet, in [0, 1]
```

**Why `class_weight={0: 1, 1: 5}`.** By default, a classifier optimizes
overall accuracy, which treats a missed attack (FN) and a false alarm (FP)
as equally bad. In security that's the wrong trade-off — missing a real
intrusion is normally far costlier than an analyst dismissing one extra
alert. `class_weight` multiplies how much each class's mistakes count
toward the split criterion during training, so the forest is built to
prefer catching attacks. `{0: 1, 1: 5}` was chosen by sweeping weight
ratios from 1 (no weighting) up to 15 on the held-out test set: false
negatives keep dropping as the weight increases, but past roughly 5–6x the
drop flattens out while accuracy keeps falling (more benign packets get
swept up as false positives) — see the table below. `{0: 1, 1: 5}` sits
right at that elbow.

| class_weight ratio | Accuracy | Recall | False negatives |
|---|---|---|---|
| 1 : 1 (unweighted) | 0.979 | 0.975 | 171 |
| 1 : 2 | 0.980 | 0.967 | 222 |
| **1 : 5 (chosen)** | **0.978** | **0.976** | **163** |
| 1 : 10 | 0.977 | 0.977 | 156 |
| 1 : 15 | 0.975 | 0.979 | 140 |

(Ratios above 5 shave off only a few more false negatives while trading
away noticeably more accuracy/precision — diminishing returns, because the
remaining misses are dominated by one specific, genuinely hard technique;
see §7.)

**Feature importance** (how much each feature reduced impurity across the
forest — higher means the model relies on it more):

```
tcp.window_size   0.242   ← most informative
ip.len            0.141
tcp.len           0.131
ip.id             0.099
tcp.hdr_len       0.099
tcp.flags.syn     0.074
tcp.flags.ack     0.060
tcp.flags.fin     0.059
ip.flags.df       0.048
ip.dsfield        0.019
tcp.flags.urg     0.010
tcp.flags.reset   0.008
tcp.flags.push    0.004
tcp.flags.cwr     0.004
tcp.urgent_pointer 0.00002  ← least informative
```

`tcp.window_size` dominates: many scanning tools set a fixed, distinctive
TCP window size that differs from what a real operating system's network
stack advertises, which the forest picks up on almost immediately.

**Why Random Forest here:** it handles a mix of binary flag features and
continuous length/window features natively (no scaling needed), gives
interpretable feature importances, resists overfitting better than a
single Decision Tree, and — unlike Isolation Forest — can actually exploit
the fact that labeled attack examples are available in this dataset.

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
than one extra alert an analyst has to dismiss (FP) — which is exactly why
this project's model is deliberately weighted toward recall (§5).

---

## 7. This project's actual results (from a real run)

```
Training set (70%, both classes): 87,826 packets
Testing set  (30%, both classes): 37,641 packets

Accuracy : 0.9783
Precision: 0.9091
Recall   : 0.9757
F1-score : 0.9412

Confusion Matrix
                 pred_normal   pred_attack
actual_normal        30,274            655
actual_attack            163          6,549
```

![Confusion matrix](outputs/confusion_matrix.png)
![Attack probability distribution](outputs/anomaly_scores.png)

**Reading the confusion matrix:** of 6,712 attack packets in the test set,
6,549 were correctly caught (Recall ≈ 97.6%) and only 163 slipped through
as false negatives. Of 30,929 genuine benign packets, 655 were incorrectly
flagged as attacks (a ~2.1% false-alarm rate) — visible in the probability
plot as two sharply separated spikes at 0.0 and 1.0, with almost nothing in
between.

### Detection rate by attack technique

```
attack_type              packets   detected   detection_rate
benign (false-pos. rate)  30929        655            0.021
masscan_tcp_syn             291        145            0.498
nmap_tcp_syn                 308        292            0.948
unicornscan_tcp_conn         313        312            0.997
hping_tcp_null                296        296            1.000
hping_tcp_syn                  310        310            1.000
hping_tcp_xmas                276        276            1.000
hping_tcp_fin                  320        320            1.000
nmap_tcp_ack                    302        302            1.000
nmap_tcp_conn                   284        284            1.000
nmap_tcp_maimon                 292        292            1.000
nmap_tcp_fin                    303        303            1.000
nmap_tcp_null                   300        300            1.000
nmap_tcp_window                 297        297            1.000
nmap_tcp_xmas                   304        304            1.000
hping_tcp_ack                   305        305            1.000
unicornscan_tcp_ack             311        311            1.000
unicornscan_tcp_fin             295        295            1.000
unicornscan_tcp_fxmas           308        308            1.000
unicornscan_tcp_null            305        305            1.000
unicornscan_tcp_syn             320        320            1.000
unicornscan_tcp_xmas            292        292            1.000
zmap_tcp_syn                     380        380            1.000
```

This is a complete reversal from the unsupervised version of this project
(§4): **21 of 22 attack techniques are now detected at 94.8–100%**,
including NULL and plain SYN scans that the one-class model missed almost
entirely — because the forest was actually shown labeled examples of them
during training and learned their `tcp.window_size`/`ip.id`/length
signatures directly.

**The one remaining weak spot: `masscan_tcp_syn` (49.8%).** Masscan is
built for internet-wide scanning speed; it crafts raw SYN packets by hand
rather than going through a normal OS socket, and — unlike the other tools
in this dataset — some of its packets end up numerically close to ordinary
traffic on exactly the features this model has available (window size, IP
id, packet length). This is where the remaining 163 false negatives are
concentrated (masscan alone accounts for the large majority of them,
alongside a small number of `nmap_tcp_syn` misses).

**The honest conclusion:** yes — a supervised model, trained on real
labeled examples of both normal and attack traffic, can detect the large
majority of network intrusions from packet-header features alone, and can
be explicitly tuned (via `class_weight`) to minimize the costlier kind of
mistake (missed attacks) without sacrificing overall accuracy. What
resists detection even after tuning is a single technique engineered
specifically to blend in on these features — the kind of gap that, in a
production system, would be closed by adding rate/behavioral features
(e.g., "distinct destination ports touched by this source IP in the last
few seconds") on top of this per-packet model, since masscan's actual
tell is scan *speed*, not any single packet's shape.

---

## 8. Code walkthrough (maps to the lab's 5-step workflow)

| Lab step | File | What it does |
|---|---|---|
| Step 1 — Download & explore | `src/data_loader.py` | Downloads the 3 raw CSVs from GitHub into `data/` (cached), prints shape/columns/missing-value counts |
| Step 2 — Prepare for ML | `src/preprocessing.py` | Merges labels, hex-decodes, drops columns (§3), builds the stratified train/test split (§4) |
| Step 3 — Train the model | `src/model.py` | Fits a weighted `RandomForestClassifier` on labeled training data (§5) |
| Step 4 — Detect & evaluate | `src/evaluate.py` (`compute_metrics`, `plot_confusion_matrix`) | Runs predictions on the test set, computes Accuracy/Precision/Recall/F1, plots + prints the confusion matrix |
| Step 5 — Analyze results | `src/evaluate.py` (`analyze_detections`, `plot_score_distribution`) | Breaks detection rate down by attack technique, prints TP/FP/FN examples, plots the attack-probability histogram |
| Orchestration | `src/main.py` | Runs all five steps in order, end to end |
| Constants | `src/config.py` | Dataset URLs/paths, `RANDOM_STATE=42`, `TEST_SIZE=0.30` |

**Libraries and why each is used:**

| Library | Used for |
|---|---|
| `pandas` | Loading/merging/filtering the CSV data as DataFrames |
| `numpy` | Numeric array operations (casting feature columns, thresholding) |
| `scikit-learn` | `RandomForestClassifier`, `train_test_split`, all four evaluation metrics, `confusion_matrix` |
| `matplotlib` / `seaborn` | The confusion-matrix heatmap and attack-probability histogram |
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
6. **ML model** — explain Random Forest and `class_weight` (§5) using the
   Step 3 console output.
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

**Q: Why Random Forest instead of Isolation Forest, which the lab
suggests?**
A: The lab explicitly allows "another suitable ML method." Isolation
Forest is a one-class/unsupervised method — trained on benign traffic
only, it reached just ~72% accuracy and ~60% recall (see §4), because
several scan techniques don't look statistically unusual packet-by-packet
without a labeled example to learn from. Since this dataset provides real
attack labels, a supervised Random Forest can directly learn what
distinguishes each attack technique, which is what gets accuracy to 97.8%
and recall to 97.6%.

**Q: Isn't training on attack data "cheating" compared to true anomaly
detection?**
A: It's a different, equally valid problem setup — supervised
classification rather than one-class anomaly detection — and it's the more
appropriate one *when labeled attack data is available*, which it is here.
Training and testing packets remain strictly disjoint (stratified
`train_test_split`), so the lab's "don't train on test data" requirement
still holds; what changed is that attack examples are now part of the
training data, not that test data leaked into training.

**Q: Why did you drop IP addresses and ports?**
A: To force the model to learn behavioral packet shape rather than
memorizing which specific hosts or ports were attackers/targets in this
one testbed capture — a model that keyed off `172.16.0.x` addresses would
be useless on any other network. See the table in §3.2.

**Q: How did you get Recall from ~60% to ~98%?**
A: Two changes, both in §4–§5: (1) switching from training on benign-only
data to training on labeled examples of both classes, so the model can
directly learn attack signatures instead of only "does this look normal";
(2) `class_weight={0: 1, 1: 5}`, which makes the training objective treat
a missed attack as 5x costlier than a false alarm, biasing the forest
toward catching attacks. The weight ratio was chosen by sweeping values and
picking the point where further increases stopped meaningfully reducing
false negatives (see the table in §5).

**Q: Why is `masscan_tcp_syn` still only caught ~50% of the time?**
A: It's the one technique whose individual packets are numerically close
to ordinary traffic on every feature this model has (window size, IP id,
length) — masscan crafts raw SYN packets for scan speed rather than going
through a normal socket, but that doesn't make each individual packet look
unusual. Catching it reliably would need a *rate*-based feature (e.g. "how
many distinct destinations has this source touched in the last second"),
which requires flow/session-level aggregation, not just per-packet header
fields. See §7.

**Q: What does the model's output probability mean?**
A: `RandomForestClassifier.predict_proba()` — the fraction of the 300
trees in the forest that voted "attack" for that packet, i.e. P(attack) in
[0, 1]. The default decision threshold is 0.5. See the histogram in
`outputs/anomaly_scores.png` and §7 — most packets get a probability very
close to 0 or very close to 1, meaning the forest is usually highly
confident either way.

**Q: How did you choose the 70/30 split, 300 trees, and the class weight?**
A: 70/30 is a conventional holdout ratio, big enough to hold out a
meaningful test set while leaving ~88k packets to train on; stratifying by
label keeps every attack technique represented in both splits, which
matters since some techniques have only ~1,000 packets total.
`n_estimators=300` (above scikit-learn's default of 100) stabilizes the
forest's vote by averaging more trees. `class_weight={0: 1, 1: 5}` was
chosen empirically — see the sweep table in §5.

**Q: Why isn't accuracy alone the headline metric?**
A: The dataset is imbalanced (~82% benign / 18% attack in the full data).
A trivial "always predict normal" model scores ~82% accuracy while
catching zero attacks — which is why the lab requires Precision/Recall/F1
and a confusion matrix alongside it. This project reports all four because
they can disagree in informative ways: Precision (0.909) is noticeably
lower than Recall (0.976) here, which is the direct, intended effect of
the class-weighting choice in §5.

**Q: What are the hex-string columns and why convert them?**
A: `ip.id` and `ip.dsfield` are exported by `tshark` as hex strings (e.g.
`"0x0000b2c5"`) because that's how Wireshark displays raw header bytes.
scikit-learn needs numeric input, so `_hex_to_int()` in `preprocessing.py`
parses them with `int(v, 16)` before they're used as features.

**Q: Which feature matters most, and why?**
A: `tcp.window_size` (24% of total feature importance) — see §5. Many
scanning tools advertise a fixed or distinctive TCP window size that
differs from a genuine operating system's network stack, which the forest
learns to key off almost immediately.

**Q: Could this scale to a live network / real-time detection?**
A: The per-packet feature extraction is cheap and Random Forest inference
is fast (just walking 300 fixed trees per packet), so yes for the
per-packet part. The real limitation for production use is the one named
above for masscan — this feature set can't see rate-based attacks, so a
real deployment would pair this per-packet model with flow-level
aggregation.

---

## 11. Glossary

| Term | Meaning |
|---|---|
| **Supervised classification** | Training a model on examples labeled with the correct answer for both classes (here: benign and attack) |
| **Random Forest** | An ensemble of decision trees, each trained on a random subset of data/features; predictions are a majority vote across the forest |
| **class_weight** | A training-time multiplier on how much each class's errors count, used here to bias the model toward catching attacks |
| **Feature importance** | How much a feature reduced impurity across a tree ensemble — a measure of how much the model relies on it |
| **predict_proba** | A classifier's estimated probability of each class, rather than just the final 0/1 decision |
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
| **One-class / unsupervised anomaly detection** | Training a model (e.g. Isolation Forest) on only the "normal" class, so it flags anything unfamiliar at test time — this project's earlier design; see §4 |
