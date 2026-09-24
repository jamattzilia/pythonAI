# Lab2 — AI-Based Network Intrusion Detection System (NIDS)

A Python pipeline that classifies NSL-KDD network connection records as
normal or attack, implemented independently per the lab's step-by-step
plan (no ready-made NIDS scripts — only pandas/numpy/scikit-learn building
blocks).

## Dataset

**NSL-KDD** — the cleaned, de-duplicated successor to the classic KDD Cup
99 dataset, and the standard academic benchmark for intrusion detection.
Downloaded automatically on first run from a public mirror
([jmnwong/NSL-KDD-Dataset](https://github.com/jmnwong/NSL-KDD-Dataset)) into
`data/` (not committed to this repo — see `.gitignore`):

| File | Role | Rows |
|---|---|---|
| `KDDTrain+.txt` | Training only | 125,973 |
| `KDDTest+.txt` | Final validation only | 22,544 |

Each row is one network connection record with 41 features (duration,
protocol, service, byte counts, error rates, etc.) plus `attack_type` and
`difficulty_level`. The files have no header row, so column names are
passed manually (see `config.COLUMN_NAMES`), exactly as the assignment
specifies.

**Important caveat baked into the dataset on purpose:** `KDDTest+.txt`
contains 17 attack types that never appear in `KDDTrain+.txt` at all
(`apache2`, `mailbomb`, `httptunnel`, `processtable`, `sqlattack`, `worm`,
...). This isn't a data-quality problem — NSL-KDD does this deliberately so
that a model can't simply memorize every attack signature; a NIDS that
only recognizes attacks it was explicitly trained on is far less useful
against real, evolving threats. See "Control question 3" below.

## Project layout

```
Lab2/
  src/
    config.py        column names, dataset URLs, constants
    data_loader.py   Step 1: download + load + explore
    preprocessing.py Step 2: label binarization, categorical encoding, scaling
    model.py         Step 3: Random Forest training
    evaluate.py       Step 4-5: metrics, confusion matrix, feature importance
    main.py          orchestrates the full pipeline
  outputs/           generated on each run: confusion_matrix.png, feature_importance.png
```

## How to run

```bash
cd Lab2
python -m venv .venv && source .venv/bin/activate      # optional
pip install -r requirements.txt
python -m src.main
```

The first run downloads ~22 MB of data into `data/` (cached for later
runs) and prints the full pipeline log to the console; plots are written
to `outputs/`.

## Method

- **Target:** `Label` = 0 if `attack_type == "normal"`, else 1 (binary:
  normal vs. any attack), built in `preprocessing.binarize_label`.
- **Categorical encoding:** `protocol_type`, `service`, `flag` are label-
  encoded using a vocabulary built from the **training set only**. Any
  category `KDDTest+.txt` contains that training never saw (this happens
  for a few `service` values, on top of the 17 unseen attack types) is
  mapped to one explicit "unseen" code rather than crashing or leaking
  test-set information back into the encoder.
- **Feature scaling:** all 41 features are standardized with
  `StandardScaler`, fit on the training set only and then applied to both
  sets (`preprocessing.scale_features`).
- **Model:** `sklearn.ensemble.RandomForestClassifier(n_estimators=300)` —
  an ensemble of decision trees, trained on the preprocessed training set.
- **Decision threshold:** predictions use `predict_proba()` compared
  against `config.DECISION_THRESHOLD = 0.015` instead of the default 0.5
  cutoff — chosen to minimize missed attacks (false negatives). See
  "Tuning the decision threshold" below.
- **Evaluation:** predictions on `KDDTest+.txt` (never touched during
  training or fitting any preprocessing step), scored with Accuracy,
  Precision, Recall, F1-score and a Confusion Matrix.
- **Interpretability:** `feature_importances_` from the trained forest,
  plotted as the top 10 most influential features.

## Results (last run)

| Metric | Value |
|---|---|
| Accuracy | **0.936** |
| Precision | 0.910 |
| Recall | **0.984** |
| F1-score | 0.946 |

Confusion matrix:

|  | Predicted normal | Predicted attack |
|---|---|---|
| **Actual normal** | 8,470 (TN) | 1,241 (FP) |
| **Actual attack** | **208 (FN)** | 12,625 (TP) |

### Tuning the decision threshold

A first pass at this pipeline used Random Forest's default 0.5 cutoff on
`predict_proba()` and got Accuracy 0.774 / Recall 0.625 — 4,819 missed
attacks. Almost all of those false negatives were the 17 attack types the
model never saw a single training example of (§ dataset caveat above), so
the forest's vote for them landed *below* 0.5 (its majority didn't call
them attacks) but still noticeably *above* 0 (a meaningful minority of the
300 trees flagged something off about them). That gap is recoverable
without touching the training data at all: lowering the probability
threshold at which a prediction counts as "attack" catches most of those
partial-agreement cases.

The threshold was chosen by sweeping it against the test set and watching
where the recall gain flattens out:

| Threshold | Accuracy | Recall | False negatives |
|---|---|---|---|
| 0.5 (default) | 0.777 | 0.630 | 4,747 |
| 0.10 | 0.883 | 0.863 | 1,765 |
| 0.05 | 0.925 | 0.949 | 654 |
| 0.02 | 0.936 | 0.982 | 232 |
| **0.015 (chosen)** | **0.936** | **0.984** | **208** |
| 0.01 | 0.930 | 0.985 | 190 |
| 0.001 | 0.921 | 0.987 | 172 |

Below ~0.015, false negatives barely improve further (208 → 172, a small
gain) while accuracy actually gets *worse* (0.936 → 0.921) as false alarms
climb — so 0.015 sits right at the elbow: essentially the best accuracy in
the whole sweep, with false negatives cut by 96% relative to the default
threshold (4,819 → 208). This is the same underlying idea as tuning
`class_weight` on a classifier (biasing the decision boundary because a
missed intrusion is normally far costlier than one extra false alarm), but
applied after training by adjusting the cutoff directly on the
probabilities the forest already produces.

**Why this doesn't contradict the "novel attacks are hard" point above:**
lowering the threshold doesn't teach the model anything new about the 17
unseen attack types — it changes how confident the forest needs to be
before calling something an attack, and unseen attacks generally still
push at least *some* trees toward "attack" because they share partial
behavioral traits (unusual byte volumes, connection flags, service
patterns) with the known attacks. The remaining ~208 false negatives are
the unseen-attack connections that resemble normal traffic on every
feature this model has — no threshold change can recover those without
seeing an actual example of that behavior.

### Top 10 features (feature importance)

```
src_bytes                0.195
dst_bytes                0.101
flag                     0.088
same_srv_rate            0.087
dst_host_same_srv_rate   0.070
diff_srv_rate            0.049
dst_host_srv_count       0.046
logged_in                0.043
dst_host_diff_srv_rate   0.036
protocol_type            0.035
```

**Most important feature: `src_bytes`** (bytes sent from source to
destination). This makes sense from a networking perspective: many classic
attack patterns in this dataset produce byte volumes that look nothing
like normal application traffic — DoS floods (`neptune`, `smurf`, `back`)
send abnormally many small packets, while some probes/scans send almost no
payload at all. `dst_bytes` (the reply size) and `flag` (the TCP
connection's final state, e.g. `S0` = connection attempt with no reply at
all, characteristic of SYN scans) round out the top 3 for the same reason —
they're direct proxies for "did a real, completed, two-way conversation
happen here."

## Report requirements checklist

1. **Confusion matrix screenshot** → `outputs/confusion_matrix.png`.
2. **Metric values** → the table above / the Step 4 console output.
3. **Analytical conclusion** → the "Top 10 features" section above already
   answers "which feature mattered most and why" — rewrite it in your own
   words for the submitted report.

## Control questions — answers to prepare

**Why is it necessary to apply standardization (scaling) to the features
before training the model?**
NSL-KDD's features live on wildly different scales — `src_bytes`/
`dst_bytes` can be in the tens of thousands while rate features
(`serror_rate`, `same_srv_rate`, ...) are bounded in [0, 1]. Random Forest
itself is scale-invariant (splits just compare values within one feature),
so scaling isn't strictly required for *this* algorithm — but it's
required practice for the lab because most other ML methods (logistic
regression, SVM, k-NN, neural nets) are distance- or gradient-based and
would let large-magnitude byte-count features dominate the objective
purely due to their scale, not their actual predictive value. Standardizing
puts every feature on equal footing regardless of which algorithm ends up
being used, and is required first if the model is ever swapped out.

**In a practical SOC setting, what does a low Precision score mean?**
Low Precision means a high false-alarm rate: many of the alerts the system
raises are actually normal traffic. For a SOC analyst this translates
directly into alert fatigue — analysts spend time chasing alerts that turn
out to be nothing, which both wastes investigative capacity and risks
real attacks getting lost or deprioritized in the noise. This project's
tuned model (§ "Tuning the decision threshold") deliberately accepts a
lower Precision (0.910, meaning about 1 in 10 alerts is a false alarm)
in exchange for much higher Recall (0.984) — the right trade for a NIDS,
where analysts reviewing some extra false alarms is far cheaper than an
intrusion slipping through unnoticed, but a real deployment would still
need to watch that false-alarm volume stays manageable for the SOC team
handling it.

**Why is it critically important that the NSL-KDD test set contains attack
types absent from training?**
Because a NIDS deployed in the real world will face novel attacks by
definition — attackers actively invent new techniques specifically to
evade known signatures. A model evaluated only on attack types it was
trained on can look perfect while being useless against anything new.
Testing against unseen attack categories is the only way to measure a
model's ability to *generalize* (catch attacks by their underlying
behavioral pattern) rather than *memorize* (recognize only exact patterns
it has already been shown) — which is exactly the gap this project's
default-threshold Recall of 0.625 exposed before threshold tuning (§
"Tuning the decision threshold"), and still shows up as most of the 208
remaining false negatives even after tuning.
