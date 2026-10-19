# MAVIS model card

## Intended use

MAVIS helps security analysts triage network flows. It scores each flow for how
unusual it is (novelty) and whether it looks like a known attack family
(recognition), then ranks flows by risk. It is a decision aid for a person, not
an inline blocker: it does not sit in the traffic path, and its alerts should be
reviewed before any response action. The optional response module can change
firewall rules, so keep it in dry-run mode unless you have checked the results.

Out of scope: automated blocking without review, use on networks you do not
own or have permission to monitor, and any use as the only control for a
security decision.

## Data

- **Training and evaluation:** CIC-IDS2017 CICFlowMeter CSVs (8 files, lab
  traffic recorded in 2017).
- **Cleaning:** 2,830,743 rows loaded; 2,867 dropped for NaN or infinite values;
  329,896 exact duplicates dropped; 2,497,980 clean rows remain. 718 flows had
  identical features with conflicting labels (recorded, not removed).
- **Anomaly-mode split:** train 418,714 benign rows (Monday only); validation
  73,891 benign rows; thresholds set on a 10% calibration slice of 200,537 rows;
  evaluation on 1,804,838 rows that include every attack category.
- **Supervised classifier:** trained on labelled flows with rare classes
  augmented with synthetic rows.

## Models

- **Isolation Forest, Local Outlier Factor, Autoencoder:** novelty scores,
  each converted to a percentile of benign traffic, then averaged into one
  anomaly score (the "ensemble mean").
- **Gradient-boosted classifier** (scikit-learn `HistGradientBoostingClassifier`):
  names the attack family and gives a probability. It also receives the three
  anomaly percentiles as inputs.
- **Fusion:** likelihood = 1 - (1 - p_known) x (1 - 0.9 x novelty), so either
  view can raise an alert. Thresholds are set for a 1% false-positive budget.

## Results (1% false-positive rate)

Full engine (classifier plus anomaly fusion), from `reports/engine_evaluation.json`:

| Metric | Value |
|---|---|
| ROC-AUC | 0.9995 |
| PR-AUC | 0.9952 |
| Precision | 0.9655 |
| Recall | 0.9996 |
| F1 | 0.9822 |
| False-positive rate | 0.96% |

Anomaly-only (no classifier), from `reports/evaluation_anomaly.json` and
`reports/engine_evaluation.json`:

| Model | ROC-AUC | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| Isolation Forest | 0.952 | 0.088 | 0.003 | 0.007 | 0.98% |
| LOF | 0.903 | 0.712 | 0.091 | 0.161 | 0.99% |
| Autoencoder | 0.951 | 0.813 | 0.160 | 0.268 | 0.99% |
| Ensemble mean | 0.965 | 0.942 | 0.619 | 0.747 | 1.04% |
| Engine, anomaly only | 0.963 | 0.931 | 0.485 | 0.637 | 0.97% |

Zero-day test (each family held out from training; share of flows alerted):

| Held-out family | Alerted | Flagged as novel |
|---|---|---|
| PortScan | 11.7% | 11.2% |
| WebAttack | 26.1% | 0% |
| DDoS | 63.2% | 0.1% |
| BruteForce | 0.3% | 0.2% |
| Bot | 0% | 0% |

Held-out flows are often labelled as a different family. For example, held-out
DDoS was most often named DoS (40,349 of 64,007 flows).

## Caveats

- **Optimistic split:** the anomaly split is by day, but the training benign
  data and the test traffic come from the same week and lab. Random or same-week
  splits flatter the results. Expect lower numbers on a new network.
- **Old lab traffic:** the models learned 2017 lab traffic. Learn on your own
  network before relying on alerts (the console has a live learning mode).
- **Sensor is an approximation:** the live sensor approximates CICFlowMeter, so
  feature values can differ from the training data.
- **Blind spots per flow:** Bot, BruteForce and WebAttack are weak when judged
  one flow at a time. Scans made of many tiny flows are missed by the per-flow
  models; only the fan-out rule catches them.
- **Recall is modest for novel attacks:** at the 1% budget, the anomaly path alone
  catches about half of the attack flows in the evaluation.
- **Thresholds are budget-based:** they are set for about 1% false positives on
  the calibration data, so the real alert volume depends on your traffic.

## Ethical use

Only monitor networks and hosts you own or are explicitly authorised to
monitor. Packet capture can expose personal communications; keep captures
to what the analysis needs and handle them under your organisation's policy.
Do not use alerts as the sole basis for action against a person.
