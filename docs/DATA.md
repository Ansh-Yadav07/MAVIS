# MAVIS data: collection and preprocessing

## 1. Collect

Everything MAVIS reads is **CICFlowMeter flow CSVs**: one row per network flow,
77 numeric features and a `Label` column. Any source that produces them works,
and they can all be mixed because the loader renames columns to the
CIC-IDS2017 spelling (`src/data/cic.py`).

Put the CSVs anywhere under `dataset/` (gitignored, searched recursively):

```text
dataset/
├── cic-ids2017/          # MachineLearningCSV.zip, the 8 *.pcap_ISCX.csv files
├── cse-cic-ids2018/      # optional: same features, a second network and year
└── lab/                  # optional: your own labelled captures
```

| Source | Where | Notes |
|---|---|---|
| **CIC-IDS2017** (have it) | https://www.unb.ca/cic/datasets/ids-2017.html, `MachineLearningCSV.zip` | Monday is 100 % benign: the anomaly-mode training day. |
| **CSE-CIC-IDS2018** (add next) | https://www.unb.ca/cic/datasets/ids-2018.html. CSVs on AWS: `aws s3 sync --no-sign-request "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/" dataset/cse-cic-ids2018/` | Same features, different spelling (`Tot Fwd Pkts`…); handled by the alias table. Use it to test whether a model trained on 2017 generalises. |
| **CIC-DDoS2019** | https://www.unb.ca/cic/datasets/ddos-2019.html | Many DDoS variants, CICFlowMeter features. |
| **Your own lab** | see below | Your own benign baseline and attacks. |

UNSW-NB15 (already profiled in `reports/raw_data_profile.json`) has a different
feature set and is **not** loaded by this pipeline; keep it as a separate experiment.

### Your own captures

1. Capture traffic on the lab network: `sudo tcpdump -i <iface> -w capture.pcap`.
2. Convert packets to flows with CICFlowMeter, either the Java tool
   (https://github.com/ahlashkari/CICFlowMeter) or `pip install cicflowmeter`
   and then `cicflowmeter -f capture.pcap -c flows.csv`.
3. Add labels. You know the attacker's IP, so:
   `python scripts/label_flows.py flows.csv dataset/lab/portscan.csv --attacker-ip 192.168.56.10 --label PortScan`

The alias table covers CIC-IDS2017, CSE-CIC-IDS2018 and the Python
`cicflowmeter` spelling. If a file fails with "missing expected columns", add
its spellings to `_ALIASES` in `src/data/cic.py`.

## 2. Preprocess

```bash
pip install -r requirements.txt
python scripts/preprocess.py                       # anomaly mode -> <data folder>/processed/
python scripts/preprocess.py --mode supervised --out-dir dataset/processed_supervised
python scripts/preprocess.py --max-rows-per-file 50000   # quick run on a small laptop
```

What happens, in order:

1. **Load**: column names stripped and aliased, labels fixed (`Web Attack � XSS` becomes
   `Web Attack - XSS`), features stored as float32, and each row tagged with its attack
   `category` (DoS, DDoS, PortScan, BruteForce, WebAttack, Bot, Infiltration,
   Heartbleed, Benign), `is_attack` and `source` file.
2. **Clean**: drop rows with NaN/inf features (zero-duration flows give an infinite
   `Flow Bytes/s`) and exact duplicates. The number of flows whose identical features
   carry different labels is recorded in the report.
3. **Drop columns**: `Fwd Header Length.1` (a copy of `Fwd Header Length`), columns
   that are constant in the whole corpus, and optionally `Destination Port`
   (`--drop-port`, so a classifier can't simply memorise ports).
4. **Split**:
   - `anomaly`: train = benign flows from Monday, val = 15 % of those benign
     flows (for choosing score thresholds without using attack labels),
     test = every other file.
   - `supervised`: stratified 70 / 15 / 15 by attack category over all files.
5. **Scale**: `sign(x)·log(1+|x|)`, then standardisation, **fitted on train only**.
   The fitted `preprocessor.joblib` is saved so the same transform runs on test
   data and later on live flows. Missing values seen at that point get the
   training median instead of crashing.

Outputs in `--out-dir`: `train/val/test.parquet` (scaled features plus `Label`,
`category`, `is_attack`, `source`), `preprocessor.joblib` and
`preprocess_report.json`. A copy of the report goes to
`reports/preprocess_report_<mode>.json`, which is small enough to commit.

Loading a split for training:

```python
from data import load_split          # with src/ on sys.path
X_train, meta_train = load_split('dataset/processed', 'train')
```

Run the tests with `python -m pytest tests`.
