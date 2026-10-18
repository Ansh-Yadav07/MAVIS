"""CICFlowMeter flow data: column schema, label normalisation and CSV loading.

CIC-IDS2017, CSE-CIC-IDS2018 and flows extracted from your own pcaps with
CICFlowMeter all describe the same flow features, but spell the column names
differently. Every file is renamed to the CIC-IDS2017 names so that all of
them can be stacked into one table and fed to the same models.
"""
import re
from pathlib import Path

import numpy as np
import pandas as pd

LABEL = 'Label'

# The 77 CICFlowMeter features, in CIC-IDS2017 spelling. 'Fwd Header Length.1'
# is left out on purpose: it is an exact copy of 'Fwd Header Length'.
FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
]

# CSE-CIC-IDS2018 / CICFlowMeter-V4 spellings that differ from CIC-IDS2017.
# The Python 'cicflowmeter' package uses the same words in snake_case
# (e.g. tot_fwd_pkts), which matches once names are normalised by _key().
_ALIASES = {
    'Dst Port': 'Destination Port',
    'Tot Fwd Pkts': 'Total Fwd Packets',
    'Tot Bwd Pkts': 'Total Backward Packets',
    'TotLen Fwd Pkts': 'Total Length of Fwd Packets',
    'TotLen Bwd Pkts': 'Total Length of Bwd Packets',
    'Fwd Pkt Len Max': 'Fwd Packet Length Max',
    'Fwd Pkt Len Min': 'Fwd Packet Length Min',
    'Fwd Pkt Len Mean': 'Fwd Packet Length Mean',
    'Fwd Pkt Len Std': 'Fwd Packet Length Std',
    'Bwd Pkt Len Max': 'Bwd Packet Length Max',
    'Bwd Pkt Len Min': 'Bwd Packet Length Min',
    'Bwd Pkt Len Mean': 'Bwd Packet Length Mean',
    'Bwd Pkt Len Std': 'Bwd Packet Length Std',
    'Flow Byts/s': 'Flow Bytes/s',
    'Flow Pkts/s': 'Flow Packets/s',
    'Fwd IAT Tot': 'Fwd IAT Total',
    'Bwd IAT Tot': 'Bwd IAT Total',
    'Fwd Header Len': 'Fwd Header Length',
    'Bwd Header Len': 'Bwd Header Length',
    'Fwd Pkts/s': 'Fwd Packets/s',
    'Bwd Pkts/s': 'Bwd Packets/s',
    'Pkt Len Min': 'Min Packet Length',
    'Pkt Len Max': 'Max Packet Length',
    'Pkt Len Mean': 'Packet Length Mean',
    'Pkt Len Std': 'Packet Length Std',
    'Pkt Len Var': 'Packet Length Variance',
    'FIN Flag Cnt': 'FIN Flag Count',
    'SYN Flag Cnt': 'SYN Flag Count',
    'RST Flag Cnt': 'RST Flag Count',
    'PSH Flag Cnt': 'PSH Flag Count',
    'ACK Flag Cnt': 'ACK Flag Count',
    'URG Flag Cnt': 'URG Flag Count',
    'ECE Flag Cnt': 'ECE Flag Count',
    'Pkt Size Avg': 'Average Packet Size',
    'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
    'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
    'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
    'Fwd Pkts/b Avg': 'Fwd Avg Packets/Bulk',
    'Fwd Blk Rate Avg': 'Fwd Avg Bulk Rate',
    'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Pkts/b Avg': 'Bwd Avg Packets/Bulk',
    'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
    'Subflow Fwd Pkts': 'Subflow Fwd Packets',
    'Subflow Fwd Byts': 'Subflow Fwd Bytes',
    'Subflow Bwd Pkts': 'Subflow Bwd Packets',
    'Subflow Bwd Byts': 'Subflow Bwd Bytes',
    'Init Fwd Win Byts': 'Init_Win_bytes_forward',
    'Init Bwd Win Byts': 'Init_Win_bytes_backward',
    'Fwd Act Data Pkts': 'act_data_pkt_fwd',
    'Fwd Seg Size Min': 'min_seg_size_forward',
}


def _key(name):
    """Spelling-insensitive column key: ' Flow Byts/s' and 'flow_byts_s' both -> 'flowbytss'."""
    return re.sub(r'[^a-z0-9]', '', str(name).lower())


_CANONICAL = {_key(c): c for c in FEATURES + [LABEL]}
_CANONICAL.update({_key(alias): c for alias, c in _ALIASES.items()})


def canonical_column(name):
    """CIC-IDS2017 name for a column, or None if it is not a model feature/label."""
    return _CANONICAL.get(_key(name))


def clean_label(raw):
    """Fix the mis-encoded dash and stray spaces in CIC labels.

    The 2017 CSVs store 'Web Attack – Brute Force' with a cp1252 en dash, which
    shows up as '\\x96', '–' or '\\ufffd' depending on how the file is decoded.
    """
    text = re.sub('[\x96–—�]', '-', str(raw).strip())
    return re.sub(r'\s+', ' ', text)


# Ordered rules: the first match wins ('Brute Force -Web' is a web attack,
# 'DDoS' must be tested before 'DoS').
_CATEGORY_RULES = [
    ('Benign', ('benign',)),
    ('WebAttack', ('web', 'xss', 'sql')),
    ('DDoS', ('ddos',)),
    ('DoS', ('dos', 'hulk', 'goldeneye', 'slowloris', 'slowhttp')),
    ('PortScan', ('portscan', 'port scan')),
    ('BruteForce', ('patator', 'brute')),
    ('Bot', ('bot',)),
    ('Infiltration', ('infilt',)),
    ('Heartbleed', ('heartbleed',)),
]


def attack_category(label):
    """Group a fine-grained label (e.g. 'DoS Hulk') into an attack family (e.g. 'DoS')."""
    low = label.lower()
    for category, keywords in _CATEGORY_RULES:
        if any(k in low for k in keywords):
            return category
    return 'Other'


def load_flow_csv(path, max_rows=None):
    """Load one CICFlowMeter CSV as float32 features plus label metadata.

    Returns a DataFrame with the FEATURES columns followed by 'Label',
    'category', 'is_attack' and 'source' (the file name).
    """
    path = Path(path)
    df = pd.read_csv(path, encoding='latin-1', low_memory=False, nrows=max_rows)
    df = df.rename(columns=lambda c: canonical_column(c) or c)
    df = df.loc[:, ~df.columns.duplicated()]

    missing = [c for c in FEATURES + [LABEL] if c not in df.columns]
    if missing:
        raise ValueError(f"{path.name}: missing {len(missing)} expected columns, e.g. {missing[:5]}")

    # CSE-CIC-IDS2018 files repeat the header row in the middle of the data.
    df = df[df[LABEL].astype(str).str.strip() != LABEL]

    out = df[FEATURES].apply(pd.to_numeric, errors='coerce').astype(np.float32)
    labels = df[LABEL].map(clean_label)
    out[LABEL] = labels.values
    out['category'] = labels.map(attack_category).values
    out['is_attack'] = (out['category'] != 'Benign').astype(np.int8)
    out['source'] = path.name
    return out.reset_index(drop=True)


def find_flow_csvs(root, exclude=None):
    """All CSV files under root (recursively), sorted, skipping anything under exclude."""
    root = Path(root)
    exclude = Path(exclude).resolve() if exclude else None
    files = []
    for p in sorted(root.rglob('*.csv')):
        if exclude and exclude in p.resolve().parents:
            continue
        files.append(p)
    return files
