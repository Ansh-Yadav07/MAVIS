import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from data.cic import _ALIASES, FEATURES, attack_category, canonical_column, clean_label, load_flow_csv  # noqa: E402
from data.preprocess import FlowPreprocessor, load_split, run  # noqa: E402

RAW_2017_COLUMNS = FEATURES[:55] + ['Fwd Header Length.1'] + FEATURES[55:] + ['Label']


def _flows(n, labels, seed):
    rng = np.random.default_rng(seed)
    data = {c: rng.integers(0, 1000, n).astype(float) for c in FEATURES}
    data['Bwd PSH Flags'] = np.zeros(n)  # constant, like the real files
    data['Init_Win_bytes_forward'] = rng.choice([-1, 0, 8192, 29200], n)
    df = pd.DataFrame(data)
    df['Label'] = rng.choice(labels, n)
    return df


def _write_2017(path, df):
    """Write like the CIC-IDS2017 MachineLearningCSV files: ' Name' headers, cp1252 dash."""
    df = df.copy()
    df.insert(55, 'Fwd Header Length.1', df['Fwd Header Length'])
    df.columns = [' ' + c if i else c for i, c in enumerate(RAW_2017_COLUMNS)]
    df.to_csv(path, index=False, encoding='cp1252')


@pytest.fixture
def raw_dir(tmp_path):
    raw = tmp_path / 'dataset'
    raw.mkdir()

    monday = _flows(400, ['BENIGN'], seed=1)
    monday.loc[0, 'Flow Bytes/s'] = np.inf
    monday.loc[1, 'Flow Bytes/s'] = np.nan
    monday = pd.concat([monday, monday.iloc[2:7]])  # 5 duplicates
    _write_2017(raw / 'Monday-WorkingHours.pcap_ISCX.csv', monday)

    thursday = _flows(300, ['BENIGN', 'Web Attack – Brute Force', 'Web Attack – XSS'], seed=2)
    _write_2017(raw / 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv', thursday)

    # CSE-CIC-IDS2018 spelling, extra columns, and a repeated header row mid-file.
    reverse = {v: k for k, v in _ALIASES.items()}
    feb = _flows(300, ['Benign', 'DDOS attack-HOIC', 'SSH-Bruteforce'], seed=3)
    feb = feb.rename(columns=lambda c: reverse.get(c, c))
    feb.insert(1, 'Protocol', 6)
    feb.insert(2, 'Timestamp', '15/02/2018 08:25:18')
    header = pd.DataFrame([feb.columns], columns=feb.columns)
    feb = pd.concat([feb.iloc[:100], header, feb.iloc[100:]])
    feb.to_csv(raw / '02-15-2018.csv', index=False)
    return raw


def test_labels_and_categories():
    assert clean_label(' Web Attack \x96 Brute Force ') == 'Web Attack - Brute Force'
    assert clean_label('Web Attack � XSS') == 'Web Attack - XSS'
    cases = {
        'BENIGN': 'Benign', 'DDoS': 'DDoS', 'DoS Hulk': 'DoS', 'DoS slowloris': 'DoS', 'PortScan': 'PortScan',
        'FTP-Patator': 'BruteForce', 'SSH-Bruteforce': 'BruteForce', 'Brute Force -Web': 'WebAttack',
        'Web Attack - Sql Injection': 'WebAttack', 'Bot': 'Bot', 'Infilteration': 'Infiltration',
        'Heartbleed': 'Heartbleed', 'DDOS attack-LOIC-UDP': 'DDoS', 'DoS attacks-SlowHTTPTest': 'DoS',
    }
    for label, category in cases.items():
        assert attack_category(label) == category, label


def test_column_aliases():
    assert canonical_column(' Flow Bytes/s') == 'Flow Bytes/s'
    assert canonical_column('Flow Byts/s') == 'Flow Bytes/s'
    assert canonical_column('flow_byts_s') == 'Flow Bytes/s'
    assert canonical_column('Init Fwd Win Byts') == 'Init_Win_bytes_forward'
    assert canonical_column('Fwd Header Length.1') is None
    assert canonical_column('Timestamp') is None


def test_load_both_spellings(raw_dir):
    a = load_flow_csv(raw_dir / 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv')
    b = load_flow_csv(raw_dir / '02-15-2018.csv')
    assert list(a.columns) == list(b.columns)
    assert len(b) == 300  # repeated header row dropped
    assert set(a['Label']) <= {'BENIGN', 'Web Attack - Brute Force', 'Web Attack - XSS'}
    assert a[FEATURES].dtypes.eq(np.float32).all()


def test_anomaly_run(raw_dir, tmp_path):
    out = tmp_path / 'processed'
    report = run(raw_dir, out, mode='anomaly', log=lambda *_: None)

    assert report['rows_dropped_nan_or_inf'] == 2
    assert report['rows_dropped_duplicate'] == 5
    assert 'Bwd PSH Flags' in report['dropped_columns']

    X_train, m_train = load_split(out, 'train')
    X_val, m_val = load_split(out, 'val')
    X_test, m_test = load_split(out, 'test')
    assert set(m_train['source']) == set(m_val['source']) == {'Monday-WorkingHours.pcap_ISCX.csv'}
    assert m_train['is_attack'].sum() == 0 and m_val['is_attack'].sum() == 0
    assert 'Monday-WorkingHours.pcap_ISCX.csv' not in set(m_test['source'])
    assert m_test['is_attack'].sum() > 0
    assert len(m_train) + len(m_val) == 400 - 2  # 405 written, -2 NaN/inf, -5 duplicates
    assert list(X_train.columns) == report['features'] == list(X_test.columns)
    np.testing.assert_allclose(X_train.mean(), 0, atol=1e-5)
    assert np.isfinite(X_test.to_numpy()).all()


def test_supervised_run(raw_dir, tmp_path):
    out = tmp_path / 'processed'
    report = run(raw_dir, out, mode='supervised', drop_port=True, log=lambda *_: None)
    assert 'Destination Port' in report['dropped_columns']
    cats = {name: set(s['categories']) for name, s in report['splits'].items()}
    assert cats['train'] == cats['val'] == cats['test'] == {'Benign', 'WebAttack', 'DDoS', 'BruteForce'}


def test_preprocessor_roundtrip_and_bad_values(raw_dir, tmp_path):
    df = load_flow_csv(raw_dir / 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv')
    pre = FlowPreprocessor(drop_columns=['Bwd PSH Flags']).fit(df)
    pre.save(tmp_path / 'pre.joblib')
    loaded = FlowPreprocessor.load(tmp_path / 'pre.joblib')

    live = df.head(3).copy()
    live.loc[0, 'Flow Bytes/s'] = np.inf  # zero-duration flow seen live
    out = loaded.transform(live)
    assert np.isfinite(out.to_numpy()).all()
    assert 'Bwd PSH Flags' not in out.columns
