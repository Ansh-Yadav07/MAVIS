"""Convert MAVIS engine output into the JSON the analyst console (frontend/) reads.

The same payload shape is produced for the committed snapshot (scripts/export_frontend.py)
and for live uploads (scripts/serve.py, POST /api/analyze), so the console renders both
with one code path. Field names follow frontend/src/data/index.js.
"""
import numpy as np
import pandas as pd

from data.cic import attack_category

from .engine import MODEL_NAMES, VOTE_PCT
from .knowledge import THREATS
from .report import analyze

# Engine model ids -> console ids.
UI_ID = {'iforest': 'if', 'lof': 'lof', 'ae': 'ae'}
SEVERITY_UI = {'Critical': 'critical', 'High': 'high', 'Medium': 'medium', 'Low': 'low', 'None': 'none'}
FEATURE_KEYS = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Flow Bytes/s', 'Flow Packets/s',
    'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Flow IAT Mean', 'SYN Flag Count',
    'PSH Flag Count', 'Init_Win_bytes_forward', 'Down/Up Ratio',
]
SERVICES = {21: 'FTP', 22: 'SSH', 53: 'DNS', 80: 'HTTP', 123: 'NTP', 137: 'NetBIOS', 139: 'SMB', 443: 'HTTPS',
            444: 'Meterpreter', 445: 'SMB', 8080: 'HTTP-alt', 3268: 'LDAP-GC', 389: 'LDAP'}
TIMELINE_BINS = 48


def service_for(port):
    if port is None or not np.isfinite(port):
        return 'Unknown'
    port = int(port)
    return SERVICES.get(port, 'Well-known' if port < 1024 else 'Ephemeral')


def baseline_medians(engine):
    """Benign median of every feature in raw units (inverse of the preprocessor's signed log)."""
    m = engine.preprocessor.medians_
    return {f: float(np.sign(v) * np.expm1(abs(v))) for f, v in m.items()}


def native_cutoffs(engine):
    """Each model's raw score at its vote percentile: the per-model cut-off the console draws."""
    out = {}
    for n in MODEL_NAMES:
        pm = engine.maps[n]
        out[UI_ID[n]] = float(np.interp(VOTE_PCT, pm.p, pm.x))
    return out


def _num(v, nd=4):
    if v is None:
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return round(f, nd) if np.isfinite(f) else None


def flow_records(engine, flows, internals, rows, id_prefix, day=None, file=None, explain=True):
    """Console flow objects for the given row positions."""
    X, raw, feats, ctx = internals['X'], internals['raw_scores'], internals['features'], internals['context']
    base = baseline_medians(engine)
    why = engine.explain(X, rows) if explain and len(rows) else [None] * len(rows)
    out = []
    for r, reasons in zip(rows, why):
        f = flows.iloc[r]
        fe = feats.iloc[r]
        c = ctx.iloc[r] if len(ctx.columns) else pd.Series(dtype=object)
        label = c.get('label') if 'label' in c else None
        family = f['threat_family'] or None
        info = THREATS.get(family) if family else None
        dst_port = _num(c.get('dst_port'), 0) if 'dst_port' in c else None
        flags = {UI_ID[n]: bool(f[f'pct_{n}'] >= VOTE_PCT) for n in MODEL_NAMES}
        rec = {
            'id': f'{id_prefix}{r}',
            'row': int(r),
            'day': day,
            'file': file,
            'ts': str(c['timestamp']) if 'timestamp' in c and pd.notna(c['timestamp']) else None,
            'src': {'ip': c.get('src_ip') if 'src_ip' in c else None,
                    'port': _num(c.get('src_port'), 0) if 'src_port' in c else None},
            'dst': {'ip': c.get('dst_ip') if 'dst_ip' in c else None,
                    'port': int(dst_port) if dst_port is not None else None},
            'proto': {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(_num(c.get('protocol'), 0)) if 'protocol' in c else None,
            'service': service_for(dst_port if dst_port is not None else np.nan),
            'durationUs': _num(fe.get('Flow Duration'), 0),
            'packets': _num((fe.get('Total Fwd Packets') or 0) + (fe.get('Total Backward Packets') or 0), 0),
            'bytes': _num((fe.get('Total Length of Fwd Packets') or 0) + (fe.get('Total Length of Bwd Packets') or 0), 0),
            'features': {k: _num(fe.get(k)) for k in FEATURE_KEYS},
            'label': label,
            'category': attack_category(label) if label else None,
            'scores': {UI_ID[n]: _num(raw[n][r], 5) for n in MODEL_NAMES},
            'pct': {UI_ID[n]: _num(f[f'pct_{n}'], 5) for n in MODEL_NAMES},
            'flags': flags,
            'agree': int(sum(flags.values())),
            'risk': _num(f['risk_score'], 1),
            'severity': SEVERITY_UI[f['severity']],
            'verdict': f['verdict'],
            'family': family,
            'familyTitle': info['title'] if info else None,
            'mode': f['detection_mode'] or None,
            'confidence': f['confidence'] or None,
            'pKnown': _num(f['p_known_attack']),
            'predictedType': f['predicted_type'],
            'typeConfidence': _num(f['type_confidence'], 3),
            'novelty': _num(f['novelty'], 3),
            'anomalyPct': _num(f['anomaly_percentile'], 5),
            'votes': int(f['model_votes']),
            'status': 'New' if f['verdict'] != 'normal' else 'Closed',
            'why': [{**w, 'value': _num(fe.get(w['feature'])), 'baseline': _num(base.get(w['feature']))}
                    for w in reasons] if reasons else [],
            'mitre': [{'tactic': t, 'technique': tech} for t, tech in info['mitre']] if info else [],
            'actions': info['actions'] if info else [],
        }
        if label is not None:
            rec['outcome'] = ('TP' if f['verdict'] != 'normal' else 'FN') if rec['category'] != 'Benign' \
                else ('FP' if f['verdict'] != 'normal' else 'TN')
        out.append(rec)
    return out


def pick_rows(flows, labels, rng, per_family=120, normals=150, misses=25, false_pos=40, top=40):
    """A readable sample: top risks, alerts of every family, misses, false positives and normal traffic."""
    n = len(flows)
    alert = (flows['verdict'] != 'normal').to_numpy()
    by_risk = np.argsort(-flows['risk_score'].to_numpy())[:top]
    chosen = set(by_risk[alert[by_risk]])
    fam = flows['threat_family'].to_numpy()
    for f in pd.unique(fam[alert]):
        idx = np.flatnonzero(alert & (fam == f))
        chosen.update(rng.choice(idx, min(per_family, len(idx)), replace=False))
    normal_idx = np.flatnonzero(~alert)
    if labels is not None:
        cats = labels.to_numpy()
        benign = cats == 'Benign'
        for c in pd.unique(cats[~benign]):
            idx = np.flatnonzero((cats == c) & ~alert)
            chosen.update(rng.choice(idx, min(misses, len(idx)), replace=False))
        idx = np.flatnonzero(benign & alert)
        chosen.update(rng.choice(idx, min(false_pos, len(idx)), replace=False))
        normal_idx = np.flatnonzero(benign & ~alert)
    chosen.update(rng.choice(normal_idx, min(normals, len(normal_idx)), replace=False))
    return np.array(sorted(int(i) for i in chosen if i < n))


def timeline(flows, labels, bins=TIMELINE_BINS):
    """Alerts per slice of the capture, in file order (the public CSVs carry no timestamps)."""
    n = len(flows)
    edges = np.linspace(0, n, bins + 1).astype(int)
    alert = (flows['verdict'] != 'normal').to_numpy()
    fam = flows['threat_family'].to_numpy()
    cats = labels.to_numpy() if labels is not None else None
    out = []
    for a, b in zip(edges[:-1], edges[1:]):
        seg = slice(a, b)
        fams = pd.Series(fam[seg][alert[seg]]).value_counts().to_dict()
        item = {'start': int(a), 'end': int(b), 'flows': int(b - a), 'alerts': int(alert[seg].sum()), 'families': fams}
        if cats is not None:
            item['attacks'] = int((cats[seg] != 'Benign').sum())
        out.append(item)
    return out


def build_payload(engine, raw_df, day=None, file=None, id_prefix='', seed=42, sample=None):
    """Analyse one batch of raw flows and return the console payload for it."""
    internals = {}
    report, flows = analyze(engine, raw_df, max_explanations=0, internals=internals)
    if not internals:
        return {'summary': report['summary'], 'flows': [], 'incidents': [], 'insights': report['insights'],
                'drift': report['drift'], 'data_quality': report['data_quality'], 'timeline': []}
    labels = flows['label'].map(attack_category) if 'label' in flows else None
    rng = np.random.default_rng(seed)
    rows = pick_rows(flows, labels, rng, **(sample or {}))
    report['summary']['severity'] = {SEVERITY_UI[k]: v for k, v in report['summary']['severity'].items()}
    if labels is not None:
        report['summary']['categories'] = labels.value_counts().to_dict()
    return {
        'day': day, 'file': file,
        'summary': report['summary'],
        'incidents': report['incidents'],
        'insights': report['insights'],
        'drift': report['drift'],
        'data_quality': report['data_quality'],
        'ground_truth': report.get('ground_truth'),
        'timeline': timeline(flows, labels),
        'flows': flow_records(engine, flows, internals, rows, id_prefix, day=day, file=file),
    }


def engine_meta(engine):
    """Static facts about the trained engine for the Models / Settings views."""
    m = engine.models
    params = {
        'if': {k: v for k, v in m['iforest'].model.get_params().items()
               if k in ('n_estimators', 'max_samples', 'max_features', 'bootstrap', 'contamination')},
        'lof': {k: v for k, v in m['lof'].model.get_params().items()
                if k in ('n_neighbors', 'metric', 'leaf_size', 'contamination', 'novelty')},
        'ae': {'input_dim': m['ae'].input_dim, **{k: (list(v) if isinstance(v, tuple) else v)
                                                  for k, v in m['ae'].config.items()}},
    }
    if hasattr(m['lof'], 'max_train_samples'):
        params['lof']['max_train_samples'] = m['lof'].max_train_samples
    return {
        'alertBudgetFpr': engine.target_fpr,
        'thresholds': engine.alert_threshold,
        'budgets': {str(k): v for k, v in getattr(engine, 'budget_table', {}).items()},
        'votePercentile': VOTE_PCT,
        'cutoffs': native_cutoffs(engine),
        'classes': engine.classes_,
        'synthetic_rows': engine.meta.get('synthetic_rows', {}),
        'features': engine.features,
        'baseline': {k: round(v, 4) for k, v in baseline_medians(engine).items() if k in FEATURE_KEYS},
        'params': params,
        'threats': {k: {**v, 'mitre': [{'tactic': t, 'technique': x} for t, x in v['mitre']]}
                    for k, v in THREATS.items()},
    }
