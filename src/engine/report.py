"""Batch analysis: raw CICFlowMeter flows in, MAVIS threat report out.

Handles messy input (missing or misspelled columns, non-numeric values, inf, no labels) and
adds what an analyst needs beyond per-flow scores: incidents grouped by source, MITRE ATT&CK
context, playbook actions, batch-level insights and a model-health (drift) check.
"""
import numpy as np
import pandas as pd

from data.cic import FEATURES, LABEL, attack_category, canonical_column, clean_label

from .knowledge import THREATS

# Identity columns CICFlowMeter tools emit; kept for incidents, never fed to the models.
_CONTEXT = {
    'src_ip': ('srcip', 'sourceip'),
    'dst_ip': ('dstip', 'destinationip'),
    'src_port': ('srcport', 'sourceport'),
    'protocol': ('protocol',),
    'timestamp': ('timestamp',),
    'flow_id': ('flowid',),
}
_SEVERITY_ORDER = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'None': 0}


def _key(name):
    return ''.join(ch for ch in str(name).lower() if ch.isalnum())


def normalise_flows(raw):
    """Map any CICFlowMeter spelling to model features + optional context and labels.

    Returns (features DataFrame, context DataFrame, labels Series or None, data-quality dict).
    Missing feature columns become NaN, which the preprocessor fills with benign medians.
    """
    raw = raw.reset_index(drop=True)
    df = raw.rename(columns=lambda c: canonical_column(c) or c)
    df = df.loc[:, ~df.columns.duplicated()]
    missing = [c for c in FEATURES if c not in df.columns]
    feats = df.reindex(columns=FEATURES).apply(pd.to_numeric, errors='coerce')
    non_finite = int((~np.isfinite(feats.to_numpy(dtype=np.float64))).any(axis=1).sum())

    keys = {_key(c): c for c in raw.columns}
    context = pd.DataFrame(index=df.index)
    for name, aliases in _CONTEXT.items():
        col = next((keys[a] for a in aliases if a in keys), None)
        if col is not None:
            context[name] = raw[col].values
    if 'Destination Port' in df.columns:
        context['dst_port'] = pd.to_numeric(df['Destination Port'], errors='coerce').values

    labels = None
    if LABEL in df.columns:
        context['label'] = df[LABEL].astype(str).map(clean_label).values
        labels = context['label'].map(attack_category)

    quality = {
        'rows': int(len(df)),
        'missing_feature_columns': missing,
        'rows_with_missing_or_infinite_values': non_finite,
        'reduced_confidence': len(missing) > 0.3 * len(FEATURES),
    }
    return feats, context, labels, quality


def _incidents(flows, context, max_incidents=50):
    """Group alerts into incidents: same source (or same target port when no IPs) and same threat family."""
    alerts = flows[flows['verdict'] != 'normal'].join(context)
    if alerts.empty:
        return []
    # Without source IPs (e.g. the public ML CSVs) one incident per family; port breadth still shows scans.
    by = 'src_ip' if 'src_ip' in alerts else None
    keys = ['threat_family'] + ([by] if by else [])
    out = []
    for key, g in alerts.groupby(keys, dropna=False):
        key = key if isinstance(key, tuple) else (key,)
        family = key[0]
        info = THREATS[family]
        sev = g['severity'].map(_SEVERITY_ORDER).max()
        inc = {
            'threat_family': family,
            'title': info['title'],
            by or 'scope': None if not by else (key[1] if pd.notna(key[1]) else None),
            'flows': int(len(g)),
            'max_risk': float(g['risk_score'].max()),
            'mean_risk': round(float(g['risk_score'].mean()), 1),
            'severity': next(k for k, v in _SEVERITY_ORDER.items() if v == sev),
            'verdicts': g['verdict'].value_counts().to_dict(),
            'confidence': g['confidence'].value_counts().idxmax(),
            'mitre': [f"{t} / {tech}" for t, tech in info['mitre']],
            'actions': info['actions'],
        }
        if 'dst_ip' in g:
            inc['targets'] = g['dst_ip'].astype(str).value_counts().head(5).to_dict()
        if 'dst_port' in g:
            ports = g['dst_port'].dropna()
            inc['distinct_dst_ports'] = int(ports.nunique())
            inc['top_dst_ports'] = {str(int(k)): int(v) for k, v in ports.value_counts().head(5).items()}
        if 'timestamp' in g:
            inc['first_seen'], inc['last_seen'] = str(g['timestamp'].min()), str(g['timestamp'].max())
        inc['priority'] = round(inc['max_risk'] * (1 + np.log10(len(g))), 1)
        out.append(inc)
    out.sort(key=lambda i: -i['priority'])
    return out[:max_incidents]


def _insights(flows, incidents, drift, quality, n):
    """Plain-language suggestions for the analyst and for tuning MAVIS itself."""
    tips = []
    alerts = flows[flows['verdict'] != 'normal']
    if n and len(alerts) / n > 0.2:
        tips.append(f"{len(alerts) / n:.0%} of flows raised alerts: this looks like an active attack wave "
                    "(or a network very different from the training baseline; see drift).")
    novel = int((alerts['detection_mode'] == 'novel').sum())
    if novel:
        tips.append(f"{novel:,} alerts are novel (no known attack signature matched). Review them first for "
                    "zero-day activity, then mark confirmed false positives so the baseline can learn them.")
    for inc in incidents[:3]:
        if inc.get('distinct_dst_ports', 0) >= 50:
            tips.append(f"{inc['title']}: one source touched {inc['distinct_dst_ports']} ports; treat it as "
                        "reconnaissance and expect follow-up attacks on the open ones.")
    low_conf = int((alerts['confidence'] == 'low').sum())
    if len(alerts) and low_conf / len(alerts) > 0.5:
        tips.append("Most alerts are low-confidence (only one model agrees). Consider a stricter alert budget "
                    "(lower --fpr) if analysts are overloaded.")
    if drift.get('status') == 'retrain-recommended':
        tips.append("Traffic has drifted from the benign baseline on many features: recalibrate or retrain "
                    "the engine on recent benign traffic.")
    if quality['missing_feature_columns']:
        tips.append(f"{len(quality['missing_feature_columns'])} feature columns were missing and filled with "
                    "baseline medians; check the flow exporter configuration.")
    if not tips:
        tips.append("No significant threats in this batch.")
    return tips


def analyze(engine, raw, max_explanations=200, internals=None):
    """Full analysis of a raw flow DataFrame. Returns (report dict, per-flow DataFrame).

    Pass a dict as `internals` to also receive the scaled features (X), the raw model scores,
    the unscaled features and the context columns, e.g. to build the frontend payload."""
    feats, context, labels, quality = normalise_flows(raw)
    if feats.empty:
        return {'summary': {'flows': 0}, 'data_quality': quality, 'incidents': [], 'top_alerts': [],
                'insights': ['Input contained no flows.'], 'drift': {'status': 'insufficient-data'}}, pd.DataFrame()

    X = engine.preprocessor.transform(feats)[engine.features]
    model_raw = engine.model_scores(X)
    flows = engine.score(X, raw=model_raw)
    normal = (flows['verdict'] == 'normal').to_numpy()

    top = flows[~normal].sort_values('risk_score', ascending=False).head(max_explanations)
    reasons = engine.explain(X, top.index.to_numpy()) if len(top) else []
    top_alerts = []
    for (i, row), why in zip(top.iterrows(), reasons):
        info = THREATS[row['threat_family']]
        item = {'flow': int(i), **{k: (v.item() if hasattr(v, 'item') else v) for k, v in row.items()},
                'title': info['title'], 'why': why, 'mitre': [f"{t} / {tech}" for t, tech in info['mitre']],
                'actions': info['actions']}
        item.update({k: (v.item() if hasattr(v, 'item') else v) for k, v in context.loc[i].items()})
        top_alerts.append(item)

    incidents = _incidents(flows, context)
    drift = engine.drift(X, normal)
    summary = {
        'flows': int(len(flows)),
        'alerts': int((~normal).sum()),
        'verdicts': flows['verdict'].value_counts().to_dict(),
        'severity': flows.loc[~normal, 'severity'].value_counts().to_dict(),
        'threat_families': flows.loc[~normal, 'threat_family'].value_counts().to_dict(),
        'detection_modes': flows.loc[~normal, 'detection_mode'].value_counts().to_dict(),
        'alert_threshold': engine.alert_threshold,
        'alert_budget_fpr': engine.target_fpr,
    }
    report = {'summary': summary, 'incidents': incidents, 'top_alerts': top_alerts, 'drift': drift,
              'data_quality': quality, 'insights': _insights(flows, incidents, drift, quality, len(flows))}
    if labels is not None:
        report['ground_truth'] = evaluate(flows, labels.to_numpy())
    if internals is not None:
        internals.update(X=X, raw_scores=model_raw, features=feats, context=context)
    flows = flows.join(context)
    return report, flows


def evaluate(flows, categories):
    """Detection quality against known labels (used when the input carries a Label column)."""
    y = np.asarray(categories) != 'Benign'
    alert = (flows['verdict'] != 'normal').to_numpy()
    tp, fp = int((alert & y).sum()), int((alert & ~y).sum())
    fn = int((~alert & y).sum())
    per = {}
    for cat in pd.unique(categories):
        m = np.asarray(categories) == cat
        entry = {'n': int(m.sum()), 'alerted': round(float(alert[m].mean()), 4)}
        if cat != 'Benign':
            hit = m & alert
            entry['named_correctly'] = round(float((flows['threat_family'].to_numpy()[hit] == cat).mean()), 4) \
                if hit.any() else 0.0
            entry['flagged_novel'] = round(float((flows['detection_mode'].to_numpy()[hit] == 'novel').mean()), 4) \
                if hit.any() else 0.0
        per[str(cat)] = entry
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        'precision': round(precision, 4), 'recall': round(recall, 4),
        'f1': round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        'fpr': round(fp / max(int((~y).sum()), 1), 4),
        'per_category': per,
    }
