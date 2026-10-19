"""MAVIS risk engine: turns scaled flow features into analyst-ready verdicts.

Per flow it combines two independent views:

- **Novelty**: Isolation Forest, LOF, the Autoencoder and ECOD each score how unusual the flow is
  compared with benign traffic. Scores become percentiles of benign traffic, so the three are
  comparable, and they are combined (see `_combine`) into the anomaly-ensemble percentile.
- **Recognition**: a gradient-boosted classifier, trained on labelled flows (plus the
  anomaly percentiles as extra inputs), names the attack family and its probability.

likelihood = 1 - (1 - p_known) * (1 - 0.9 * novelty)     (noisy-OR: either view can raise it)
risk       = 100 * likelihood * (0.7 + 0.3 * impact)     (impact from engine/knowledge.py)

Alerting uses two detectors that share the analyst's false-positive "alert budget" (target FPR),
calibrated on held-out benign flows (the known path at most half, the novel path the rest):
- known path: the classifier's attack probability is above its threshold -> `malicious`;
- novel path: the anomaly ensemble is above its threshold while the classifier sees nothing
  -> `suspicious` (a zero-day candidate). An unseen attack family usually looks benign to the
  classifier, so without a separate novel path its weak anomaly signal would be outvoted.
risk orders alerts and sets their severity.
"""
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.neighbors import NearestNeighbors

from .knowledge import NOVEL, THREATS, severity_for

MODEL_NAMES = ('iforest', 'lof', 'ae', 'ecod')
BENIGN = 'Benign'
VOTE_PCT = 0.99           # a model "votes" when the flow is above its 99th benign percentile
NOVEL_TAIL = (0.05, 0.0005)  # novelty rises from 0 (top 5 % of benign) to 1 (top 0.05 %)
_GRID = np.concatenate([np.linspace(0, 0.99, 991), np.linspace(0.99, 1, 1001)[1:]])


class PercentileMap:
    """Maps a raw score to its percentile among reference (benign) scores, from a compact quantile grid."""

    def __init__(self, reference_scores):
        q = np.quantile(np.asarray(reference_scores, dtype=np.float64), _GRID)
        # np.interp needs strictly increasing x: nudge ties apart.
        self.x = np.maximum.accumulate(q) + np.arange(len(q)) * 1e-12
        self.p = _GRID
        # Scores closer than `tol` count as equal. Without it, very uniform reference traffic
        # (e.g. learning on localhost) makes float noise flip a flow from the 0th to the 100th
        # percentile. 1 % of the reference's 1st-99th percentile range, never below a tiny floor.
        lo, hi = np.interp([0.01, 0.99], _GRID, self.x)
        self.tol = float(max(0.01 * (hi - lo), 1e-6 * max(1.0, abs(float(np.median(q))))))

    def __call__(self, scores):
        v = np.asarray(scores, dtype=np.float64)
        tol = getattr(self, 'tol', 0.0)  # maps pickled before `tol` existed behave as before
        if tol <= 0:
            return np.interp(v, self.x, self.p, left=0.0, right=1.0)
        # mid-rank within the tolerance band: ties get the middle of their percentile range
        return 0.5 * (np.interp(v - tol, self.x, self.p, left=0.0, right=1.0)
                      + np.interp(v + tol, self.x, self.p, left=0.0, right=1.0))


def oversample_rare(X, y, min_count=2000, k=5, seed=42):
    """SMOTE-style augmentation: new rows interpolated between same-class neighbours.

    Only for training the classifier; never applied to evaluation data.
    Returns (X_aug, y_aug, n_added_per_class).
    """
    rng = np.random.default_rng(seed)
    Xs, ys, added = [X], [y], {}
    for cls, idx in pd.Series(np.arange(len(y))).groupby(y).groups.items():
        n = len(idx)
        if cls == BENIGN or n >= min_count or n < 2:
            continue
        pts = X[np.asarray(idx)]
        nn = NearestNeighbors(n_neighbors=min(k + 1, n)).fit(pts)
        neigh = nn.kneighbors(pts, return_distance=False)[:, 1:]
        need = min_count - n
        base = rng.integers(0, n, need)
        mate = neigh[base, rng.integers(0, neigh.shape[1], need)]
        gap = rng.random((need, 1)).astype(X.dtype)
        Xs.append(pts[base] + gap * (pts[mate] - pts[base]))
        ys.append(np.full(need, cls, dtype=object))
        added[cls] = int(need)
    return np.vstack(Xs), np.concatenate(ys), added


def _psi(expected_frac, actual_frac, eps=1e-4):
    e, a = np.clip(expected_frac, eps, None), np.clip(actual_frac, eps, None)
    return float(np.sum((a - e) * np.log(a / e)))


class MavisEngine:
    def __init__(self, models, preprocessor=None):
        self.models = dict(models)
        self.names = tuple(n for n in MODEL_NAMES if n in self.models)
        self.preprocessor = preprocessor
        self.features = None
        self.maps = {}
        self.ens_map = None
        self.classifier = None
        self.classes_ = None
        self.alert_threshold = None
        self.target_fpr = None
        self.drift_ref = None
        self.meta = {}

    # ------------------------------------------------------------------ scoring pieces
    def model_scores(self, X):
        return {n: np.asarray(m.predict_anomaly_score(X), dtype=np.float64) for n, m in self.models.items()}

    @staticmethod
    def _combine(pct):
        """Mean of the model percentiles. Chosen among 12 combiners on the calibration half only (recall at
        1 % FPR; CIC-IDS2017, four detectors): mean of 4 0.519; mean of 3 without ECOD 0.482; mean of 4
        plus a strong-single-vote path (alert if any detector's percentile is above a cut-off that takes
        10/20/30/50 % of the novel path's budget) 0.518/0.507/0.469/0.428; Fisher 0.291; max 0.147.
        Held-out eval: mean of 4 recall 0.522, F1 0.670, ROC-AUC 0.958. A strong-vote path spends false
        positives on loud benign outliers and loses more mean-path recall than it gains, so plain mean won.
        ECOD lifts it because it is confident exactly where the others are calm (Heartbleed 0 -> 100 %)."""
        return pct.mean(axis=1)

    def _percentiles(self, raw):
        pct = np.column_stack([self.maps[n](raw[n]) for n in self.names])
        return pct, self.ens_map(self._combine(pct))

    @staticmethod
    def _clf_input(X, pct):
        return np.hstack([np.asarray(X, dtype=np.float32), pct.astype(np.float32)])

    @staticmethod
    def _novelty(ens_pct):
        tail = np.clip(1 - ens_pct, 1e-6, 1)
        hi, lo = NOVEL_TAIL
        return np.clip(np.log(hi / tail) / np.log(hi / lo), 0, 1)

    # ------------------------------------------------------------------ fitting
    def fit(self, X_train, y_train, raw_train, X_calib, y_calib, raw_calib, target_fpr=0.01,
            augment=True, exclude_categories=(), max_benign=300_000, seed=42, log=print):
        """Fit percentile maps, classifier and alert threshold.

        X_*: scaled features; y_*: attack category per row ('Benign', 'DoS', ...);
        raw_*: dict model name -> anomaly scores for those rows (precomputed, e.g. cached).
        Percentile maps and the alert threshold come from the benign rows of the *calibration*
        set, which the classifier never sees, so the false-positive rate holds on new data.
        """
        self.features = list(X_train.columns)
        y_train, y_calib = np.asarray(y_train, dtype=object), np.asarray(y_calib, dtype=object)
        benign_c = y_calib == BENIGN
        self.maps = {n: PercentileMap(raw_calib[n][benign_c]) for n in self.names}
        pct_c = np.column_stack([self.maps[n](raw_calib[n]) for n in self.names])
        self.ens_map = PercentileMap(self._combine(pct_c[benign_c]))

        # classifier training rows: drop excluded families (novel-attack experiments), cap benign
        pct_t, _ = self._percentiles(raw_train)
        keep = ~np.isin(y_train, list(exclude_categories))
        rng = np.random.default_rng(seed)
        benign_idx = np.flatnonzero(keep & (y_train == BENIGN))
        if len(benign_idx) > max_benign:
            keep[rng.choice(benign_idx, len(benign_idx) - max_benign, replace=False)] = False
        Xc = self._clf_input(X_train.to_numpy()[keep], pct_t[keep])
        yc = y_train[keep]
        added = {}
        if augment:
            Xc, yc, added = oversample_rare(Xc, yc, seed=seed)
            if added:
                log(f"augmented rare classes with synthetic rows: {added}")
        counts = pd.Series(yc).value_counts()
        weight = pd.Series(yc).map(lambda c: (len(yc) / (len(counts) * counts[c])) ** 0.5).to_numpy()
        log(f"training classifier on {len(yc):,} rows, classes {counts.to_dict()}")
        self.classifier = HistGradientBoostingClassifier(
            max_iter=300, learning_rate=0.1, max_leaf_nodes=63, early_stopping=True,
            validation_fraction=0.1, random_state=seed)
        self.classifier.fit(Xc, yc, sample_weight=weight)
        self.classes_ = list(self.classifier.classes_)

        self._calibrate(X_calib, raw_calib, benign_c, target_fpr, seed)
        self.meta = {'n_train': int(len(yc)), 'synthetic_rows': added,
                     'excluded_categories': list(exclude_categories), 'classes': self.classes_}
        log(f"alert thresholds for a {target_fpr:.1%} budget: p_known >= {self.alert_threshold['known']:.3f}, "
            f"anomaly percentile >= {self.alert_threshold['novel']:.5f}")
        return self

    def _calibrate(self, X_calib, raw_calib, benign_c, target_fpr, seed=42):
        """Alert thresholds, budget table, explanation and drift references from benign flows."""
        # alert thresholds: each path gets half the false-positive budget on benign calibration flows
        self.target_fpr = target_fpr
        pct_c, ens_c = self._percentiles(raw_calib)
        p_known_c = 1 - self.classifier.predict_proba(self._clf_input(X_calib, pct_c))[:, self.classes_.index(BENIGN)]
        known_thr = float(max(np.quantile(p_known_c[benign_c], 1 - target_fpr / 2), 0.5))
        # the novel path gets whatever budget the known path leaves unused
        known_fp = benign_c & (p_known_c >= known_thr)
        left = max(target_fpr - known_fp.sum() / benign_c.sum(), target_fpr / 2)
        rest = benign_c & ~known_fp
        self.alert_threshold = {
            'known': known_thr,
            # floor at 1 - budget: ens is a benign percentile, so on well-spread data the quantile already
            # sits there; on degenerate (near-identical) traffic it would collapse to ~0.5 and flag everything
            'novel': float(max(np.quantile(ens_c[rest], 1 - left * benign_c.sum() / rest.sum()), 1 - left)),
        }

        # drift reference: per-feature decile bins and the benign share in each (ties in discrete
        # features make bins uneven, so the real shares are stored rather than assumed 10 % each)
        Xb = X_calib.to_numpy()[benign_c]
        edges = np.quantile(Xb, np.linspace(0, 1, 11), axis=0)
        ae = self.models.get('ae')
        if ae is not None and hasattr(ae, 'feature_errors'):
            sample = X_calib[benign_c].sample(n=min(50_000, int(benign_c.sum())), random_state=seed)
            self.benign_feature_error = np.maximum(ae.feature_errors(sample).mean(axis=0), 1e-9)
        # Thresholds for other alert budgets, so the console can re-apply them without the engine.
        self.budget_table = {}
        for b in (0.001, 0.0025, 0.005, 0.01, 0.02, 0.05):
            kt = float(max(np.quantile(p_known_c[benign_c], 1 - b / 2), 0.5))
            kfp = benign_c & (p_known_c >= kt)
            lft = max(b - kfp.sum() / benign_c.sum(), b / 2)
            rst = benign_c & ~kfp
            self.budget_table[b] = {'known': kt, 'novel': float(max(np.quantile(ens_c[rst], 1 - lft * benign_c.sum() / rst.sum()), 1 - lft))}
        self.drift_ref = {}
        for j, f in enumerate(self.features):
            inner = np.unique(edges[:, j])[1:-1]
            if len(inner):
                frac = np.bincount(np.searchsorted(inner, Xb[:, j], side='right'), minlength=len(inner) + 1) / len(Xb)
                self.drift_ref[f] = (inner, frac)

    def recalibrate(self, X, raw=None, target_fpr=None, seed=42, log=print):
        """"Learn my network": re-fit percentile maps, alert thresholds and drift references on
        this network's own traffic, treated as normal. The models and the classifier are not
        retrained; only what counts as unusual *here* changes. Use a capture with no known attacks.
        """
        if len(X) < 200:
            raise ValueError(f"need at least 200 normal flows to learn from, got {len(X)}: keep learning a little longer")
        raw = raw if raw is not None else self.model_scores(X)
        X = X.reset_index(drop=True)
        benign = np.ones(len(X), dtype=bool)
        self.maps = {n: PercentileMap(raw[n]) for n in self.names}
        pct = np.column_stack([self.maps[n](raw[n]) for n in self.names])
        self.ens_map = PercentileMap(self._combine(pct))
        self._calibrate(X, raw, benign, target_fpr or self.target_fpr, seed)
        self.meta['recalibrated_on'] = int(len(X))
        log(f"recalibrated on {len(X):,} local flows: p_known >= {self.alert_threshold['known']:.3f}, "
            f"anomaly percentile >= {self.alert_threshold['novel']:.5f}")
        return self

    # ------------------------------------------------------------------ per-flow verdicts
    def score(self, X, raw=None):
        """Per-flow verdict table (one row per flow, same order as X)."""
        if raw is None:
            raw = self.model_scores(X)
        pct, ens = self._percentiles(raw)
        novelty = self._novelty(ens)
        proba = self.classifier.predict_proba(self._clf_input(X, pct))
        cls = np.array(self.classes_, dtype=object)
        b = self.classes_.index(BENIGN)
        p_known = 1 - proba[:, b]
        attack_proba = proba.copy()
        attack_proba[:, b] = -1
        best = attack_proba.argmax(axis=1)
        attack_type = cls[best]
        type_conf = np.where(p_known > 0, proba[np.arange(len(best)), best] / np.maximum(p_known, 1e-9), 0)

        recognised = p_known >= self.alert_threshold['known']
        novel_hit = ens >= self.alert_threshold['novel']
        family = np.where(recognised, attack_type, NOVEL)
        impact = np.array([THREATS.get(f, THREATS[NOVEL])['impact'] for f in family])
        likelihood = 1 - (1 - p_known) * (1 - 0.9 * novelty)
        risk = 100 * likelihood * (0.7 + 0.3 * impact)

        votes = (pct >= VOTE_PCT).sum(axis=1) + recognised.astype(int)
        alert = recognised | novel_hit
        verdict = np.where(~alert, 'normal', np.where(recognised, 'malicious', 'suspicious'))
        mode = np.where(~alert, '', np.where(recognised & novel_hit, 'known+novel',
                                             np.where(recognised, 'known', 'novel')))
        confidence = np.where((votes >= 3) | (p_known >= 0.9), 'high',
                              np.where((votes == 2) | (p_known >= 0.6), 'medium', 'low'))
        out = pd.DataFrame({
            'risk_score': risk.round(1),
            'severity': [severity_for(r, 0) if a else 'None' for r, a in zip(risk, alert)],
            'verdict': verdict,
            'threat_family': np.where(alert, family, ''),
            'detection_mode': mode,
            'confidence': np.where(alert, confidence, ''),
            'p_known_attack': p_known.round(4),
            'predicted_type': attack_type,
            'type_confidence': type_conf.round(3),
            'novelty': novelty.round(3),
            'anomaly_percentile': ens.round(5),
            'model_votes': votes,
        })
        for i, n in enumerate(self.names):
            out[f'pct_{n}'] = pct[:, i].round(5)
        return out

    def explain(self, X, rows, top=3):
        """Features that make each flow abnormal, ranked by how much worse the autoencoder
        reconstructs them than it does on typical benign traffic (`ratio`). `z` is the feature's
        position against the benign distribution (features are standardised on benign traffic)."""
        Xr = X.iloc[rows]
        z = Xr.to_numpy()
        ae = self.models.get('ae')
        ref = getattr(self, 'benign_feature_error', None)
        if ae is not None and hasattr(ae, 'feature_errors') and ref is not None:
            weight = ae.feature_errors(Xr) / ref
        else:
            weight = z ** 2
        out = []
        for i in range(len(rows)):
            idx = np.argsort(weight[i])[::-1][:top]
            items = []
            for j in idx:
                f, zz, r = self.features[j], float(z[i, j]), float(weight[i, j])
                side = 'higher' if zz >= 0 else 'lower'
                if ref is None:
                    text = f"{f} is {abs(zz):.1f} std {side} than normal"
                elif abs(zz) >= 1:
                    text = f"{f} is {side} than typical ({r:.0f}x the reconstruction error of normal traffic)"
                else:
                    text = (f"{f} has a typical value but does not fit the rest of this flow "
                            f"({r:.0f}x the reconstruction error of normal traffic)")
                items.append({'feature': f, 'z': round(zz, 2), 'ratio': round(r, 1), 'text': text})
            out.append(items)
        return out

    # ------------------------------------------------------------------ monitoring
    def drift(self, X, normal_mask, min_rows=5000):
        """Population-stability index of each feature on flows judged normal vs the benign reference.
        PSI > 0.25 on several features means the network changed and the models should be recalibrated."""
        Xn = X.to_numpy()[normal_mask]
        if len(Xn) < min_rows:  # fewer normal flows give noisy PSI on 10 bins
            return {'status': 'insufficient-data', 'rows': int(len(Xn))}
        psi = {}
        for j, f in enumerate(self.features):
            if f not in self.drift_ref:
                continue
            inner, ref = self.drift_ref[f]
            act = np.bincount(np.searchsorted(inner, Xn[:, j], side='right'), minlength=len(inner) + 1) / len(Xn)
            psi[f] = _psi(ref, act)
        worst = sorted(psi.items(), key=lambda kv: -kv[1])[:5]
        n_bad = sum(v > 0.25 for v in psi.values())
        status = 'retrain-recommended' if n_bad >= 10 else 'watch' if n_bad >= 3 else 'stable'
        return {'status': status, 'features_drifted': n_bad,
                'top': [{'feature': f, 'psi': round(v, 3)} for f, v in worst]}

    # ------------------------------------------------------------------ persistence
    def save(self, path):
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        for n, m in self.models.items():
            m.save(path / f"{n}.{'pt' if n == 'ae' else 'joblib'}")
        state = {k: v for k, v in self.__dict__.items() if k != 'models'}
        joblib.dump(state, path / 'engine.joblib')
        (path / 'engine_info.json').write_text(json.dumps({
            'alert_threshold': self.alert_threshold, 'target_fpr': self.target_fpr,
            'features': self.features, **self.meta}, indent=2))

    @classmethod
    def load(cls, path):
        from models import MavisAutoencoder, MavisECOD, MavisIsolationForest, MavisLOF
        path = Path(path)
        files = {'iforest': (MavisIsolationForest, 'iforest.joblib'), 'lof': (MavisLOF, 'lof.joblib'),
                 'ae': (MavisAutoencoder, 'ae.pt'), 'ecod': (MavisECOD, 'ecod.joblib')}
        # an engine built before ECOD existed has no ecod.joblib: load the models that are present
        models = {n: c.load(path / f) for n, (c, f) in files.items() if (path / f).exists()}
        eng = cls(models)
        eng.__dict__.update(joblib.load(path / 'engine.joblib'))
        eng.names = tuple(n for n in MODEL_NAMES if n in models)
        return eng
