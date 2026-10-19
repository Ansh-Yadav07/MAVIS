// ML Models: the four detectors, the attack classifier and the fusion that combines them.
// Hyperparameters, cut-offs and metrics are read from the exported snapshot; the prose comes
// from data/model-registry.js and mirrors src/models/*.py and src/engine/engine.py.
import { html, mount } from '../core/dom.js';
import { fmtInt, fmtPct } from '../core/format.js';
import { tagEngine, tagEval, tagCode, infoCallout } from '../components/security.js';
import { engine, evaluation, currentBudget } from '../data/index.js';
import { MODELS, CLASSIFIER, FUSION_STEPS } from '../data/model-registry.js';
import { pageHead, panel, ratioBar, pctText, watch, noData } from './common.js';

const ENG_KEY = { if: 'iforest', lof: 'lof', ae: 'ae', ecod: 'ecod' };
const CATS = ['DoS', 'DDoS', 'PortScan', 'BruteForce', 'WebAttack', 'Bot', 'Infiltration', 'Heartbleed'];
const num = (v, d = 3) => (v == null ? 'n/a' : v.toFixed(d));
const fmtParam = (v) => (Array.isArray(v) ? v.join(', ') : typeof v === 'boolean' ? (v ? 'True' : 'False') : String(v));

function aeLayers(p) {
  if (!p?.input_dim) return [];
  const h = (p.hidden_fractions || []).map((f) => Math.max(2, Math.floor(p.input_dim * f)));
  return [p.input_dim, ...h, ...[...h].reverse().slice(1), p.input_dim];
}

const metricTiles = (r) => !r ? html`<p class="panel-meta">No evaluation result in the snapshot.</p>` : html`
  <div class="mini-metrics">
    <div class="metric"><div class="metric-label">ROC-AUC</div><div class="metric-value num">${num(r.roc_auc)}</div></div>
    <div class="metric"><div class="metric-label">PR-AUC</div><div class="metric-value num">${num(r.pr_auc)}</div></div>
    <div class="metric"><div class="metric-label">Precision</div><div class="metric-value num">${pctText(r.precision)}</div></div>
    <div class="metric"><div class="metric-label">Recall</div><div class="metric-value num">${pctText(r.recall)}</div></div>
    <div class="metric"><div class="metric-label">F1</div><div class="metric-value num">${num(r.f1)}</div></div>
    <div class="metric"><div class="metric-label">False-positive rate</div><div class="metric-value num">${pctText(r.fpr, 2)}</div></div>
  </div>`;

const detectionRows = (r, key) => !r?.per_category ? '' : html`
  <table class="table table-tight"><thead><tr><th scope="col">Attack family</th><th scope="col">Flagged</th></tr></thead><tbody>${
    CATS.filter((c) => r.per_category[c]).map((c) => html`<tr><td>${c} <span class="muted num">${fmtInt(r.per_category[c].n)}</span></td><td>${ratioBar(r.per_category[c][key])}</td></tr>`)}</tbody></table>`;

export default {
  title: 'ML Models',
  render(root) {
    const paint = () => {
      const e = engine();
      const ev = evaluation() || {};
      const an = ev.anomaly?.results || {};
      const eng = ev.engine;
      const thr = e.thresholds;

      const detector = (m) => {
        const p = e.params?.[m.id] || {};
        const r = an[ENG_KEY[m.id]];
        const layers = m.id === 'ae' ? aeLayers(p) : [];
        return html`
          <article class="model-card" data-m="${m.id}" aria-label="${m.name}">
            <header class="model-card-head"><i class="mdot" data-m="${m.id}"></i><h2>${m.name}</h2>${tagCode(m.short)}</header>
            <p>${m.idea}</p>
            <div class="formula"><span class="panel-meta">Score</span><code>${m.scoreFormula}</code></div>
            <p class="panel-meta">${m.scoreDirection}</p>
            <h3 class="section-title">Hyperparameters ${tagEngine('From the trained model')}</h3>
            <dl class="kv">${Object.entries(p).map(([k, v]) => html`<dt class="mono">${k}</dt><dd class="mono">${fmtParam(v)}</dd>`)}
              <dt>Training</dt><dd>${m.trainingNote}</dd>
              <dt>Cut-off</dt><dd class="mono">${num(e.cutoffs?.[m.id], 4)} <span class="muted">native score at the ${fmtPct(e.votePercentile, 0)} benign percentile (one vote)</span></dd></dl>
            ${layers.length ? html`<div class="ae-layers" role="img" aria-label="Autoencoder layer widths ${layers.join(', ')}">${layers.map((n, i) => html`<div class="ae-layer ${n === Math.min(...layers) ? 'is-bottleneck' : ''}" style="--h:${Math.max(18, (n / layers[0]) * 100)}%" title="${n} units"><span>${n}</span></div>`)}</div>` : ''}
            <h3 class="section-title">Alone, at a 1% false-positive budget ${tagEval()}</h3>
            ${metricTiles(r)}
            ${detectionRows(r, 'flagged')}
            <p class="panel-meta file-ref mono">${m.file} · ${m.library}</p>
          </article>`;
      };

      const syn = e.synthetic_rows || {};
      const classifier = html`
        <article class="model-card" data-m="clf" aria-label="${CLASSIFIER.name}">
          <header class="model-card-head"><i class="mdot" data-m="clf"></i><h2>${CLASSIFIER.name}</h2>${tagCode(CLASSIFIER.short)}</header>
          <p>${CLASSIFIER.idea}</p>
          <p>${CLASSIFIER.training}</p>
          <h3 class="section-title">Settings ${tagCode()}</h3>
          <dl class="kv">${CLASSIFIER.settings.map(([k, v]) => html`<dt class="mono">${k}</dt><dd class="mono">${v}</dd>`)}
            <dt>Classes</dt><dd>${(e.classes || []).join(', ')}</dd></dl>
          <h3 class="section-title">Synthetic rows added for rare classes ${tagEngine()}</h3>
          ${Object.keys(syn).length ? html`<dl class="kv">${Object.entries(syn).map(([k, v]) => html`<dt>${k}</dt><dd class="mono">+${fmtInt(v)}</dd>`)}</dl>
            <p class="panel-meta">These families have too few real flows to learn from. Interpolated copies are added to training only; the evaluation below never contains synthetic rows.</p>` : html`<p class="panel-meta">None were needed.</p>`}
          <p class="panel-meta file-ref mono">${CLASSIFIER.file} · ${CLASSIFIER.library}</p>
        </article>`;

      const E = eng?.engine, A = eng?.anomaly_only;
      const compare = !E ? noData('The engine evaluation') : html`
        <div class="table-wrap"><table class="table table-tight">
          <thead><tr><th scope="col">Result on held-out flows</th><th scope="col" class="r">Detectors only</th><th scope="col" class="r">Full engine</th></tr></thead>
          <tbody>
            ${[['ROC-AUC', 'roc_auc', num], ['PR-AUC', 'pr_auc', num], ['Precision', 'precision', pctText], ['Recall', 'recall', pctText], ['F1', 'f1', num], ['False-positive rate', 'fpr', (v) => pctText(v, 2)]].map(([l, k, f]) => html`
              <tr><td>${l}</td><td class="r mono">${A ? f(A[k]) : 'n/a'}</td><td class="r mono"><b>${f(E[k])}</b></td></tr>`)}
          </tbody></table></div>
        <h3 class="section-title">Share of each family alerted</h3>
        <div class="table-wrap"><table class="table table-tight">
          <thead><tr><th scope="col">Family</th><th scope="col">Detectors only</th><th scope="col">Full engine</th><th scope="col" class="r">Named correctly</th></tr></thead>
          <tbody>${CATS.filter((c) => E.per_category?.[c]).map((c) => html`<tr>
            <td>${c} <span class="muted num">${fmtInt(E.per_category[c].n)}</span></td>
            <td>${A?.per_category?.[c] ? ratioBar(A.per_category[c].alerted) : ''}</td>
            <td>${ratioBar(E.per_category[c].alerted)}</td>
            <td class="r mono">${pctText(E.per_category[c].named_correctly)}</td></tr>`)}</tbody></table></div>
        <p class="panel-meta">Benign false-positive rate: ${pctText(E.per_category?.Benign?.alerted, 2)} (budget ${fmtPct(eng.alert_budget_fpr)}). The engine is evaluated on a random split of the same capture days, so these figures are optimistic about a different network.</p>`;

      const zd = eng?.zero_day;
      const zero = !zd ? noData('The zero-day test') : html`
        <p class="prose">A zero-day test asks what happens when an attack family has never been seen. For each family below, the engine is rebuilt with that family left out of the classifier’s training data, then asked to analyse that family’s flows. The detectors never train on attacks anyway, so they are the only part that can catch it. <b>Alerted</b> is the share of the family’s flows flagged at all. <b>As novel</b> is the share flagged by the anomaly path as “Novel”. <b>Misnamed</b> counts flows the classifier labelled as a different known family. The benign false-positive rate stays near the budget.</p>
        <div class="table-wrap"><table class="table table-tight">
          <thead><tr><th scope="col">Hidden family</th><th scope="col" class="r">Flows</th><th scope="col">Alerted</th><th scope="col">As novel</th><th scope="col">Anomaly path fired</th><th scope="col">Misnamed as</th><th scope="col" class="r">Benign FPR</th></tr></thead>
          <tbody>${Object.entries(zd).map(([k, z]) => html`<tr>
            <td><b>${k}</b></td><td class="r mono">${fmtInt(z.n)}</td><td>${ratioBar(z.alerted)}</td><td>${ratioBar(z.as_novel)}</td><td>${ratioBar(z.anomaly_path_fired)}</td>
            <td class="muted">${Object.entries(z.misnamed_as || {}).map(([a, n]) => `${a} ${fmtInt(n)}`).join(', ') || 'none'}</td>
            <td class="r mono">${pctText(z.benign_fpr, 2)}</td></tr>`)}</tbody></table></div>
        <p class="panel-meta">Reading it honestly: unseen families that look like known traffic (DDoS resembles DoS) are caught but mislabelled; families that look like ordinary flows (Bot, BruteForce) are mostly missed. That is the limit of anomaly detection on this feature set.</p>`;

      mount(root, html`
        ${pageHead({ title: 'ML Models', sub: 'Three anomaly detectors trained on benign traffic, an attack classifier, and the fusion that turns them into one verdict.' })}

        ${panel({ title: 'How the engine decides', tag: tagCode(), cls: 'fusion',
          body: html`<ol class="steps">${FUSION_STEPS.map(([t, d], i) => html`<li><span class="step-n num">${i + 1}</span><div><b>${t}</b><span>${d}</span></div></li>`)}</ol>
            <div class="fusion-foot">
              <dl class="kv">
                <dt>Alert budget</dt><dd class="mono">${fmtPct(currentBudget(), 2)} <span class="muted">false alerts on benign flows; engine default ${fmtPct(e.alertBudgetFpr, 1)}</span></dd>
                <dt>Known path</dt><dd class="mono">attack probability ≥ ${num(thr.known, 3)}</dd>
                <dt>Novel path</dt><dd class="mono">anomaly percentile ≥ ${num(thr.novel, 5)}</dd>
                <dt>Two detectors, one budget</dt><dd>The known path takes half the budget; the novel path gets whatever the known path leaves unused, so total false alerts on benign calibration flows stay at the budget.</dd>
              </dl>
              ${infoCallout('The thresholds are calibrated once on held-out benign flows. Changing the budget in the top bar re-applies pre-computed thresholds to the exported flows; no model is re-run.')}
            </div>` })}

        <div class="models-grid">${MODELS.map(detector)}</div>
        <div class="models-grid models-grid-2">${classifier}
          ${panel({ title: 'Engine against detectors alone', tag: tagEval(), cls: 'model-compare', body: compare })}
        </div>
        ${panel({ title: 'Zero-day test: families the classifier has never seen', tag: tagEval(), body: zero })}`);
    };
    paint();
    return watch((ev) => { if (ev.type === 'pref' && (ev.key === 'alertBudget' || ev.key === '*')) paint(); });
  },
};
