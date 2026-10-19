// Models (compact): the detectors, how they are fused, and the measured evaluation numbers.
// Facts come from GET api/engine or data/engine.json; the prose from data/model-registry.js.
import { html, mount } from '../core/dom.js';
import { fmtPct } from '../core/format.js';
import { infoCallout } from '../components/security.js';
import { engine, evaluation } from '../data/index.js';
import { MODELS, CLASSIFIER, FUSION_STEPS } from '../data/model-registry.js';
import { pageHead, panel } from './common.js';

const ENG_KEY = { if: 'iforest', lof: 'lof', ae: 'ae', ecod: 'ecod' };
const num = (v, d = 3) => (v == null ? 'n/a' : v.toFixed(d));
const pct = (v, d = 1) => (v == null ? 'n/a' : fmtPct(v, d));
const cells = (r) => (r ? html`<td class="r mono">${num(r.roc_auc)}</td><td class="r mono">${num(r.pr_auc)}</td><td class="r mono">${pct(r.precision)}</td><td class="r mono">${pct(r.recall)}</td><td class="r mono">${pct(r.fpr, 2)}</td>`
  : html`<td class="r muted" colspan="5">not available</td>`);

export default {
  title: 'Models',
  render(root) {
    const e = engine();
    const ev = evaluation() || {};
    const an = ev.anomaly?.results || {};
    const full = ev.engine?.engine;
    mount(root, html`
      ${pageHead({ title: 'Models', sub: 'Four anomaly detectors trained on benign traffic, an attack classifier, and the fusion that turns them into one verdict.' })}
      ${e ? '' : infoCallout('Engine details are not available: the server did not return api/engine and data/engine.json is missing.')}
      ${panel({ title: 'Detectors and evaluation', meta: 'held-out CIC-IDS2017 flows, each detector alone at a 1% false-positive budget', bodyCls: 'flush', body: html`<div class="table-wrap"><table class="table table-tight">
        <thead><tr><th>Model</th><th>Idea</th><th class="r">ROC-AUC</th><th class="r">PR-AUC</th><th class="r">Precision</th><th class="r">Recall</th><th class="r">False-positive rate</th></tr></thead>
        <tbody>
          ${MODELS.map((m) => html`<tr><td><i class="mdot" data-m="${m.id}"></i> <b>${m.name}</b></td><td class="muted wrap">${m.idea.split('. ')[0]}.</td>${cells(an[ENG_KEY[m.id]])}</tr>`)}
          <tr><td><i class="mdot" data-m="clf"></i> <b>Full engine</b></td><td class="muted wrap">Detectors plus ${CLASSIFIER.name.toLowerCase()}, fused.</td>${cells(full)}</tr>
        </tbody></table></div>` })}
      ${e ? panel({ title: 'Thresholds', body: html`<dl class="kv">
        <dt>Alert budget</dt><dd class="mono">${pct(e.alertBudgetFpr, 2)} <span class="muted">false alerts on benign calibration flows</span></dd>
        <dt>Known path</dt><dd class="mono">attack probability ≥ ${num(e.thresholds?.known)}</dd>
        <dt>Novel path</dt><dd class="mono">anomaly percentile ≥ ${num(e.thresholds?.novel, 5)}</dd>
        <dt>Detector vote</dt><dd class="mono">above the ${pct(e.votePercentile, 0)} benign percentile</dd>
        <dt>Attack classes</dt><dd>${(e.classes || []).filter((c) => c !== 'Benign').join(', ')}</dd></dl>` }) : ''}
      ${panel({ title: 'How the engine decides', body: html`<ol class="steps">${FUSION_STEPS.map(([t, d], i) => html`<li><span class="step-n num">${i + 1}</span><div><b>${t}</b><span>${d}</span></div></li>`)}</ol>
        <p class="panel-meta">The models were trained on 2017 lab traffic. Use Learning on the Overview page to calibrate them on your own network.</p>` })}`);
  },
};
