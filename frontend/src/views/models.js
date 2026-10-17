// ML Models: what each detector is (from the code), how its score works, and how the three
// compare. Configuration is real; every score-derived number is computed on sample flows.
import { html, mount, on, $ } from '../core/dom.js';
import { fmtInt, fmtPct } from '../core/format.js';
import { icon } from '../components/icons.js';
import { bindChart, histogram } from '../components/charts.js';
import { tip } from '../components/overlays.js';
import { tagSample, tagCode, tagPlanned, sampleCallout, SCORE_RANGE, cutoffFor } from '../components/security.js';
import { flows, cicSummary } from '../data/index.js';
import { MODELS } from '../data/model-registry.js';
import { pageHead, panel } from './common.js';

// Metrics on sample data: flags vs. the sample flows' dataset labels.
function metricsFor(id, list) {
  let tp = 0, fp = 0, fn = 0, tn = 0;
  list.forEach((f) => {
    const pos = f.label !== 'BENIGN';
    const hit = f.flags[id];
    if (hit && pos) tp++; else if (hit) fp++; else if (pos) fn++; else tn++;
  });
  const precision = tp / (tp + fp || 1), recall = tp / (tp + fn || 1);
  // ROC-AUC by rank (Mann–Whitney U)
  const sorted = [...list].sort((a, b) => a.scores[id] - b.scores[id]);
  let rankSum = 0, nPos = 0;
  sorted.forEach((f, i) => { if (f.label !== 'BENIGN') { rankSum += i + 1; nPos++; } });
  const nNeg = list.length - nPos;
  const auc = (rankSum - (nPos * (nPos + 1)) / 2) / (nPos * nNeg || 1);
  return { tp, fp, fn, tn, precision, recall, f1: (2 * precision * recall) / (precision + recall || 1), auc, flagged: tp + fp };
}

function aeLayers(d) {
  const w = [d, Math.trunc(d * 0.75), Math.trunc(d * 0.5), Math.trunc(d * 0.25), Math.trunc(d * 0.5), Math.trunc(d * 0.75), d];
  return w;
}

function ensembleDiagram(features) {
  return html`
  <div class="ensemble" role="img" aria-label="MAVIS detection pipeline: flow features go to three detectors in parallel; their scores will feed a fusion engine that is not built yet.">
    <div class="ens-col">
      <div class="ens-node ens-input"><span class="ens-k">Input</span><b>${features} flow features</b><span>CIC-IDS2017, per flow</span></div>
    </div>
    <div class="ens-wires" aria-hidden="true"><span></span><span></span><span></span></div>
    <div class="ens-col ens-models">
      ${MODELS.map((m) => html`<div class="ens-node ens-model" data-m="${m.id}"><span class="mdot" data-m="${m.id}"></span><div><b>${m.name}</b><span>${m.scoreName}</span></div>${tagCode('Code')}</div>`)}
    </div>
    <div class="ens-wires ens-wires-in" aria-hidden="true"><span></span><span></span><span></span></div>
    <div class="ens-col">
      <div class="ens-node ens-planned"><span class="ens-k">Fusion engine</span><b>Normalise and combine</b><span>Described in the Readme as the MAVIS Risk Engine</span>${tagPlanned()}</div>
    </div>
    <div class="ens-arrow" aria-hidden="true">${icon('arrowRight')}</div>
    <div class="ens-col">
      <div class="ens-node ens-planned"><span class="ens-k">Output</span><b>Risk score and explanation</b><span>Shown here once available</span>${tagPlanned()}</div>
    </div>
  </div>`;
}

function modelTab(m, list) {
  const flagged = list.filter((f) => f.flags[m.id]).length;
  const d = 78;
  return html`
    <div class="model-tab" data-m="${m.id}">
      <div class="model-intro">
        <div class="model-intro-text">
          <h3 class="model-name"><span class="mdot" data-m="${m.id}"></span>${m.name}</h3>
          <p>${m.idea}</p>
          <div class="formula"><span class="panel-meta">Score</span><code>${m.scoreFormula}</code></div>
          <p class="panel-meta">${m.scoreDirection}</p>
        </div>
        <div class="model-stats">
          <div class="metric"><div class="metric-label">Flagged ${tagSample()}</div><div class="metric-value num">${fmtInt(flagged)}<small>/ ${fmtInt(list.length)}</small></div></div>
          <div class="metric"><div class="metric-label">Cut-off</div><div class="metric-value num" style="font-size:var(--fs-lg)">${m.id === 'ae' ? html`${cutoffFor('ae')} ${tagSample()}` : '0'}</div><div class="metric-foot">${m.thresholdSource}</div></div>
          <div class="metric"><div class="metric-label">Processing time</div><div class="metric-value" style="font-size:var(--fs-lg)">Not measured</div><div class="metric-foot">No training or scoring run yet</div></div>
        </div>
      </div>

      <div class="model-cols">
        <div class="model-col">
          <h4 class="section-title">Score distribution ${tagSample()}</h4>
          <div class="chart" id="mh-${m.id}"></div>
          <div class="legend"><span class="legend-item"><i class="swatch" style="background:var(--benign)"></i>Benign-labelled</span><span class="legend-item"><i class="swatch" style="background:var(--m-${m.id})"></i>Attack-labelled</span><span class="legend-item"><i class="swatch" style="background:var(--ink-1);height:2px"></i>Cut-off</span></div>
        </div>
        <div class="model-col">
          <h4 class="section-title">Configuration ${tagCode()}</h4>
          <dl class="kv">
            <dt>Class</dt><dd class="mono">${m.className}</dd>
            <dt>Source</dt><dd class="mono">${m.file}</dd>
            <dt>Library</dt><dd>${m.library}</dd>
            ${m.params.map(([k, v]) => html`<dt class="mono">${k}</dt><dd class="mono">${v}</dd>`)}
            <dt>Training</dt><dd>${m.trainingNote}</dd>
            <dt>Saved as</dt><dd>${m.persistence}</dd>
          </dl>
        </div>
      </div>
      ${m.id === 'ae' ? html`
        <div class="ae-arch">
          <h4 class="section-title">Network shape ${tagCode()}</h4>
          <div class="ae-layers" role="img" aria-label="Autoencoder layer widths ${aeLayers(d).join(', ')}">
            ${aeLayers(d).map((w, i) => html`<div class="ae-layer ${i === 3 ? 'is-bottleneck' : ''}" style="--h:${(w / d) * 100}%" data-tip='${tip(i === 3 ? 'Bottleneck' : i < 3 ? `Encoder layer ${i}` : `Decoder layer ${i - 3}`, [['Units', String(w)]])}' tabindex="0"><span>${w}</span></div>`)}
          </div>
          <p class="panel-meta">Widths shown for d = ${d}, the raw CIC-IDS2017 feature count. The real d depends on preprocessing, which is not in the repo yet.</p>
        </div>` : ''}
    </div>`;
}

function fusionTab() {
  return html`
    <div class="model-tab">
      <div class="empty" style="justify-items:start;text-align:left;padding:4px 0 8px">
        <div class="empty-title" style="display:flex;gap:10px;align-items:center">MAVIS Fusion Engine ${tagPlanned()}</div>
        <p style="max-width:70ch">The Readme describes a MAVIS Risk Engine that combines the three detectors into one threat score. It has not been written yet, so this interface does not invent a fusion formula. When it lands, this tab will show the normalisation used for each score, the combination rule, and the resulting risk distribution.</p>
      </div>
      <h4 class="section-title">What the engine will need to decide</h4>
      <ul class="checklist">
        <li>${icon('pipeline')}<div><b>Score normalisation.</b> IF and LOF scores centre on 0, the autoencoder error is always positive. They need a common scale before they can be combined.</div></li>
        <li>${icon('layers')}<div><b>Combination rule.</b> For example a weighted mean, a vote, or a learned combiner.</div></li>
        <li>${icon('alert')}<div><b>Autoencoder cut-off.</b> The code returns a reconstruction error but defines no threshold.</div></li>
      </ul>
    </div>`;
}

export default {
  title: 'ML Models',
  render(root) {
    const list = flows();
    const cic = cicSummary();
    const features = cic.columns - 1;
    const met = Object.fromEntries(MODELS.map((m) => [m.id, metricsFor(m.id, list)]));
    const classes = Array.from(new Set(list.filter((f) => f.label !== 'BENIGN').map((f) => f.attackClass)));
    const byClass = classes.map((c) => {
      const rows = list.filter((f) => f.attackClass === c);
      return { c, n: rows.length, rates: Object.fromEntries(MODELS.map((m) => [m.id, rows.filter((f) => f.flags[m.id]).length / rows.length])) };
    }).sort((a, b) => b.n - a.n);
    const pair = (a, b) => {
      const A = list.filter((f) => f.flags[a]), B = new Set(list.filter((f) => f.flags[b]).map((f) => f.id));
      const inter = A.filter((f) => B.has(f.id)).length;
      return inter / (A.length + B.size - inter || 1);
    };

    mount(root, html`
      ${pageHead({ title: 'ML Models', sub: 'Three unsupervised detectors look at the same flow from different angles. Their disagreements are as informative as their agreement.' })}
      ${sampleCallout(html`<b>No model has been trained in this repository yet.</b> Model descriptions and parameters come from <code>src/models</code>. Scores, counts and metrics below are computed in the browser on ${fmtInt(list.length)} sample flows so the layout can be evaluated.`)}

      ${panel({ title: 'Detection architecture', meta: 'From the code and Readme', body: ensembleDiagram(features) })}

      ${panel({ title: 'Detectors', cls: 'models-panel', bodyCls: 'flush', body: html`
        <div class="tabs" role="tablist" aria-label="Detectors">
          ${MODELS.map((m, i) => html`<button class="tab" role="tab" id="tab-${m.id}" aria-controls="tp-${m.id}" aria-selected="${i === 0}" tabindex="${i === 0 ? 0 : -1}" data-tab="${m.id}">${m.name}</button>`)}
          <button class="tab" role="tab" id="tab-fusion" aria-controls="tp-fusion" aria-selected="false" tabindex="-1" data-tab="fusion">Fusion Engine</button>
          <span class="tab-ink" aria-hidden="true"></span>
        </div>
        ${MODELS.map((m, i) => html`<div class="tab-panel" role="tabpanel" id="tp-${m.id}" aria-labelledby="tab-${m.id}" ${i === 0 ? '' : html`hidden`}>${modelTab(m, list)}</div>`)}
        <div class="tab-panel" role="tabpanel" id="tp-fusion" aria-labelledby="tab-fusion" hidden>${fusionTab()}</div>` })}

      <div class="models-grid">
        ${panel({ title: 'Evaluation on sample flows', tag: tagSample(), cls: 'span-2', bodyCls: 'flush', body: html`
          <div class="table-wrap"><table class="table">
            <caption class="visually-hidden">Detector metrics computed on sample flows</caption>
            <thead><tr><th scope="col">Detector</th><th class="r" scope="col">Flagged</th><th class="r" scope="col">Precision</th><th class="r" scope="col">Recall</th><th class="r" scope="col">F1</th><th class="r" scope="col">ROC-AUC</th><th class="r" scope="col">False positives</th></tr></thead>
            <tbody>${MODELS.map((m) => html`<tr>
              <td><span style="display:inline-flex;gap:8px;align-items:center"><span class="mdot" data-m="${m.id}"></span>${m.name}</span></td>
              <td class="r mono">${fmtInt(met[m.id].flagged)}</td>
              <td class="r mono">${met[m.id].precision.toFixed(3)}</td>
              <td class="r mono">${met[m.id].recall.toFixed(3)}</td>
              <td class="r mono">${met[m.id].f1.toFixed(3)}</td>
              <td class="r mono">${met[m.id].auc.toFixed(3)}</td>
              <td class="r mono">${fmtInt(met[m.id].fp)}</td></tr>`)}
              <tr class="muted-row"><td>MAVIS fusion</td><td class="r" colspan="6"><span class="tag tag-planned">Not built</span></td></tr>
            </tbody></table></div>
          <div class="panel-foot">These numbers describe generated sample flows against their generated labels. They say nothing about real model performance on CIC-IDS2017.</div>` })}

        ${panel({ title: 'Pairwise agreement', tag: tagSample(), meta: 'Jaccard overlap of flagged sets', body: html`
          <div class="pairs" role="table" aria-label="Pairwise agreement between detectors">
            <div role="row" class="pairs-row"><span role="columnheader"></span>${MODELS.map((m) => html`<span role="columnheader" class="pairs-h">${m.short}</span>`)}</div>
            ${MODELS.map((a) => html`<div role="row" class="pairs-row"><span role="rowheader" class="pairs-h">${a.short}</span>${MODELS.map((b) => {
              const v = a.id === b.id ? 1 : pair(a.id, b.id);
              return html`<span role="cell" class="pairs-cell ${a.id === b.id ? 'is-self' : ''}" style="--v:${v.toFixed(3)}" tabindex="0" data-tip='${tip(`${a.short} and ${b.short}`, [['Overlap', fmtPct(v, 0)]], a.id === b.id ? 'Same detector' : 'Share of flagged flows both detectors flag')}'>${a.id === b.id ? '—' : fmtPct(v, 0)}</span>`;
            })}</div>`)}
          </div>
          <p class="panel-meta" style="margin-top:10px">Anything under 100% means each detector catches flows the others miss, which is the reason for running three.</p>` })}

        ${panel({ title: 'Detection rate by attack class', tag: tagSample(), cls: 'span-3', bodyCls: 'flush', body: html`
          <div class="table-wrap"><table class="table rate-table">
            <caption class="visually-hidden">Share of attack-labelled sample flows each detector flagged, by class</caption>
            <thead><tr><th scope="col">Attack class</th><th class="r" scope="col">Flows</th>${MODELS.map((m) => html`<th scope="col"><span style="display:inline-flex;gap:6px;align-items:center"><span class="mdot" data-m="${m.id}"></span>${m.short}</span></th>`)}</tr></thead>
            <tbody>${byClass.map((r) => html`<tr><td>${r.c}</td><td class="r mono">${fmtInt(r.n)}</td>${MODELS.map((m) => html`<td><span class="rate"><span class="rate-bar"><span style="width:${(r.rates[m.id] * 100).toFixed(0)}%;background:var(--m-${m.id})"></span></span><span class="mono">${fmtPct(r.rates[m.id], 0)}</span></span></td>`)}</tr>`)}</tbody>
          </table></div>` })}
      </div>`);

    // Histograms per detector, drawn when their tab is first shown
    const drawn = new Set();
    const drawHist = (id) => {
      if (drawn.has(id) || id === 'fusion') return;
      drawn.add(id);
      bindChart($(`#mh-${id}`, root), (w) => histogram(w, 180, {
        values: list.map((f) => ({ value: f.scores[id], group: f.label === 'BENIGN' ? 'benign' : 'attack' })),
        groups: [{ key: 'benign', name: 'Benign-labelled' }, { key: 'attack', name: 'Attack-labelled' }],
        range: SCORE_RANGE[id], bins: 30, cutoff: cutoffFor(id), cutoffLabel: id === 'ae' ? 'sample cut-off' : 'cut-off 0',
        color: `var(--m-${id})`, label: `${id} score distribution, sample`, fmt: (v) => v.toFixed(2),
      }));
    };

    const tabs = Array.from(root.querySelectorAll('[role="tab"]'));
    const ink = root.querySelector('.tab-ink');
    const moveInk = (t) => { ink.style.width = `${t.offsetWidth}px`; ink.style.transform = `translateX(${t.offsetLeft}px)`; };
    const select = (t) => {
      tabs.forEach((x) => { const on_ = x === t; x.setAttribute('aria-selected', String(on_)); x.tabIndex = on_ ? 0 : -1; root.querySelector(`#${x.getAttribute('aria-controls')}`).hidden = !on_; });
      moveInk(t);
      drawHist(t.dataset.tab);
    };
    on(root, 'click', '[role="tab"]', (_e, t) => select(t));
    on(root, 'keydown', '[role="tab"]', (ev, t) => {
      const i = tabs.indexOf(t);
      if (ev.key === 'ArrowRight' || ev.key === 'ArrowLeft') {
        const n = tabs[(i + (ev.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
        n.focus(); select(n); ev.preventDefault();
      }
    });
    requestAnimationFrame(() => select(tabs[0]));
    const ro = new ResizeObserver(() => moveInk(tabs.find((t) => t.getAttribute('aria-selected') === 'true')));
    ro.observe(root.querySelector('.tabs'));
    return () => ro.disconnect();
  },
};

