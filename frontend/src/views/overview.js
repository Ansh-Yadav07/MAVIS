// Overview: what the trained engine found in the CIC-IDS2017 capture week. Every number is
// engine output or an evaluation result; the public CSVs carry no timestamps or IPs, so the
// activity chart is in capture-sequence (file) order and detections show port/service.
import { html, mount, on, $ } from '../core/dom.js';
import { fmtInt, fmtPct, fmtCompact } from '../core/format.js';
import { sevGlyph } from '../components/icons.js';
import { bindChart, hBars } from '../components/charts.js';
import { sevBadge, ipText, tagEngine, tagEval, SEV_LABEL } from '../components/security.js';
import { createTable } from '../components/table.js';
import { openFlowDrawer } from '../components/flow-detail.js';
import { mountFlowMap, snapshotModel, liveModel } from '../components/flowmap.js';
import { store } from '../core/store.js';
import { go } from '../core/router.js';
import { flows, apiAvailable, subscribeLive, liveState, flowById, flagged, summary, timeline, evaluation, currentBudget, engine, DAYS } from '../data/index.js';
import { pageHead, panel, SEV_COLOR, curDay, dayName, scopeText, watch, detectedStrip, miniBars, donut, activityChart, valueBars } from './common.js';

const kpi = (label, value, foot, spark, tag = '') => html`
  <div class="kpi">
    <div class="metric-label">${label}${tag}</div>
    <div class="kpi-value num">${value}</div>
    <div class="kpi-spark">${spark}</div>
    <div class="metric-foot">${foot}</div>
  </div>`;

const budgetText = () => fmtPct(currentBudget(), currentBudget() < 0.01 ? 2 : 1).replace(/\.0+%/, '%');

function rocRows() {
  const ev = evaluation();
  const r = ev?.anomaly?.results || {};
  const eng = ev?.engine?.engine;
  const rows = [
    ['Isolation Forest', r.iforest, 'var(--m-if)'],
    ['Local Outlier Factor', r.lof, 'var(--m-lof)'],
    ['Autoencoder', r.ae, 'var(--m-ae)'],
    ['Mean of the three', r.ens_mean, 'var(--ink-3)'],
    ['MAVIS engine', eng, 'var(--m-engine)'],
  ].filter(([, v]) => v && v.roc_auc != null);
  return rows.map(([label, v, color]) => ({
    label, color, value: v.roc_auc, metric: 'ROC-AUC',
    extra: [['PR-AUC', v.pr_auc != null ? v.pr_auc.toFixed(3) : 'n/a']],
  }));
}

export default {
  title: 'Overview',
  render(root) {
    const paint = () => {
      const day = curDay();
      const s = summary(day);
      const dayFilter = day ? { day } : {};
      const alerts = flagged(dayFilter);
      const perDay = DAYS.map((d) => ({ d, s: summary(d.id) }));
      const dayLabels = perDay.map((x) => x.d.label);
      const hiCrit = (x) => (x.severity.critical || 0) + (x.severity.high || 0);
      const seenFam = new Set();
      const top5 = [...alerts].sort((a, b) => b.risk - a.risk).filter((f) => !seenFam.has(f.family) && seenFam.add(f.family)).slice(0, 5);
      const dayIdx = Object.fromEntries(DAYS.map((d, i) => [d.id, i]));
      const recent = [...alerts].sort((a, b) => (dayIdx[b.day] ?? 9) - (dayIdx[a.day] ?? 9) || b.row - a.row).slice(0, 8);
      const normal = Math.max(0, s.flows - s.alerts);
      const atDefault = currentBudget() === engine().alertBudgetFpr;

      mount(root, html`
        ${pageHead({ title: 'Overview' })}

        <div class="ov-band">
          <section class="ov-intro" aria-label="Summary">
            <p class="ov-context">CIC-IDS2017 capture week · <b class="num">${fmtInt(s.flows)}</b> flows analysed · alert budget <b class="num">${budgetText()}</b> ${day ? html`· showing ${dayName(day)}` : ''}</p>
            <p class="panel-meta">The public CSVs have no IP addresses or timestamps, so the console reports destination port, service and capture sequence instead.${atDefault ? '' : html` Totals below are fixed at the engine’s default ${fmtPct(engine().alertBudgetFpr)} budget; tables use your budget.`}</p>
            <div class="ov-actions">
              <a class="btn btn-primary" href="#analyze">Analyze a capture</a>
              <a class="btn" href="#threats">Open alert queue</a>
            </div>
            <section class="panel ov-flow" aria-label="Network flow">
              <div class="panel-head"><h2 class="panel-title">Network flow</h2><span class="panel-meta" id="fm-meta"></span><span class="spacer"></span><a class="linklike" href="#live">Live Monitor</a></div>
              <div class="panel-body"><div class="fm-host" id="fm-host"></div>
                <div class="legend-row" id="fm-legend"></div></div>
            </section>
          </section>
          <section class="ov-latest panel" aria-label="Latest detections">
            <div class="panel-head"><h2 class="panel-title">Latest detections</h2><span class="panel-meta">highest risk per attack type</span></div>
            ${top5.length ? html`<ol class="latest-list">${top5.map((f) => html`
              <li><button class="latest-row" data-open="${f.id}">
                <span class="latest-sev">${sevGlyph(f.severity)}<span class="visually-hidden">${SEV_LABEL[f.severity]}</span></span>
                <span class="latest-main"><b>${f.familyTitle || f.family}</b><span>${f.service} · port ${f.dst.port ?? 'n/a'}</span></span>
                <span class="latest-meta num">${dayName(f.day).split(' ')[0]}<br>risk ${Math.round(f.risk)}</span>
              </button></li>`)}</ol>` : html`<p class="panel-body panel-meta">No exported alerts at this budget for ${scopeText(day)}.</p>`}
          </section>
        </div>

        <div class="kpi-row">
          ${kpi('Flows analysed', fmtInt(s.flows), `${s.files} capture file${s.files === 1 ? '' : 's'}`,
            miniBars(perDay.map((x) => x.s.flows), dayLabels, { label: 'Flows', fmt: fmtInt }), tagEngine())}
          ${kpi('Alerts', fmtInt(s.alerts), `${fmtPct(s.alertRate, 2)} of flows`,
            miniBars(perDay.map((x) => x.s.alerts), dayLabels, { label: 'Alerts', fmt: fmtInt }), tagEngine())}
          ${kpi('High and Critical', fmtInt(hiCrit(s)), 'alerts rated High or Critical',
            miniBars(perDay.map((x) => hiCrit(x.s)), dayLabels, { label: 'High + Critical', fmt: fmtInt }), tagEngine())}
          ${kpi('Model agreement', fmtPct(s.agreement, 0), 'alerts confirmed by ≥2 detectors',
            miniBars(perDay.map((x) => x.s.agreement * 100), dayLabels, { label: 'Agreement %', fmt: (v) => `${v.toFixed(0)}%` }), tagEngine())}
        </div>

        <div class="ov-grid">
          ${panel({ title: 'Activity across the capture', tag: tagEngine(), meta: 'alerts vs normal flows per slice', cls: 'ov-activity',
            body: html`<div class="chart" id="ch-activity"></div>
              <div class="legend-row"><span class="legend-item"><i class="swatch" style="background:var(--accent)"></i>Alerts</span><span class="legend-item"><i class="swatch" style="background:var(--benign)"></i>Normal</span></div>
              <p class="panel-meta">Each file is cut into 48 equal slices in file order. The public CSVs have no timestamps, so left to right is row order within each capture file, not clock time.</p>` })}

          ${panel({ title: 'Risk distribution', tag: tagEngine(), cls: 'ov-risk',
            body: html`<div class="donut-wrap"><div class="chart donut" id="ch-risk"></div>
              <ul class="legend-list">${[['critical', s.severity.critical], ['high', s.severity.high], ['medium', s.severity.medium], ['low', s.severity.low], ['none', normal]].map(([k, v]) => html`
                <li><i class="swatch" style="background:${SEV_COLOR[k]}"></i><span>${SEV_LABEL[k]}</span><b class="num">${fmtInt(v || 0)}</b></li>`)}</ul></div>` })}

          ${panel({ title: 'Model performance (ROC-AUC)', tag: tagEval(), cls: 'ov-roc',
            body: html`<div class="chart" id="ch-roc"></div>
              <p class="panel-meta">Detector rows: held-out evaluation (anomaly report). The engine row is measured on a random split of the same capture days, so it is optimistic about new networks; the zero-day test on <a href="#models">ML Models</a> is the harder check.</p>` })}

          ${panel({ title: 'Recent detections', meta: 'last in capture sequence', cls: 'ov-recent', bodyCls: 'flush',
            actions: html`<a class="linklike" href="#threats">View all</a>`, body: html`<div id="recent"></div>` })}

          ${panel({ title: 'Attack type distribution', tag: tagEngine(), cls: 'ov-types',
            body: html`<div class="chart" id="ch-types"></div>` })}
        </div>`);

      // charts
      const files = timeline(day);
      bindChart($('#ch-activity', root), (w) => activityChart(w, 220, { files, label: 'Alerts and normal flows per capture slice' }));
      bindChart($('#ch-risk', root), () => donut(176, {
        rows: ['critical', 'high', 'medium', 'low', 'none'].map((k) => ({ label: SEV_LABEL[k], value: k === 'none' ? normal : (s.severity[k] || 0), color: SEV_COLOR[k] })),
        centre: fmtCompact(s.flows), sub: 'flows', label: `Risk distribution of ${fmtInt(s.flows)} flows`,
      }));
      const roc = rocRows();
      if (roc.length) bindChart($('#ch-roc', root), (w) => valueBars(w, 0, { rows: roc, labelWidth: 132, label: 'ROC-AUC per detector and engine' }));
      else mount($('#ch-roc', root), html`<p class="panel-meta">Evaluation reports are not in the snapshot.</p>`);
      const fam = Object.entries(s.families).sort((a, b) => b[1] - a[1]);
      bindChart($('#ch-types', root), (w) => hBars(w, 0, {
        rows: fam.map(([k, v]) => ({ label: k, value: v, color: k === 'Novel' ? 'var(--signal)' : 'var(--accent)' })),
        label: 'Alerts per attack type', labelWidth: 110, showShare: true, scale: 'log',
      }));

      createTable($('#recent', root), {
        rows: recent, pageSize: 8, caption: 'Recent detections',
        onRowClick: (f) => openFlowDrawer(f.id),
        emptyTitle: 'No alerts', emptyText: 'Nothing is flagged at this budget for the selected day.',
        columns: [
          { key: 'when', label: 'Capture', sortable: false, render: (f) => html`${dayName(f.day).split(' ')[0]} <span class="muted num">#${fmtInt(f.row)}</span>` },
          { key: 'dst', label: 'Destination', sortable: false, render: (f) => html`${ipText(null, f.dst.port)} <span class="muted">${f.service}</span>` },
          { key: 'family', label: 'Attack type', sortable: false, render: (f) => f.familyTitle || f.family },
          { key: 'risk', label: 'Risk', sortable: false, render: (f) => html`${sevBadge(f.severity)} <span class="mono">${Math.round(f.risk)}</span>` },
          { key: 'by', label: 'Detected by', sortable: false, render: (f) => detectedStrip(f) },
        ],
      });
    };

    let map = null, stopLive = null, lastMap = 0;
    const LIVE_WINDOW = 600;
    const drawMap = () => {
      const host = $('#fm-host', root);
      if (!host) return;
      const ls = liveState();
      const liveOn = ls.available && ls.sensor?.connected && ls.stats.flows > 0;
      const list = liveOn ? flows({ day: 'live' }).slice(-LIVE_WINDOW) : flows(curDay() ? { day: curDay() } : {});
      const model = (liveOn ? liveModel : snapshotModel)(list);
      $('#fm-meta', root).textContent = liveOn ? `live · last ${fmtInt(list.length)} flows · ${ls.sensor.iface || 'sensor'}` : 'CIC-IDS2017 snapshot · exported sample';
      mount($('#fm-legend', root), html`<span class="legend-item"><i class="swatch" style="background:var(--ink-3)"></i>Normal</span>${['high', 'critical'].map((k) => html`<span class="legend-item"><i class="swatch" style="background:${SEV_COLOR[k]}"></i>${SEV_LABEL[k]}</span>`)}<span class="legend-item panel-meta">width = flows</span>`);
      map ||= mountFlowMap(host, { onLink: (lk) => {
        if (liveOn) {
          const f = [...list].reverse().find((x) => (x.src?.ip || 'unknown') === lk.from && x.id === lk.last) || flowById(lk.last);
          if (f) openFlowDrawer(f.id);
        } else if (lk.kind === 'normal') { store.setSession('explorerFilters', { verdict: 'normal' }); go('explorer'); }
        else { store.session.threatFilters = { sevs: ['critical', 'high', 'medium', 'low'], family: lk.from, mode: '', confidence: '', status: 'all', q: '' }; go('threats'); }
      } });
      map.update(model);
    };
    paint();
    drawMap();
    apiAvailable().then((ok) => {
      if (!ok || !root.isConnected) return;
      stopLive = subscribeLive(() => { if (Date.now() - lastMap > 3000) { lastMap = Date.now(); drawMap(); } });
    });
    on(root, 'click', '[data-open]', (_e, b) => openFlowDrawer(b.dataset.open));
    const unwatch = watch(() => { paint(); map?.destroy(); map = null; drawMap(); });
    return () => { unwatch?.(); stopLive?.(); map?.destroy(); };
  },
};
