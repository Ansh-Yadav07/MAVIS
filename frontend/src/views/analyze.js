// Analyze capture: send a CICFlowMeter CSV to the local MAVIS engine and read the result.
// The static site (Netlify) has no engine, so this page explains how to start it instead.
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { go } from '../core/router.js';
import { fmtInt, fmtPct, fmtBytes } from '../core/format.js';
import { icon } from '../components/icons.js';
import { sevBadge, tagUpload, tagEngine, infoCallout } from '../components/security.js';
import { createTable } from '../components/table.js';
import { openFlowDrawer } from '../components/flow-detail.js';
import { apiAvailable, analyzeCsv, flagged } from '../data/index.js';
import { pageHead, panel, ratioBar, pctText, watch, detectedStrip } from './common.js';

const CATS = ['Benign', 'DoS', 'DDoS', 'PortScan', 'BruteForce', 'WebAttack', 'Bot', 'Infiltration', 'Heartbleed'];
const sevKey = (s) => String(s || '').toLowerCase();

const unavailable = html`
  <div class="api-panel" role="status">
    <div>${icon('cpu')}</div>
    <div>
      <h2 class="panel-title">Live analysis needs the local engine</h2>
      <p>This page is served without the MAVIS engine, so a capture cannot be analysed here. To enable it, run the local server from the repository root and open the console through it:</p>
      <pre class="codeblock"><code>python scripts/serve.py</code></pre>
      <p>then open <a href="http://localhost:8000">http://localhost:8000</a>. The server loads the trained engine from <code>results/engine</code> and serves this same console, with the analysis endpoint switched on.</p>
      <p class="panel-meta">Everything else in the console works without it: it shows the engine’s results for the CIC-IDS2017 capture week from the committed snapshot. Docs: <code>frontend/README.md</code> and the header of <code>scripts/serve.py</code>.</p>
    </div>
  </div>`;

function resultView(cap) {
  const s = cap.summary || {};
  const dq = cap.data_quality || {};
  const gt = cap.ground_truth;
  const sev = s.severity || {};
  const hi = (sev.critical || 0) + (sev.high || 0);
  const warn = [];
  if (dq.missing_feature_columns?.length) warn.push(html`<b>${dq.missing_feature_columns.length} feature columns are missing</b> and were filled with benign medians: <span class="mono">${dq.missing_feature_columns.slice(0, 12).join(', ')}${dq.missing_feature_columns.length > 12 ? ', …' : ''}</span>.`);
  if (dq.rows_with_missing_or_infinite_values) warn.push(html`<b>${fmtInt(dq.rows_with_missing_or_infinite_values)} rows</b> had missing or infinite values; they were repaired before scoring.`);
  if (dq.reduced_confidence) warn.push(html`<b>Reduced confidence:</b> more than 30% of the expected columns are missing, so verdicts are less reliable. Check the flow exporter settings.`);
  const top = flagged({ upload: true }).filter((f) => f.file === cap.file).sort((a, b) => b.risk - a.risk);
  return html`
    <div class="kpi-row">
      ${[['Flows analysed', fmtInt(s.flows || 0), cap.file], ['Alerts', fmtInt(s.alerts || 0), `${fmtPct(s.flows ? s.alerts / s.flows : 0, 2)} of flows`],
        ['High and Critical', fmtInt(hi), 'alerts rated High or Critical'], ['Novel alerts', fmtInt(s.detection_modes?.novel || 0), 'anomalous, no known family']].map(([l, v, foot]) => html`
        <div class="kpi"><div class="metric-label">${l}${tagUpload()}</div><div class="kpi-value num">${v}</div><div class="metric-foot">${foot}</div></div>`)}
    </div>

    ${warn.length ? html`<div class="callout" data-tone="warn" role="alert">${icon('alert')}<div><b>Data quality</b><ul class="plain-list">${warn.map((w) => html`<li>${w}</li>`)}</ul></div></div>`
      : infoCallout('All expected feature columns were present and no unusable values were found.')}

    <div class="ov-grid">
      ${panel({ title: 'Verdicts and severity', tag: tagEngine(), cls: 'span-1', body: html`
        <dl class="kv">
          ${['normal', 'malicious', 'suspicious'].map((k) => html`<dt>${k === 'malicious' ? 'Malicious (known family)' : k === 'suspicious' ? 'Suspicious (novel)' : 'Normal'}</dt><dd class="mono">${fmtInt(s.verdicts?.[k] || 0)}</dd>`)}
        </dl>
        <hr class="rule">
        <dl class="kv">${['critical', 'high', 'medium', 'low'].map((k) => html`<dt>${sevBadge(k)}</dt><dd class="mono">${fmtInt(sev[k] || 0)}</dd>`)}</dl>` })}
      ${panel({ title: 'Attack types', tag: tagEngine(), cls: 'span-1', body: Object.keys(s.threat_families || {}).length
        ? html`<dl class="kv">${Object.entries(s.threat_families).sort((a, b) => b[1] - a[1]).map(([k, v]) => html`<dt>${k}</dt><dd class="mono">${fmtInt(v)}</dd>`)}</dl>` : html`<p class="panel-meta">No alerts.</p>` })}
      ${panel({ title: 'Drift check', tag: tagEngine(), cls: 'span-1', body: html`
        <p><b>${cap.drift?.status || 'n/a'}</b>${cap.drift?.features_drifted != null ? html` · ${cap.drift.features_drifted} drifted features` : ''}</p>
        ${(cap.drift?.top || []).length ? html`<dl class="kv">${cap.drift.top.map((t) => html`<dt>${t.feature}</dt><dd class="mono">PSI ${t.psi}</dd>`)}</dl>` : ''}
        <p class="panel-meta">Whether normal-looking traffic resembles the benign baseline the engine learned.</p>` })}
    </div>

    ${panel({ title: 'Incidents', tag: tagEngine(), body: (cap.incidents || []).length ? html`<ol class="incident-list">${cap.incidents.slice(0, 10).map((i) => html`
      <li><div class="inc-head">${sevBadge(sevKey(i.severity))}<b>${i.title}</b></div>
        <div class="inc-meta"><span class="mono">${fmtInt(i.flows)} flows</span><span class="mono">max risk ${Math.round(i.max_risk)}</span>${i.src_ip ? html`<span class="mono">from ${i.src_ip}</span>` : ''}${i.distinct_dst_ports ? html`<span class="mono">${fmtInt(i.distinct_dst_ports)} destination ports</span>` : ''}</div>
        ${i.actions?.length ? html`<div class="panel-meta">Suggested: ${i.actions.slice(0, 2).join(' ')}</div>` : ''}</li>`)}</ol>` : html`<p class="panel-meta">No incidents.</p>` })}

    ${panel({ title: 'Insights', tag: tagEngine(), body: html`<ul class="recs">${(cap.insights || []).map((t) => html`<li>${t}</li>`)}</ul>` })}

    ${gt ? panel({ title: 'Ground truth (the file has labels)', tag: tagEngine(), body: html`
      <p>Precision <b>${pctText(gt.precision)}</b> · recall <b>${pctText(gt.recall)}</b> · F1 <b>${gt.f1?.toFixed(3)}</b> · false-positive rate <b>${pctText(gt.fpr, 2)}</b></p>
      <div class="table-wrap"><table class="table table-tight"><thead><tr><th scope="col">Category</th><th scope="col" class="r">Flows</th><th scope="col">Alerted</th><th scope="col" class="r">Named correctly</th></tr></thead>
        <tbody>${CATS.filter((c) => gt.per_category?.[c]).map((c) => html`<tr><td>${c}</td><td class="r mono">${fmtInt(gt.per_category[c].n)}</td><td>${ratioBar(gt.per_category[c].alerted)}</td><td class="r mono">${c === 'Benign' ? '' : pctText(gt.per_category[c].named_correctly)}</td></tr>`)}</tbody></table></div>` }) : ''}

    ${panel({ title: 'Highest-risk alerts', tag: tagUpload(), meta: `${fmtInt(top.length)} exported alerts`, bodyCls: 'flush',
      actions: html`<button class="btn btn-sm btn-primary" data-open-explorer ${top.length ? '' : html`disabled`}>Open in Event Explorer</button><button class="btn btn-sm" data-open-queue ${top.length ? '' : html`disabled`}>Open alert queue</button>`,
      body: html`<div id="up-table"></div>` })}`;
}

export default {
  title: 'Analyze capture',
  render(root) {
    const st = { api: null, phase: 'idle', cap: null, error: '', file: null };

    const paint = () => {
      const busy = st.phase === 'uploading' || st.phase === 'analysing';
      mount(root, html`
        ${pageHead({ title: 'Analyze capture', sub: 'Upload a CICFlowMeter CSV and the trained engine scores every flow: verdict, severity, attack family and the reasons behind it.' })}
        ${st.api === null ? html`<p class="panel-meta" role="status">Checking for the local engine…</p>`
          : st.api === false ? unavailable : ''}
        <section class="dropzone ${st.api ? '' : 'is-off'}" id="drop" aria-label="Upload a capture" aria-disabled="${!st.api || busy}">
          <div class="drop-icon">${icon('database')}</div>
          <div class="drop-text">
            <b>${busy ? 'Uploading and analysing…' : 'Drop a CSV here'}</b>
            <span>${st.file ? `${st.file.name} · ${fmtBytes(st.file.size)}` : 'CICFlowMeter output (.csv). Column names are matched leniently; missing columns are reported.'}</span>
          </div>
          <label class="btn ${st.api && !busy ? 'btn-primary' : ''}" ${st.api && !busy ? '' : html`aria-disabled="true"`}>Choose file
            <input type="file" id="file" accept=".csv,text/csv" class="visually-hidden" ${st.api && !busy ? '' : html`disabled`}></label>
          ${busy ? html`<div class="progress indeterminate" role="progressbar" aria-label="${st.phase}" aria-busy="true"><span></span></div>` : ''}
        </section>
        ${st.error ? html`<div class="callout" data-tone="error" role="alert">${icon('alert')}<div><b>Analysis failed.</b> ${st.error}</div></div>` : ''}
        ${st.cap ? resultView(st.cap) : ''}`);

      if (st.cap) {
        const rows = flagged({ upload: true }).filter((f) => f.file === st.cap.file).sort((a, b) => b.risk - a.risk);
        createTable($('#up-table', root), {
          rows, pageSize: 10, caption: 'Uploaded capture alerts', onRowClick: (f) => openFlowDrawer(f.id),
          rowAttrs: (f) => ({ 'data-sev': f.severity }),
          columns: [
            { key: 'row', label: 'Row', render: (f) => html`<span class="mono">#${fmtInt(f.row)}</span>` },
            { key: 'family', label: 'Attack type', sort: (f) => f.familyTitle || '', render: (f) => f.familyTitle || f.family },
            { key: 'dst', label: 'Destination', sort: (f) => f.dst.port ?? -1, render: (f) => html`<span class="mono">${f.dst.port ?? 'n/a'}</span> <span class="muted">${f.service}</span>` },
            { key: 'risk', label: 'Risk', className: 'sev-cell', render: (f) => html`${sevBadge(f.severity)} <span class="mono">${Math.round(f.risk)}</span>` },
            { key: 'by', label: 'Detected by', sortable: false, render: (f) => detectedStrip(f) },
          ],
        });
      }
    };

    async function run(file) {
      if (!file || !st.api || st.phase === 'uploading' || st.phase === 'analysing') return;
      st.file = file; st.error = ''; st.cap = null; st.phase = 'analysing';
      paint();
      try {
        st.cap = await analyzeCsv(file);
        st.phase = 'done';
      } catch (err) {
        st.error = err?.message || String(err);
        st.phase = 'error';
      }
      paint();
    }

    paint();
    apiAvailable().then((ok) => { st.api = !!ok; paint(); });

    on(root, 'change', '#file', (_e, input) => { run(input.files?.[0]); });
    on(root, 'dragover', '#drop', (ev, el) => { ev.preventDefault(); if (st.api) el.classList.add('is-over'); });
    on(root, 'dragleave', '#drop', (_e, el) => el.classList.remove('is-over'));
    on(root, 'drop', '#drop', (ev, el) => { ev.preventDefault(); el.classList.remove('is-over'); run(ev.dataTransfer?.files?.[0]); });
    on(root, 'click', '[data-open-explorer]', () => {
      const top = flagged({ upload: true }).filter((f) => f.file === st.cap.file).sort((a, b) => b.risk - a.risk)[0];
      if (top) go('explorer', top.id);
    });
    on(root, 'click', '[data-open-queue]', () => { store.session.uploadOnly = true; go('threats'); });
    return watch((ev) => { if (ev.type === 'pref' || ev.type === 'edit') paint(); });
  },
};
