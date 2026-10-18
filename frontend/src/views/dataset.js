// Dataset Analysis: everything here is measured from the raw files (reports/raw_data_profile.json).
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { fmtInt, fmtBytes, fmtPct } from '../core/format.js';
import { icon } from '../components/icons.js';
import { bindChart, hBars } from '../components/charts.js';
import { toast } from '../components/overlays.js';
import { tagReal, tagEval, infoCallout } from '../components/security.js';
import { createTable } from '../components/table.js';
import { emptyState } from '../components/states.js';
import { datasetProfile, cicSummary, evaluation } from '../data/index.js';
import { pageHead, panel, remount } from './common.js';

const FAMILIES = [
  ['Flow', /^(Flow|Destination Port|Down\/Up|Average Packet Size|Min Packet|Max Packet|Packet Length)/],
  ['Forward', /^(Fwd|Total Fwd|Total Length of Fwd|Avg Fwd|Subflow Fwd|act_data_pkt_fwd|min_seg_size_forward|Init_Win_bytes_forward)/],
  ['Backward', /^(Bwd|Total Backward|Total Length of Bwd|Avg Bwd|Subflow Bwd|Init_Win_bytes_backward)/],
  ['Flags', /Flag Count$|PSH Flags|URG Flags/],
  ['Active / idle', /^(Active|Idle)/],
];
const familyOf = (c) => (c === 'Label' ? 'Target' : (FAMILIES.find(([, re]) => re.test(c)) || ['Other'])[0]);
const dayOf = (src) => src.split('-')[0].replace(/^./, (x) => x.toUpperCase());

const catOrder = ['Benign', 'DoS', 'DDoS', 'PortScan', 'BruteForce', 'WebAttack', 'Bot', 'Infiltration', 'Heartbleed'];

// What preprocessing did to the raw rows before training (reports/preprocess_report_anomaly.json).
function preprocessPanel() {
  const pr = evaluation()?.preprocess;
  if (!pr) return panel({ title: 'Preprocessing', body: html`<p class="panel-meta">The preprocessing report is not in the snapshot. Run <code>python scripts/export_frontend.py</code>.</p>` });
  const splits = Object.entries(pr.splits || {});
  const cats = catOrder.filter((c) => splits.some(([, v]) => v.categories?.[c]));
  return panel({ title: 'Preprocessing', tag: tagEval('From the pipeline'), cls: 'span-3',
    meta: `seed ${pr.seed} · benign training source: ${pr.benign_source}`,
    body: html`
      <div class="prep-grid">
        <dl class="kv">
          <dt>Rows loaded</dt><dd class="mono">${fmtInt(pr.rows_loaded)}</dd>
          <dt>Dropped: NaN or infinite</dt><dd class="mono">${fmtInt(pr.rows_dropped_nan_or_inf)}</dd>
          <dt>Dropped: duplicates</dt><dd class="mono">${fmtInt(pr.rows_dropped_duplicate)}</dd>
          <dt>Conflicting labels</dt><dd class="mono">${fmtInt(pr.flows_with_conflicting_labels)} <span class="muted">identical flows carrying different labels</span></dd>
          <dt>Clean rows</dt><dd class="mono"><b>${fmtInt(pr.rows_clean)}</b> <span class="muted">${fmtPct(pr.rows_clean / pr.rows_loaded)} of loaded</span></dd>
          <dt>Features kept</dt><dd class="mono">${pr.features?.length ?? 'n/a'}</dd>
          <dt>Dropped columns (${pr.dropped_columns?.length ?? 0})</dt><dd><div class="tag-list" style="margin:0">${(pr.dropped_columns || []).map((c) => html`<span class="tag">${c}</span>`)}</div><span class="panel-meta">Constant in the data, so they carry no signal.</span></dd>
        </dl>
        <div class="table-wrap"><table class="table table-tight">
          <caption class="visually-hidden">Rows per split and category</caption>
          <thead><tr><th scope="col">Category</th>${splits.map(([k]) => html`<th scope="col" class="r">${k}</th>`)}</tr></thead>
          <tbody>${cats.map((c) => html`<tr><td>${c}</td>${splits.map(([, v]) => html`<td class="r mono">${v.categories?.[c] ? fmtInt(v.categories[c]) : html`<span class="muted">0</span>`}</td>`)}</tr>`)}
            <tr class="total-row"><td>Total</td>${splits.map(([, v]) => html`<td class="r mono"><b>${fmtInt(v.rows)}</b></td>`)}</tr></tbody></table></div>
      </div>
      <p class="panel-meta">Detectors train on the benign split only (Monday traffic). The test split holds every attack family plus the remaining benign flows.</p>` });
}

export default {
  title: 'Dataset Analysis',
  render(root) {
    const which = store.session.dataset || 'cic';
    const cic = cicSummary();
    const unsw = datasetProfile.files.filter((f) => f.dataset === 'UNSW-NB15');
    const files = which === 'cic' ? cic.files : unsw;
    const rows = files.reduce((a, f) => a + f.rows, 0);
    const bytes = files.reduce((a, f) => a + f.fileSizeBytes, 0);
    const missing = files.reduce((a, f) => a + Object.values(f.missingValues).reduce((x, y) => x + y, 0), 0);
    const infinite = files.reduce((a, f) => a + f.infiniteValues, 0);
    const dups = files.reduce((a, f) => a + f.duplicateRows, 0);
    const earlier = files.reduce((a, f) => a + f.rowsSeenEarlier, 0);
    const labels = {};
    files.forEach((f) => Object.entries(f.targetCounts).forEach(([k, v]) => { labels[k] = (labels[k] || 0) + v; }));
    const constantAll = files[0].constantColumns.filter((c) => files.every((f) => f.constantColumns.includes(c)) && c !== 'Label');
    let scale = 'log';

    mount(root, html`
      ${pageHead({
        title: 'Dataset Analysis',
        sub: 'Raw file profile and the preprocessing that turns it into training data. File numbers were measured from the files; preprocessing numbers come from the pipeline report.',
        actions: html`
          <div class="segmented" role="group" aria-label="Dataset">
            <button data-ds="cic" aria-pressed="${which === 'cic'}">CIC-IDS2017</button>
            <button data-ds="unsw" aria-pressed="${which === 'unsw'}">UNSW-NB15</button>
          </div>
          <button class="btn" data-action="copy">${icon('copy')}Copy summary</button>`,
      })}

      ${which === 'unsw' ? infoCallout(html`<b>UNSW-NB15 is profiled but kept separate.</b> ${datasetProfile.notes[1]} MAVIS’s primary dataset is CIC-IDS2017.`) : ''}

      <div class="ds-stats">
        <div class="metric metric-hero"><div class="metric-label">Rows ${tagReal()}</div><div class="metric-value num" data-count-to="${rows}">${fmtInt(rows)}</div><div class="metric-foot">${files.length} files · ${fmtBytes(bytes)}</div></div>
        <div class="metric"><div class="metric-label">Columns</div><div class="metric-value num">${files[0].columns}</div><div class="metric-foot">${files[0].numericColumns} numeric · target <code>${files[0].target}</code></div></div>
        <div class="metric"><div class="metric-label">Missing values</div><div class="metric-value num">${fmtInt(missing)}</div><div class="metric-foot">${which === 'cic' ? 'All in Flow Bytes/s' : 'None found'}</div></div>
        <div class="metric"><div class="metric-label">Infinite values</div><div class="metric-value num">${fmtInt(infinite)}</div><div class="metric-foot">Need clipping or removal</div></div>
        <div class="metric"><div class="metric-label">Duplicate rows</div><div class="metric-value num">${fmtInt(dups)}</div><div class="metric-foot">${fmtPct(dups / rows)} within files · ${fmtInt(earlier)} repeat earlier files</div></div>
      </div>

      <div class="ds-grid">
        ${panel({ title: 'Label distribution', tag: tagReal(), cls: 'span-2',
          actions: html`<div class="segmented" role="group" aria-label="Scale"><button data-scale="log" aria-pressed="true">Log</button><button data-scale="linear" aria-pressed="false">Linear</button></div>`,
          body: html`<div class="chart" id="ch-labels"></div><p class="panel-meta" style="margin-top:10px">${which === 'cic' ? 'Classes range from 2.27 million benign flows to 11 Heartbleed flows. A log scale keeps the rare classes visible; switch to linear to see the true imbalance.' : 'UNSW-NB15 is labelled 0 (normal) or 1 (attack) in this export.'}</p>` })}

        ${panel({ title: 'Data quality', tag: tagReal(), body: html`
          <ul class="quality">
            <li data-tone="${missing ? 'warn' : 'ok'}">${icon(missing ? 'alert' : 'check')}<div><b>${fmtInt(missing)} missing values</b><span>${which === 'cic' ? 'Only in Flow Bytes/s, where flow duration is 0.' : 'No missing values.'}</span></div></li>
            <li data-tone="${infinite ? 'warn' : 'ok'}">${icon(infinite ? 'alert' : 'check')}<div><b>${fmtInt(infinite)} infinite values</b><span>Rates divided by a zero duration.</span></div></li>
            <li data-tone="warn">${icon('layers')}<div><b>${fmtInt(dups)} duplicate rows</b><span>Detected with a stable row hash, including across files.</span></div></li>
            <li data-tone="${constantAll.length ? 'warn' : 'ok'}">${icon(constantAll.length ? 'filter' : 'check')}<div><b>${constantAll.length} constant columns in every file</b><span>${constantAll.length ? 'Carry no signal and can be dropped.' : 'None.'}</span></div></li>
          </ul>` })}

        ${which === 'cic' ? preprocessPanel() : ''}

        ${panel({ title: 'Files', tag: tagReal(), cls: 'span-3', bodyCls: 'flush', body: html`<div id="ds-files"></div>` })}

        ${panel({ title: 'Feature catalogue', tag: tagReal(), cls: 'span-2', meta: `${files[0].columns} columns`,
          actions: html`<div class="search" style="width:200px">${icon('search')}<input class="input" id="feat-q" type="search" placeholder="Filter features" aria-label="Filter features"></div>`,
          body: html`<div id="features"></div>` })}

        ${panel({ title: 'Data preview', body: emptyState({ icon: 'database', title: 'Row preview needs the raw files', text: 'The CSV and Parquet files live in /dataset/, which is excluded from git. This page reads the committed profile only, so it cannot show individual rows.' }) })}
      </div>`);

    // Label chart
    const labelRows = () => Object.entries(labels).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({
      label: k === 'BENIGN' || k === '0' ? (k === '0' ? 'Normal (0)' : 'Benign') : k === '1' ? 'Attack (1)' : k,
      value: v,
      color: k === 'BENIGN' || k === '0' ? 'var(--benign)' : 'var(--accent)',
    }));
    const drawLabels = () => bindChart($('#ch-labels', root), (w) => hBars(w, 0, { rows: labelRows(), label: 'Rows per label', scale, labelWidth: 190, showShare: true }));
    drawLabels();

    // Files table
    createTable($('#ds-files', root), {
      rows: files.map((f) => ({ ...f, id: f.source })), pageSize: 20, caption: 'Profiled files',
      initialSort: { key: 'rows', dir: 'desc' },
      expandable: (f) => html`<div class="file-detail">
        <div><h4 class="section-title">Labels</h4><dl class="kv">${Object.entries(f.targetCounts).map(([k, v]) => html`<dt>${k}</dt><dd class="mono">${fmtInt(v)}</dd>`)}</dl></div>
        <div><h4 class="section-title">Constant columns (${f.constantColumns.length})</h4><div class="tag-list">${f.constantColumns.map((c) => html`<span class="tag">${c}</span>`)}</div></div>
      </div>`,
      columns: [
        { key: 'source', label: 'File', render: (f) => html`<span style="display:inline-flex;gap:8px;align-items:center">${icon('chevronDown', { cls: 'row-caret' })}<span class="mono" style="font-size:12px">${f.source}</span></span>` },
        { key: 'day', label: 'Capture day', sort: (f) => f.source, render: (f) => (f.dataset === 'CIC-IDS2017' ? dayOf(f.source) : f.source.includes('train') ? 'Training split' : 'Testing split') },
        { key: 'rows', label: 'Rows', align: 'right', render: (f) => html`<span class="mono">${fmtInt(f.rows)}</span>` },
        { key: 'fileSizeBytes', label: 'Size', align: 'right', render: (f) => html`<span class="mono">${fmtBytes(f.fileSizeBytes)}</span>` },
        { key: 'attack', label: 'Attack share', align: 'right', sort: (f) => 1 - (f.targetCounts.BENIGN ?? f.targetCounts['0'] ?? 0) / f.rows, render: (f) => html`<span class="mono">${fmtPct(1 - (f.targetCounts.BENIGN ?? f.targetCounts['0'] ?? 0) / f.rows)}</span>` },
        { key: 'infiniteValues', label: 'Infinite', align: 'right', render: (f) => html`<span class="mono">${fmtInt(f.infiniteValues)}</span>` },
        { key: 'duplicateRows', label: 'Duplicates', align: 'right', render: (f) => html`<span class="mono">${fmtInt(f.duplicateRows)}</span>` },
        { key: 'rowsSeenEarlier', label: 'Seen earlier', align: 'right', render: (f) => html`<span class="mono">${fmtInt(f.rowsSeenEarlier)}</span>` },
      ],
    });

    // Feature catalogue
    const cols = which === 'cic' ? datasetProfile.cicColumns : null;
    const paintFeatures = (q = '') => {
      if (!cols) { mount($('#features', root), html`<p class="panel-meta">The UNSW-NB15 export has ${files[0].columns} columns, including categorical <code>${files[0].categoricalColumns.join(', ')}</code>. The column catalogue is shown for CIC-IDS2017, the primary dataset.</p>`); return; }
      const groups = {};
      cols.filter((c) => c.toLowerCase().includes(q.toLowerCase())).forEach((c) => { (groups[familyOf(c)] ||= []).push(c); });
      mount($('#features', root), Object.keys(groups).length ? html`<div class="feature-groups">${Object.entries(groups).map(([g, list]) => html`
        <div class="feature-group"><h4 class="section-title">${g} <span class="panel-meta">${list.length}</span></h4>
          <div class="tag-list">${list.map((c) => html`<span class="tag ${constantAll.includes(c) ? 'is-constant' : ''}" title="${constantAll.includes(c) ? 'Constant in every file' : ''}">${c}${constantAll.includes(c) ? html` <span class="visually-hidden">(constant)</span>${icon('close', { cls: 'tag-x' })}` : ''}</span>`)}</div></div>`)}</div>
        <div class="legend" style="margin-top:10px"><span class="legend-item">${icon('close', { cls: 'tag-x' })}Constant in every file, safe to drop</span></div>`
        : emptyState({ title: 'No feature matches', text: `Nothing in the ${cols.length} columns contains “${q}”.`, icon: 'search' }));
    };
    paintFeatures();

    on(root, 'input', '#feat-q', (_e, i) => paintFeatures(i.value));
    on(root, 'click', '[data-scale]', (_e, b) => {
      scale = b.dataset.scale;
      root.querySelectorAll('[data-scale]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      drawLabels();
    });
    on(root, 'click', '[data-ds]', (_e, b) => { store.session.dataset = b.dataset.ds; remount(this, root); });
    on(root, 'click', '[data-action="copy"]', async () => {
      const name = which === 'cic' ? 'CIC-IDS2017' : 'UNSW-NB15';
      const text = [`${name} raw profile (from reports/raw_data_profile.json)`, `Rows: ${fmtInt(rows)} in ${files.length} files (${fmtBytes(bytes)})`, `Missing: ${fmtInt(missing)} · Infinite: ${fmtInt(infinite)} · Duplicates: ${fmtInt(dups)}`,
        'Labels:', ...Object.entries(labels).sort((a, b) => b[1] - a[1]).map(([k, v]) => `  ${k}: ${fmtInt(v)}`)].join('\n');
      try { await navigator.clipboard.writeText(text); toast('Profile summary copied'); }
      catch { toast('Copy is blocked in this view. Select the numbers on the page instead.', { tone: 'warn' }); }
    });
  },
};
