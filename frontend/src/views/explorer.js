// Event Explorer: every flow the snapshot (and any uploaded capture) holds, with search,
// filters, sortable columns, paging and CSV export. A flow id in the URL opens its drawer.
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { fmtInt, fmtPct } from '../core/format.js';
import { icon } from '../components/icons.js';
import { sevBadge, statusBadge, modelStrip, riskCell, modeTag, outcomeTag, dayLabel, tagEngine, infoCallout } from '../components/security.js';
import { createTable } from '../components/table.js';
import { openFlowDrawer } from '../components/flow-detail.js';
import { toast } from '../components/overlays.js';
import { flows, flowById, captures, DAYS, currentBudget } from '../data/index.js';
import { pageHead, panel } from './common.js';

const SEV_RANK = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
const fresh = () => ({ q: '', verdict: '', family: '', category: '', outcome: '', day: '', file: '', upload: '' });

const csvCell = (v) => {
  const s = v == null ? '' : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
const CSV_COLS = [
  ['id', (f) => f.id], ['day', (f) => f.day], ['file', (f) => f.file], ['row', (f) => f.row], ['dst_port', (f) => f.dst.port],
  ['service', (f) => f.service], ['label', (f) => f.label], ['category', (f) => f.category], ['verdict', (f) => f.verdict],
  ['family', (f) => f.family], ['mode', (f) => f.mode], ['confidence', (f) => f.confidence], ['severity', (f) => f.severity],
  ['risk', (f) => f.risk], ['p_known', (f) => f.pKnown], ['anomaly_pct', (f) => f.anomalyPct],
  ['pct_if', (f) => f.pct.if], ['pct_lof', (f) => f.pct.lof], ['pct_ae', (f) => f.pct.ae], ['pct_ecod', (f) => f.pct.ecod], ['outcome', (f) => f.outcome], ['status', (f) => f.status],
];
function downloadCsv(list) {
  const body = [CSV_COLS.map(([h]) => h).join(','), ...list.map((f) => CSV_COLS.map(([, g]) => csvCell(g(f))).join(','))].join('\n');
  const url = URL.createObjectURL(new Blob([body], { type: 'text/csv;charset=utf-8' }));
  const a = Object.assign(document.createElement('a'), { href: url, download: `mavis-flows-${list.length}.csv` });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const opt = (value, label, cur) => html`<option value="${value}" ${cur === value ? html`selected` : ''}>${label}</option>`;

export default {
  title: 'Event Explorer',
  crumb: (param) => param || null,
  render(root, param) {
    const filters = { ...fresh(), ...(store.session.explorerFilters || {}) };
    if (store.session.query) { filters.q = store.session.query; store.session.query = ''; }
    const gday = store.session.day || '';
    const all = flows();
    const families = [...new Set(all.map((f) => f.family).filter(Boolean))].sort();
    const cats = [...new Set(all.map((f) => f.category).filter(Boolean))].sort();
    const files = [...new Set(captures().map((c) => c.file))];
    const hasLabels = cats.length > 0;
    let current = [];

    mount(root, html`
      ${pageHead({
        title: 'Event Explorer',
        sub: html`Every exported flow with the engine's verdict at the <b>${fmtPct(currentBudget(), 1)}</b> alert budget. The public CSVs carry no IPs or timestamps, so rows are identified by capture file and row.`,
        actions: html`${tagEngine()}<button class="btn" data-action="export">${icon('external')}Export CSV</button>`,
      })}
      ${all.length ? '' : infoCallout('The snapshot holds no flows.')}
      <div class="filter-bar">
        <div class="search">${icon('search')}
          <input class="input" id="ex-q" type="search" placeholder="Id, port, service, label, family, verdict" aria-label="Search flows" value="${filters.q}"></div>
        <label class="fl">Verdict<select class="select" id="ex-verdict">${opt('', 'Any', filters.verdict)}${['normal', 'malicious', 'suspicious'].map((v) => opt(v, v, filters.verdict))}</select></label>
        <label class="fl">Family<select class="select" id="ex-family">${opt('', 'Any', filters.family)}${families.map((v) => opt(v, v, filters.family))}</select></label>
        ${hasLabels ? html`
          <label class="fl">Label category<select class="select" id="ex-category">${opt('', 'Any', filters.category)}${cats.map((v) => opt(v, v, filters.category))}</select></label>
          <label class="fl">Outcome<select class="select" id="ex-outcome">${opt('', 'Any', filters.outcome)}${['TP', 'FP', 'FN', 'TN'].map((v) => opt(v, v, filters.outcome))}</select></label>` : ''}
        <label class="fl">Day<select class="select" id="ex-day">${opt('', gday ? 'Top-bar day' : 'All days', filters.day)}${DAYS.map((d) => opt(d.id, d.label, filters.day))}</select></label>
        <label class="fl">File<select class="select" id="ex-file">${opt('', 'Any file', filters.file)}${files.map((v) => opt(v, v, filters.file))}</select></label>
        <label class="fl">Source<select class="select" id="ex-upload">${opt('', 'Snapshot + uploads', filters.upload)}${opt('snapshot', 'Snapshot only', filters.upload)}${opt('upload', 'Uploads only', filters.upload)}</select></label>
        <button class="btn btn-ghost btn-sm" data-action="clear">Clear</button>
      </div>
      ${panel({ title: 'Flows', bodyCls: 'flush', actions: html`<span class="panel-meta" id="ex-count" aria-live="polite"></span>`, body: html`<div id="ex-table"></div>` })}
    `);

    const table = createTable($('#ex-table', root), {
      rows: [], pageSize: store.prefs.pageSize, caption: 'All flows',
      initialSort: { key: 'risk', dir: 'desc' },
      rowAttrs: (f) => ({ 'data-sev': f.severity }),
      onRowClick: (f) => { table.select(f.id); openFlowDrawer(f.id, { onChange: refresh }); },
      columns: [
        { key: 'id', label: 'Flow', className: 'sev-cell', render: (f) => html`<span class="mono">${f.id}</span>` },
        { key: 'day', label: 'Day', render: (f) => dayLabel(f.day) },
        { key: 'port', label: 'Dst port', sort: (f) => f.dst.port ?? -1, render: (f) => html`<span class="mono">${f.dst.port ?? '—'}</span> <span class="muted">${f.service || ''}</span>` },
        { key: 'label', label: 'Label', sort: (f) => f.label || '', render: (f) => html`<span class="${f.label === 'BENIGN' ? 'muted' : ''}">${f.label ?? '—'}</span>` },
        { key: 'verdict', label: 'Verdict', render: (f) => html`${f.verdict}${f.mode ? html` · ${modeTag(f.mode)}` : ''}` },
        { key: 'family', label: 'Family', sort: (f) => f.family || '', render: (f) => f.familyTitle || f.family || html`<span class="muted">—</span>` },
        { key: 'risk', label: 'Risk', sort: (f) => f.risk, render: (f) => riskCell(f.risk) },
        { key: 'severity', label: 'Severity', sort: (f) => SEV_RANK[f.severity] * 1000 + f.risk, render: (f) => sevBadge(f.severity) },
        { key: 'agree', label: 'Detectors', sort: (f) => f.votes, render: (f) => modelStrip(f.flags) },
        ...(hasLabels ? [{ key: 'outcome', label: 'Outcome', render: (f) => outcomeTag(f.outcome) }] : []),
        { key: 'status', label: 'Status', render: (f) => statusBadge(f.status) },
      ],
      card: (f) => html`<span class="event-card-row">${sevBadge(f.severity)}<span class="mono muted" style="font-size:12px">${f.id}</span></span>
        <span class="event-card-row">${f.familyTitle || f.family || f.verdict}${riskCell(f.risk)}</span>
        <span class="event-card-row"><span class="mono muted">port ${f.dst.port ?? '—'} ${f.service || ''}</span>${outcomeTag(f.outcome)}</span>`,
      emptyTitle: 'No flows match', emptyText: 'Clear a filter or widen the search.',
    });

    const match = (f) => {
      const q = filters.q.trim().toLowerCase();
      return (!filters.verdict || f.verdict === filters.verdict) && (!filters.family || f.family === filters.family)
        && (!filters.category || f.category === filters.category) && (!filters.outcome || f.outcome === filters.outcome)
        && (!q || f.id.toLowerCase().includes(q) || String(f.dst.port) === q || (f.service || '').toLowerCase().includes(q)
          || (f.label || '').toLowerCase().includes(q) || (f.family || '').toLowerCase().includes(q) || (f.familyTitle || '').toLowerCase().includes(q) || f.verdict === q);
    };
    function refresh() {
      const day = filters.day || gday || undefined;
      const up = filters.upload === 'upload' ? true : filters.upload === 'snapshot' ? false : undefined;
      current = flows({ day, file: filters.file || undefined, upload: up }).filter(match);
      $('#ex-count', root).textContent = `${fmtInt(current.length)} flows`;
      table.setRows(current, { resetPage: false });
      store.session.explorerFilters = filters;
    }

    const bind = (sel, key) => on(root, 'change', sel, (_e, s) => { filters[key] = s.value; table.setRows(table.rows, { resetPage: true }); refresh(); });
    [['#ex-verdict', 'verdict'], ['#ex-family', 'family'], ['#ex-category', 'category'], ['#ex-outcome', 'outcome'], ['#ex-day', 'day'], ['#ex-file', 'file'], ['#ex-upload', 'upload']].forEach(([s, k]) => bind(s, k));
    let t;
    on(root, 'input', '#ex-q', (_e, i) => { clearTimeout(t); t = setTimeout(() => { filters.q = i.value; table.setRows(table.rows, { resetPage: true }); refresh(); }, 160); });
    on(root, 'click', '[data-action="clear"]', () => {
      Object.assign(filters, fresh());
      root.querySelectorAll('select').forEach((s) => { s.value = ''; });
      $('#ex-q', root).value = '';
      refresh();
    });
    on(root, 'click', '[data-action="export"]', () => {
      if (!current.length) { toast('Nothing to export for this filter', { tone: 'warn' }); return; }
      downloadCsv(current);
      toast(`Exported ${fmtInt(current.length)} flows`);
    });

    // A new query from the top-bar search while this view is already open.
    const unsub = store.subscribe((ev) => {
      if (ev.type === 'session' && ev.key === 'query' && store.session.query) {
        filters.q = store.session.query; store.session.query = '';
        $('#ex-q', root).value = filters.q;
        table.setRows(table.rows, { resetPage: true }); refresh();
      }
    });

    refresh();
    if (param) {
      if (flowById(param)) openFlowDrawer(param, { onChange: refresh });
      else toast(`No flow called ${param} in this snapshot`, { tone: 'warn' });
    }
    return () => { clearTimeout(t); unsub(); };
  },
};
