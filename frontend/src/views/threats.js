// Threat Detection: the triage queue. Flagged flows, sortable and filterable, opening into a drawer.
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { fmtInt, fmtTime } from '../core/format.js';
import { icon, sevGlyph } from '../components/icons.js';
import { sevBadge, statusBadge, modelStrip, ipText, scoreBar, tagSample, sampleCallout, SEV_LABEL } from '../components/security.js';
import { createTable } from '../components/table.js';
import { openFlowDrawer } from '../components/flow-detail.js';
import { flagged } from '../data/index.js';
import { MODELS } from '../data/model-registry.js';
import { STATUS_OPTIONS } from '../data/sample/events.js';
import { pageHead, panel, severityCounts } from './common.js';

const SEVS = ['critical', 'high', 'medium', 'low'];
const SEV_RANK = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

export default {
  title: 'Threat Detection',
  render(root) {
    const saved = store.session.threatFilters;
    const filters = saved ? { ...saved, sevs: [...saved.sevs], models: [...saved.models] } : { sevs: [...SEVS], models: [], status: 'open', q: '' };
    let selected = null;

    mount(root, html`
      ${pageHead({
        title: 'Threat Detection',
        sub: 'Flows that at least one detector scored above its cut-off, ranked for investigation.',
      })}
      ${sampleCallout(html`<b>Sample queue.</b> These flows and scores are generated for design. Scores are shown in each detector’s own units with its cut-off marked; the autoencoder cut-off is a sample value because the code does not define one.`)}

      <div class="sev-filter" role="group" aria-label="Filter by severity" id="sev-filter"></div>

      <div class="filters">
        <div class="search" style="flex:1 1 240px;max-width:340px">${icon('search')}
          <input class="input" id="th-q" type="search" placeholder="Search ID, IP, label" aria-label="Search flagged flows by ID, IP address or label" value="${filters.q}">
        </div>
        <div class="toolbar" role="group" aria-label="Flagged by detector">
          <span class="panel-meta">Flagged by</span>
          ${MODELS.map((m) => html`<button class="chip" data-model="${m.id}" aria-pressed="${filters.models.includes(m.id)}"><span class="mdot" data-m="${m.id}"></span>${m.short}</button>`)}
        </div>
        <label class="visually-hidden" for="th-status">Investigation status</label>
        <select class="select" id="th-status" style="width:auto">
          <option value="open" ${filters.status === 'open' ? html`selected` : ''}>Open (new, triaging, escalated)</option>
          <option value="all" ${filters.status === 'all' ? html`selected` : ''}>All statuses</option>
          ${STATUS_OPTIONS.map((s) => html`<option value="${s}" ${filters.status === s ? html`selected` : ''}>${s}</option>`)}
        </select>
        <button class="btn btn-ghost btn-sm" data-action="clear">Clear filters</button>
      </div>

      ${panel({ title: 'Flagged flows', tag: tagSample(), meta: '', bodyCls: 'flush', id: 'p-queue', actions: html`<span class="panel-meta" id="th-count" aria-live="polite"></span>`, body: html`<div id="th-table"></div>` })}
    `);

    const match = (f) =>
      filters.sevs.includes(f.severity) &&
      filters.models.every((m) => f.flags[m]) &&
      (filters.status === 'all' || (filters.status === 'open' ? ['New', 'Triaging', 'Escalated'].includes(f.status) : f.status === filters.status)) &&
      (!filters.q || [f.id, f.src.ip, f.dst.ip, f.label].some((v) => v.toLowerCase().includes(filters.q.trim().toLowerCase())));

    const table = createTable($('#th-table', root), {
      rows: [], pageSize: store.prefs.pageSize, caption: 'Flagged flows (sample)',
      initialSort: { key: 'severity', dir: 'desc' },
      rowAttrs: (f) => ({ 'data-sev': f.severity }),
      onRowClick: (f) => { selected = f.id; table.select(f.id); openFlowDrawer(f.id, { onChange: refresh }); },
      columns: [
        { key: 'severity', label: 'Severity', className: 'sev-cell', sort: (f) => SEV_RANK[f.severity] * 10 + f.agree, render: (f) => sevBadge(f.severity, { pulse: f.status === 'New' }) },
        { key: 'id', label: 'Flow', render: (f) => html`<span class="mono">${f.id}</span>` },
        { key: 'ts', label: 'Time (UTC)', render: (f) => html`<span class="mono muted">${fmtTime(f.ts)}</span>` },
        { key: 'route', label: 'Source → destination', sort: (f) => f.src.ip, render: (f) => html`${ipText(f.src.ip)} <span class="muted">→</span> ${ipText(f.dst.ip, f.dst.port)}` },
        { key: 'agree', label: 'Detectors', render: (f) => modelStrip(f.flags) },
        ...MODELS.map((m) => ({ key: `s_${m.id}`, label: `${m.short} score`, sort: (f) => f.scores[m.id], render: (f) => scoreBar(m.id, f.scores[m.id]) })),
        { key: 'label', label: 'Dataset label', render: (f) => html`<span class="${f.label === 'BENIGN' ? 'muted' : ''}">${f.label === 'BENIGN' ? 'Benign' : f.label}</span>` },
        { key: 'status', label: 'Status', render: (f) => statusBadge(f.status) },
      ],
      card: (f) => html`<span class="event-card-row">${sevBadge(f.severity)}<span class="mono muted" style="font-size:12px">${f.id} · ${fmtTime(f.ts, { seconds: false })}</span></span>
        <span class="event-card-row route">${ipText(f.src.ip)}<span class="muted">→</span>${ipText(f.dst.ip, f.dst.port)}</span>
        <span class="event-card-row">${modelStrip(f.flags)}${statusBadge(f.status)}</span>`,
      emptyTitle: 'No flagged flows match', emptyText: 'Clear the search or include more severities and statuses.',
    });

    function paintSevFilter() {
      const all = flagged();
      const c = severityCounts(all.filter((f) => filters.status === 'all' || (filters.status === 'open' ? ['New', 'Triaging', 'Escalated'].includes(f.status) : f.status === filters.status)));
      mount($('#sev-filter', root), SEVS.map((s) => html`
        <button class="sev-tile" data-sev-toggle="${s}" data-sev="${s}" aria-pressed="${filters.sevs.includes(s)}">
          <span class="sev-tile-top"><span class="sev" data-sev="${s}">${sevGlyph(s)}${SEV_LABEL[s]}</span></span>
          <span class="sev-tile-num num">${fmtInt(c[s])}</span>
        </button>`));
    }

    function refresh() {
      const list = flagged().filter(match);
      $('#th-count', root).textContent = `${fmtInt(list.length)} shown`;
      table.setRows(list, { resetPage: false });
      if (selected) table.select(selected);
      paintSevFilter();
      store.session.threatFilters = filters;
    }

    on(root, 'click', '[data-sev-toggle]', (_e, b) => {
      const s = b.dataset.sevToggle;
      filters.sevs = filters.sevs.includes(s) ? filters.sevs.filter((x) => x !== s) : [...filters.sevs, s];
      refresh();
    });
    on(root, 'click', '[data-model]', (_e, b) => {
      const m = b.dataset.model;
      filters.models = filters.models.includes(m) ? filters.models.filter((x) => x !== m) : [...filters.models, m];
      b.setAttribute('aria-pressed', String(filters.models.includes(m)));
      refresh();
    });
    on(root, 'change', '#th-status', (_e, s) => { filters.status = s.value; refresh(); });
    let t;
    on(root, 'input', '#th-q', (_e, i) => { clearTimeout(t); t = setTimeout(() => { filters.q = i.value; refresh(); }, 140); });
    on(root, 'click', '[data-action="clear"]', () => {
      Object.assign(filters, { sevs: [...SEVS], models: [], status: 'all', q: '' });
      $('#th-q', root).value = ''; $('#th-status', root).value = 'all';
      root.querySelectorAll('[data-model]').forEach((b) => b.setAttribute('aria-pressed', 'false'));
      refresh();
    });

    refresh();
  },
};
