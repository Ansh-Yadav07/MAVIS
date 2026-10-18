import { render as rerender } from '../core/router.js';
// Threat Detection: the alert queue. Flows the engine alerted on at the current alert budget,
// ranked by risk, filterable, opening into the flow drawer.
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { fmtInt, fmtPct } from '../core/format.js';
import { icon, sevGlyph } from '../components/icons.js';
import { sevBadge, statusBadge, modelStrip, riskCell, modeTag, dayLabel, tagEngine, infoCallout, SEV_LABEL } from '../components/security.js';
import { createTable } from '../components/table.js';
import { openFlowDrawer } from '../components/flow-detail.js';
import { flagged, currentBudget, STATUS_OPTIONS } from '../data/index.js';
import { pageHead, panel, severityCounts } from './common.js';

const SEVS = ['critical', 'high', 'medium', 'low'];
const SEV_RANK = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
const CONF_RANK = { low: 1, medium: 2, high: 3 };
const OPEN = ['New', 'Triaging', 'Escalated'];
const fresh = () => ({ sevs: [...SEVS], family: '', mode: '', confidence: '', status: 'open', q: '' });

export default {
  title: 'Threat Detection',
  render(root) {
    const filters = { ...fresh(), ...(store.session.threatFilters || {}) };
    filters.sevs = [...(filters.sevs || SEVS)];
    const day = store.session.day || undefined;
    // "Open alert queue" on the Analyze page narrows the queue to uploaded captures.
    const uploadOnly = !!store.session.uploadOnly;
    const scope = uploadOnly ? { upload: true } : { day };
    const base = flagged(scope);
    const families = [...new Set(base.map((f) => f.family))].sort();
    let selected = null;

    mount(root, html`
      ${pageHead({
        title: 'Threat Detection',
        sub: html`Alert queue: flows the engine flagged at the <b>${fmtPct(currentBudget(), 1)}</b> alert budget, highest risk first. ${day ? '' : 'All capture days.'}`,
        actions: tagEngine(),
      })}
      ${uploadOnly ? html`<div class="callout" role="note">${icon('info')}<div>Showing alerts from your uploaded captures only. <button class="btn btn-ghost btn-sm" data-action="all-captures">Show all captures</button></div></div>` : ''}
      ${base.length ? '' : infoCallout('No alerts for this selection. Try another capture day or a looser alert budget in the top bar.')}
      <div class="sev-filter" role="group" aria-label="Filter by severity" id="sev-filter"></div>

      <div class="filter-bar" style="margin-top:var(--s-3)">
        <div class="search">${icon('search')}
          <input class="input" id="th-q" type="search" placeholder="Search id, family, port, service" aria-label="Search alerts" value="${filters.q}">
        </div>
        <label class="fl">Family<select class="select" id="th-family"><option value="">All families</option>${families.map((x) => html`<option value="${x}" ${filters.family === x ? html`selected` : ''}>${x}</option>`)}</select></label>
        <label class="fl">Mode<select class="select" id="th-mode"><option value="">Any mode</option>${['known', 'novel', 'known+novel'].map((x) => html`<option value="${x}" ${filters.mode === x ? html`selected` : ''}>${x}</option>`)}</select></label>
        <label class="fl">Confidence<select class="select" id="th-conf"><option value="">Any confidence</option>${['high', 'medium', 'low'].map((x) => html`<option value="${x}" ${filters.confidence === x ? html`selected` : ''}>${x}</option>`)}</select></label>
        <label class="fl">Status<select class="select" id="th-status">
          <option value="open" ${filters.status === 'open' ? html`selected` : ''}>Open (new, triaging, escalated)</option>
          <option value="all" ${filters.status === 'all' ? html`selected` : ''}>All statuses</option>
          ${STATUS_OPTIONS.map((s) => html`<option value="${s}" ${filters.status === s ? html`selected` : ''}>${s}</option>`)}</select></label>
        <button class="btn btn-ghost btn-sm" data-action="clear">Clear filters</button>
      </div>

      ${panel({ title: 'Alerts', meta: 'Engine output', bodyCls: 'flush', id: 'p-queue', actions: html`<span class="panel-meta" id="th-count" aria-live="polite"></span>`, body: html`<div id="th-table"></div>` })}
    `);

    const statusOk = (f) => filters.status === 'all' || (filters.status === 'open' ? OPEN.includes(f.status) : f.status === filters.status);
    const match = (f) =>
      filters.sevs.includes(f.severity) && statusOk(f) &&
      (!filters.family || f.family === filters.family) &&
      (!filters.mode || f.mode === filters.mode) &&
      (!filters.confidence || f.confidence === filters.confidence) &&
      (!filters.q || [f.id, f.family, f.familyTitle, f.service, String(f.dst.port)].some((v) => String(v ?? '').toLowerCase().includes(filters.q.trim().toLowerCase())));

    const table = createTable($('#th-table', root), {
      rows: [], pageSize: store.prefs.pageSize, caption: 'Alert queue',
      initialSort: { key: 'risk', dir: 'desc' },
      rowAttrs: (f) => ({ 'data-sev': f.severity }),
      onRowClick: (f) => { selected = f.id; table.select(f.id); openFlowDrawer(f.id, { onChange: refresh }); },
      columns: [
        { key: 'risk', label: 'Risk', className: 'sev-cell', sort: (f) => f.risk, render: (f) => riskCell(f.risk) },
        { key: 'severity', label: 'Severity', sort: (f) => SEV_RANK[f.severity] * 1000 + f.risk, render: (f) => sevBadge(f.severity, { pulse: f.status === 'New' }) },
        { key: 'family', label: 'Family', sort: (f) => f.family || '', render: (f) => html`<span title="${f.id}">${f.familyTitle || f.family}</span>` },
        { key: 'mode', label: 'Verdict / mode', sort: (f) => f.mode || '', render: (f) => html`<span class="muted">${f.verdict}</span> · ${modeTag(f.mode)}` },
        { key: 'conf', label: 'Confidence', sort: (f) => CONF_RANK[f.confidence] || 0, render: (f) => f.confidence },
        { key: 'agree', label: 'Detectors', sort: (f) => f.votes, render: (f) => html`${modelStrip(f.flags)} <span class="mono muted" title="Attack classifier P(known)">C ${Math.round(f.pKnown * 100)}%</span>` },
        { key: 'port', label: 'Dst port', sort: (f) => f.dst.port ?? -1, render: (f) => html`<span class="mono">${f.dst.port ?? '—'}</span> <span class="muted">${f.service || ''}</span>` },
        { key: 'day', label: 'Day', render: (f) => dayLabel(f.day) },
        { key: 'status', label: 'Status', render: (f) => statusBadge(f.status) },
      ],
      card: (f) => html`<span class="event-card-row">${sevBadge(f.severity)}${riskCell(f.risk)}<span class="mono muted" style="font-size:12px">${dayLabel(f.day)}</span></span>
        <span class="event-card-row">${f.familyTitle || f.family}${modeTag(f.mode)}</span>
        <span class="event-card-row">${modelStrip(f.flags)}<span class="mono muted">port ${f.dst.port ?? '—'}</span>${statusBadge(f.status)}</span>`,
      emptyTitle: 'No alerts match', emptyText: 'Clear a filter, include more severities, or pick All statuses.',
    });

    function paintSevFilter() {
      const c = severityCounts(base.filter(statusOk));
      mount($('#sev-filter', root), SEVS.map((s) => html`
        <button class="sev-tile" data-sev-toggle="${s}" data-sev="${s}" aria-pressed="${filters.sevs.includes(s)}">
          <span class="sev-tile-top"><span class="sev" data-sev="${s}">${sevGlyph(s)}${SEV_LABEL[s]}</span></span>
          <span class="sev-tile-num num">${fmtInt(c[s])}</span>
        </button>`));
    }

    function refresh() {
      const list = flagged(scope).filter(match);
      $('#th-count', root).textContent = `${fmtInt(list.length)} of ${fmtInt(base.length)} shown`;
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
    [['#th-family', 'family'], ['#th-mode', 'mode'], ['#th-conf', 'confidence'], ['#th-status', 'status']]
      .forEach(([sel, key]) => on(root, 'change', sel, (_e, s) => { filters[key] = s.value; refresh(); }));
    let t;
    on(root, 'input', '#th-q', (_e, i) => { clearTimeout(t); t = setTimeout(() => { filters.q = i.value; refresh(); }, 140); });
    on(root, 'click', '[data-action="all-captures"]', () => { store.session.uploadOnly = false; rerender(); });
    on(root, 'click', '[data-action="clear"]', () => {
      Object.assign(filters, fresh(), { status: 'all' });
      $('#th-q', root).value = '';
      ['#th-family', '#th-mode', '#th-conf'].forEach((s) => { $(s, root).value = ''; });
      $('#th-status', root).value = 'all';
      refresh();
    });

    refresh();
    return () => clearTimeout(t);
  },
};
