// Alerts: the live queue (flow alerts plus insider alerts) with filters. Click a row to open it.
import { html, mount, on, $ } from '../core/dom.js';
import { fmtTime } from '../core/format.js';
import { openFlowDrawer } from '../components/flow-detail.js';
import { openDialog } from '../components/overlays.js';
import { sevBadge, riskCell, SEV_ORDER, SEV_LABEL } from '../components/security.js';
import { subscribeLive, liveFlows, flowById } from '../data/index.js';
import { pageHead, regions, insiderItem } from './common.js';

const LIMIT = 200;

function rows(s) {
  const flow = liveFlows().filter((f) => f.verdict !== 'normal').map((f) => ({
    key: f.id, type: 'flow', ts: f.ts, t: Date.parse(f.ts) || f._rx, sev: f.severity, title: f.familyTitle || f.family || 'Alert',
    src: f.src?.ip, dst: f.dst?.ip, port: f.dst?.port, risk: f.risk, extra: f.response?.action || '',
  }));
  const ins = (s.insider || []).map((a) => ({
    key: a.id, type: 'insider', ts: a.ts, t: Date.parse(a.ts) || 0, sev: a.severity, title: a.title, src: a.src, dst: a.dst, port: a.dstPort, risk: a.risk, extra: a.kind, raw: a,
  }));
  return [...flow, ...ins].sort((a, b) => b.t - a.t);
}

export default {
  title: 'Alerts',
  render(root) {
    const filt = { sev: new Set(['critical', 'high', 'medium', 'low']), type: 'all', q: '' };
    mount(root, html`
      ${pageHead({ title: 'Alerts', sub: 'Newest first. Flow alerts come from the engine; insider alerts come from host profiles.' })}
      <div class="al-filters">
        <div class="chips-inline" role="group" aria-label="Severity filter">${SEV_ORDER.filter((x) => x !== 'none').map((x) => html`<button class="chip" data-sev-chip="${x}" aria-pressed="true">${SEV_LABEL[x]}</button>`)}</div>
        <select class="select" id="al-type" aria-label="Alert type"><option value="all">All types</option><option value="flow">Flow alerts</option><option value="insider">Insider alerts</option></select>
        <input class="input" id="al-q" type="search" placeholder="Filter by address, port or family" aria-label="Filter alerts" autocomplete="off">
      </div>
      <section class="panel" aria-label="Alert queue"><div class="panel-body flush" id="al-body"></div></section>`);
    const region = regions(root);
    let latest = null;
    const paint = () => {
      if (!latest) return;
      const all = rows(latest);
      const q = filt.q.trim().toLowerCase();
      const list = all.filter((r) => filt.sev.has(r.sev) && (filt.type === 'all' || r.type === filt.type)
        && (!q || `${r.src} ${r.dst} ${r.port} ${r.title} ${r.extra}`.toLowerCase().includes(q)));
      region('al-body', JSON.stringify([[...filt.sev], filt.type, q, all.length, all[0]?.key, latest.seq]), () => list.length ? html`
        <div class="table-wrap"><table class="table"><thead><tr><th>Time</th><th>Severity</th><th>Alert</th><th>Source</th><th>Destination</th><th>Risk</th><th>Response</th></tr></thead><tbody>
          ${list.slice(0, LIMIT).map((r) => html`<tr class="is-clickable" data-row="${r.key}" data-type="${r.type}" tabindex="0">
            <td class="mono">${r.ts ? fmtTime(r.ts, { date: false }) : ''}</td><td>${sevBadge(r.sev)}</td>
            <td>${r.title}${r.type === 'insider' ? html` <span class="tag-plain">insider</span>` : ''}</td>
            <td class="mono">${r.src ?? ''}</td><td class="mono">${r.dst ?? ''}${r.port != null ? `:${r.port}` : ''}</td>
            <td>${riskCell(r.risk)}</td><td class="muted">${r.extra}</td></tr>`)}
        </tbody></table></div>${list.length > LIMIT ? html`<p class="panel-body panel-meta">Showing the newest ${LIMIT} of ${list.length}.</p>` : ''}`
        : html`<p class="panel-body panel-meta">${all.length ? 'No alerts match these filters.' : 'No alerts yet. Normal traffic is not listed.'}</p>`);
    };
    const open = (tr) => {
      if (tr.dataset.type === 'flow') { openFlowDrawer(tr.dataset.row); return; }
      const a = (latest.insider || []).find((x) => x.id === tr.dataset.row);
      if (!a) return;
      if (a.flowId && flowById(a.flowId)) { openFlowDrawer(a.flowId); return; }
      openDialog(() => html`<div class="dialog-head"><h2 class="panel-title" style="font-size:var(--fs-lg)">Insider alert</h2></div>
        <div class="dialog-body"><ul class="ins-list">${insiderItem(a)}</ul></div><div class="dialog-foot"><button class="btn btn-primary" data-close data-autofocus>Close</button></div>`, { label: 'Insider alert' });
    };
    on(root, 'click', '[data-row]', (_e, tr) => open(tr));
    on(root, 'keydown', '[data-row]', (ev, tr) => { if (ev.key === 'Enter') open(tr); });
    on(root, 'click', '[data-sev-chip]', (_e, b) => {
      const k = b.dataset.sevChip;
      if (filt.sev.has(k)) filt.sev.delete(k); else filt.sev.add(k);
      b.setAttribute('aria-pressed', String(filt.sev.has(k)));
      paint();
    });
    on(root, 'change', '#al-type', (_e, sel) => { filt.type = sel.value; paint(); });
    on(root, 'input', '#al-q', (_e, i) => { filt.q = i.value; paint(); });
    return subscribeLive((s) => { if (!root.isConnected) return; latest = s; paint(); });
  },
};
