// Investigations: incidents (alerts grouped per threat family) on a status board.
// Status and notes are analyst edits stored in this browser (store.setEdit on incident.id).
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { go } from '../core/router.js';
import { fmtInt, fmtPct } from '../core/format.js';
import { icon } from '../components/icons.js';
import { sevBadge, tagEngine, riskCell, dayLabel, infoCallout } from '../components/security.js';
import { openDrawer, toast } from '../components/overlays.js';
import { incidents, currentBudget, STATUS_OPTIONS } from '../data/index.js';
import { pageHead } from './common.js';

const ports = (inc) => Object.entries(inc.top_dst_ports || {});

const mitreText = (m) => (typeof m === 'string' ? m : `${m.tactic} / ${m.technique}`);

function card(inc) {
  const p = ports(inc).slice(0, 3);
  return html`<button class="inc-card" data-inc="${inc.id}" data-sev="${inc.severity}">
    <span class="inc-title">${inc.title || inc.threat_family}</span>
    <span class="inc-meta">${sevBadge(inc.severity)}<span class="tag-plain">${inc.threat_family}</span><span class="mono">${dayLabel(inc.day)}</span></span>
    <span class="inc-meta"><span><b class="mono">${fmtInt(inc.flows)}</b> flows</span><span>risk max ${riskCell(inc.max_risk)}</span><span class="mono">mean ${inc.mean_risk}</span></span>
    ${inc.distinct_dst_ports != null ? html`<span class="inc-meta"><span><b class="mono">${fmtInt(inc.distinct_dst_ports)}</b> ports</span>${p.length ? html`<span class="mono">${p.map(([k]) => k).join(', ')}</span>` : ''}</span>` : ''}
    ${inc.note ? html`<span class="inc-meta">${icon('note')}<span>${inc.note.length > 70 ? `${inc.note.slice(0, 70)}…` : inc.note}</span></span>` : ''}
  </button>`;
}

function openIncident(id, onChange) {
  const inc = incidents(store.session.day || undefined).find((x) => x.id === id);
  if (!inc) return;
  const { el } = openDrawer(() => html`
    <div class="drawer-head">
      <div style="flex:1;min-width:0" class="flow-head">
        <div class="flow-head-top">${sevBadge(inc.severity)}${tagEngine()}</div>
        <div class="flow-id" style="font-size:var(--fs-lg);font-weight:600">${inc.title || inc.threat_family}</div>
        <div class="flow-sub"><span>${inc.threat_family}</span><span>·</span><span>${dayLabel(inc.day)}</span><span>·</span><span class="mono">${inc.file}</span></div>
      </div>
      <button class="icon-btn" data-close aria-label="Close">${icon('close')}</button>
    </div>
    <div class="drawer-body">
      <section class="dsec"><h3 class="section-title">Scope</h3>
        <dl class="kv">
          <dt>Alerted flows</dt><dd class="mono">${fmtInt(inc.flows)} <span class="panel-meta">in the full capture file</span></dd>
          <dt>Risk</dt><dd>max ${riskCell(inc.max_risk)} · mean <span class="mono">${inc.mean_risk}</span></dd>
          <dt>Confidence</dt><dd>${inc.confidence}</dd>
          <dt>Verdicts</dt><dd class="mono">${Object.entries(inc.verdicts || {}).map(([k, v]) => `${k} ${fmtInt(v)}`).join(' · ') || '—'}</dd>
          ${inc.distinct_dst_ports != null ? html`<dt>Distinct dst ports</dt><dd class="mono">${fmtInt(inc.distinct_dst_ports)}</dd>` : ''}
          ${ports(inc).length ? html`<dt>Top dst ports</dt><dd class="mono">${ports(inc).map(([k, v]) => `${k} (${fmtInt(v)})`).join(', ')}</dd>` : ''}
          <dt>Priority</dt><dd class="mono">${inc.priority}</dd>
        </dl></section>
      <section class="dsec"><h3 class="section-title">MITRE ATT&amp;CK</h3>
        ${inc.mitre?.length ? html`<div class="chips-inline">${inc.mitre.map((m) => html`<span class="tag-plain">${mitreText(m)}</span>`)}</div>` : html`<p class="panel-meta">No mapping.</p>`}</section>
      <section class="dsec"><h3 class="section-title">Recommended actions</h3>
        ${inc.actions?.length ? html`<ol class="prose" style="margin:0;padding-left:18px">${inc.actions.map((a) => html`<li>${a}</li>`)}</ol>` : html`<p class="panel-meta">None.</p>`}</section>
      <section class="dsec"><h3 class="section-title">Investigation</h3>
        <div class="field"><label class="field-label" for="inc-status">Status</label>
          <select class="select" id="inc-status">${STATUS_OPTIONS.map((s) => html`<option ${s === inc.status ? html`selected` : ''}>${s}</option>`)}</select>
          <span class="field-hint">Saved in this browser only.</span></div>
        <div class="field"><label class="field-label" for="inc-note">Note</label>
          <textarea class="textarea" id="inc-note" maxlength="2000" placeholder="Scope, hypothesis, next step">${inc.note}</textarea>
          <div><button class="btn btn-sm" data-save>${icon('note')}Save note</button></div></div>
      </section>
    </div>
    <div class="drawer-foot">
      <button class="btn btn-primary" data-go-alerts>${icon('threat')}Matching alerts</button>
      <button class="btn" data-go-explorer>${icon('explorer')}In Event Explorer</button>
      <button class="btn btn-ghost" data-close>Close</button>
    </div>`, { label: `Incident ${inc.title || inc.threat_family}`, onClose: onChange });
  const close = () => el.querySelector('[data-close]').click();
  on(el, 'change', '#inc-status', (_e, s) => { store.setEdit(inc.id, { status: s.value }); toast(`Incident marked ${s.value.toLowerCase()}`); });
  on(el, 'click', '[data-save]', () => { store.setEdit(inc.id, { note: $('#inc-note', el).value.trim() }); toast('Note saved'); });
  on(el, 'click', '[data-go-alerts]', () => {
    store.session.threatFilters = { sevs: ['critical', 'high', 'medium', 'low'], family: inc.threat_family, mode: '', confidence: '', status: 'all', q: '' };
    close(); go('threats');
  });
  on(el, 'click', '[data-go-explorer]', () => { store.setSession('query', inc.threat_family); close(); go('explorer'); });
}

export default {
  title: 'Investigations',
  render(root) {
    const day = store.session.day || undefined;
    const list = incidents(day);
    const draw = () => {
      const all = incidents(day);
      mount($('#inv-board', root), STATUS_OPTIONS.map((s) => {
        const col = all.filter((i) => i.status === s);
        return html`<section class="board-col" aria-label="${s}">
          <h3><span>${s}</span><span class="mono">${col.length}</span></h3>
          <div class="board-list">${col.length ? col.map(card) : html`<div class="empty-col">None</div>`}</div></section>`;
      }));
    };
    mount(root, html`
      ${pageHead({
        title: 'Investigations',
        sub: html`Incidents group alerts per threat family (the public CSVs carry no source addresses, so there is one incident per family and capture file). Alert budget <b>${fmtPct(currentBudget(), 1)}</b>.`,
        actions: tagEngine(),
      })}
      ${list.length ? '' : infoCallout('No incidents for this selection. Try another capture day or a looser alert budget.')}
      <div class="board" id="inv-board"></div>`);
    draw();
    on(root, 'click', '[data-inc]', (_e, b) => openIncident(b.dataset.inc, draw));
  },
};
