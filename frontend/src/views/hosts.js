// Hosts: every host seen by the sensor or simulator, with services, role, risk and Block/Unblock.
import { html, mount, on } from '../core/dom.js';
import { fmtInt } from '../core/format.js';
import { toast } from '../components/overlays.js';
import { toggleBlock } from '../components/block.js';
import { SEV_COLOR } from '../components/security.js';
import { subscribeLive, blockedSet, isProtected, approveBlock, rejectBlock } from '../data/index.js';
import { pageHead, panel, regions } from './common.js';

const riskColor = (r) => (r >= 85 ? SEV_COLOR.critical : r >= 70 ? SEV_COLOR.high : 'inherit');

export default {
  title: 'Hosts',
  render(root) {
    mount(root, html`
      ${pageHead({ title: 'Hosts', sub: 'Highest risk first. Blocking follows the response backend (dry-run by default).' })}
      <div id="ho-pending"></div>
      <div class="al-filters"><input class="input" id="ho-q" type="search" placeholder="Filter by address, role or service" aria-label="Filter hosts" autocomplete="off"></div>
      <section class="panel" aria-label="Hosts"><div class="panel-body flush" id="ho-body"></div></section>`);
    const region = regions(root);
    let q = '', latest = null;
    const paint = () => {
      const s = latest;
      if (!s) return;
      const blocked = blockedSet(s);
      region('ho-pending', JSON.stringify(s.pending), () => s.pending.length ? panel({ title: 'Block approvals', meta: 'awaiting an analyst', bodyCls: 'flush', body: s.pending.map((b) => html`<div class="pend-row" data-attention>
        <div class="grow"><b class="mono">${b.ip}</b> <span class="panel-meta">${b.reason}</span></div>
        <button class="btn btn-sm btn-primary" data-approve="${b.ip}">Approve</button><button class="btn btn-sm" data-reject="${b.ip}">Reject</button></div>`) }) : '');
      const needle = q.trim().toLowerCase();
      const hosts = [...s.hosts].filter((h) => !needle || `${h.ip} ${h.role || ''} ${Object.keys(h.services || {}).join(' ')}`.toLowerCase().includes(needle))
        .sort((a, b) => (b.maxRisk - a.maxRisk) || (b.flows - a.flows)).slice(0, 300);
      region('ho-body', JSON.stringify([hosts, [...blocked], needle]), () => hosts.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>Host</th><th>Scope</th><th>Role</th><th>Services</th><th class="r">Flows</th><th class="r">Alerts</th><th class="r">Risk</th><th>State</th><th></th></tr></thead><tbody>
        ${hosts.map((h) => { const bl = blocked.has(h.ip); return html`<tr>
          <td class="mono">${h.ip}</td><td class="muted">${isProtected(h.ip) ? 'protected' : 'external'}</td><td class="muted">${h.role || 'none'}</td>
          <td><span class="lv-svc">${Object.entries(h.services || {}).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => html`<span class="tag-plain" title="${v} flows">${k}</span>`)}</span></td>
          <td class="r mono">${fmtInt(h.flows)}</td><td class="r mono">${fmtInt(h.alerts)}</td>
          <td class="r mono" style="color:${riskColor(h.maxRisk)}">${Math.round(h.maxRisk || 0)}</td>
          <td>${bl ? html`<span class="tag-plain blocked-tag">blocked</span>` : ''}</td>
          <td class="r"><button class="btn btn-sm ${bl ? '' : 'btn-danger'}" data-toggle="${h.ip}" data-blocked="${bl}">${bl ? 'Unblock' : 'Block'}</button></td></tr>`; })}
        </tbody></table></div>` : html`<p class="panel-body panel-meta">${s.hosts.length ? 'No hosts match.' : 'No hosts seen yet.'}</p>`);
    };
    const act = async (fn, ok) => { try { await fn(); toast(ok); } catch (e) { toast(e.message, { tone: 'error' }); } };
    on(root, 'click', '[data-toggle]', (_e, b) => toggleBlock(b.dataset.toggle, b.dataset.blocked === 'true', 'Blocked from the hosts table'));
    on(root, 'click', '[data-approve]', (_e, b) => act(() => approveBlock(b.dataset.approve), 'Block approved'));
    on(root, 'click', '[data-reject]', (_e, b) => act(() => rejectBlock(b.dataset.reject), 'Block rejected'));
    on(root, 'input', '#ho-q', (_e, i) => { q = i.value; paint(); });
    return subscribeLive((s) => { if (!root.isConnected) return; latest = s; paint(); });
  },
};
