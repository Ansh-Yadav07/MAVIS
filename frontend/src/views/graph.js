// Attack Graph: the full live graph with a side panel for the selected host.
import { html, mount, on, $ } from '../core/dom.js';
import { fmtInt, fmtTime } from '../core/format.js';
import { createGraph } from '../components/attackgraph.js';
import { toggleBlock } from '../components/block.js';
import { openFlowDrawer } from '../components/flow-detail.js';
import { sevBadge } from '../components/security.js';
import { subscribeLive, liveFlows, blockedSet, isProtected } from '../data/index.js';
import { pageHead, panel, regions } from './common.js';

function sidePanel(s, ip) {
  if (!ip) return html`<p class="panel-meta">Select a host in the graph to see what it did and to block or unblock it.</p>`;
  const h = (s.hosts || []).find((x) => x.ip === ip);
  const blocked = blockedSet(s).has(ip);
  const alerts = liveFlows().filter((f) => f.verdict !== 'normal' && (f.src?.ip === ip || f.dst?.ip === ip)).slice(-6).reverse();
  const ep = (s.episodes || []).filter((e) => e.target === ip || (e.topSources || []).includes(ip)).slice(0, 3);
  return html`
    <div class="side-head"><b class="mono">${ip}</b><span class="tag-plain">${isProtected(ip) ? 'protected' : 'external'}</span>${blocked ? html`<span class="tag-plain blocked-tag">blocked</span>` : ''}</div>
    <dl class="kv">
      <dt>Role</dt><dd>${h?.role || 'none'}</dd>
      <dt>Flows</dt><dd class="mono">${fmtInt(h?.flows || 0)}</dd>
      <dt>Alerts</dt><dd class="mono">${fmtInt(h?.alerts || 0)}</dd>
      <dt>Max risk</dt><dd class="mono">${Math.round(h?.maxRisk || 0)}</dd>
      <dt>Peers</dt><dd class="mono">${fmtInt(h?.peers || 0)}</dd>
      <dt>Services</dt><dd><span class="lv-svc">${Object.entries(h?.services || {}).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, v]) => html`<span class="tag-plain" title="${v} flows">${k}</span>`)}</span></dd>
      <dt>Last seen</dt><dd class="mono">${h?.lastSeen ? fmtTime(h.lastSeen, { date: false }) : 'n/a'}</dd>
    </dl>
    ${ep.length ? html`<h3 class="section-title">Incidents</h3><ul class="prose" style="margin:0;padding-left:18px">${ep.map((e) => html`<li>${e.title} <span class="panel-meta">${e.state}</span></li>`)}</ul>` : ''}
    ${alerts.length ? html`<h3 class="section-title">Recent alerts</h3><ul class="lv-feed-list">${alerts.map((f) => html`<li><button class="lv-feed-row" data-open="${f.id}"><span>${sevBadge(f.severity)} <b>${f.familyTitle || f.family}</b></span><span class="when">${f.ts ? fmtTime(f.ts, { date: false }) : ''}</span><span class="route">${f.src?.ip} → ${f.dst?.ip}:${f.dst?.port}</span></button></li>`)}</ul>` : ''}
    <div><button class="btn ${blocked ? '' : 'btn-danger'}" data-toggle-block="${ip}" data-blocked="${blocked}">${blocked ? 'Unblock host' : 'Block host'}</button></div>`;
}

export default {
  title: 'Attack Graph',
  render(root) {
    mount(root, html`
      ${pageHead({ title: 'Attack Graph', sub: 'Hosts and the traffic between them over the last 30 seconds. An attack converges on its target.' })}
      <div class="ag-layout">
        ${panel({ title: 'Live graph', meta: 'protected hosts in the centre, external hosts on the ring', cls: 'ag-main', body: html`<div class="ag-host" id="ag-host"></div>
          <div class="legend-row">
            <span class="legend-item"><i class="swatch" style="background:var(--accent)"></i>Protected host</span>
            <span class="legend-item"><i class="swatch" style="background:var(--sev-critical)"></i>Critical</span>
            <span class="legend-item"><i class="swatch" style="background:var(--sev-high)"></i>High</span>
            <span class="legend-item"><i class="swatch" style="background:var(--sev-medium)"></i>Medium</span>
            <span class="legend-item"><i class="swatch" style="background:var(--surface-3);border:1px solid var(--ink-3)"></i>Normal or blocked (crossed)</span>
            <span class="legend-item">Line width: flows in the last 30 s</span></div>` })}
        ${panel({ title: 'Host', cls: 'ag-side', body: html`<div class="side-body" id="ag-side"></div>` })}
      </div>`);
    const region = regions(root);
    let selected = null, latest = null;
    const graph = createGraph($('#ag-host', root), { onSelect: (ip) => { selected = ip; graph.select(ip); side(); } });
    const side = () => { if (latest) region('ag-side', JSON.stringify([selected, latest.hosts.find((h) => h.ip === selected), [...blockedSet(latest)].includes(selected), latest.seq]), () => sidePanel(latest, selected)); };
    on(root, 'click', '[data-open]', (_e, b) => openFlowDrawer(b.dataset.open));
    on(root, 'click', '[data-toggle-block]', async (_e, b) => { await toggleBlock(b.dataset.toggleBlock, b.dataset.blocked === 'true', 'Blocked from the attack graph'); });
    const stop = subscribeLive((s) => { if (!root.isConnected) return; latest = s; graph.update(s); side(); });
    return () => { stop(); graph.destroy(); };
  },
};
