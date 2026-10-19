// Live Monitor: a local sensor streams flows to scripts/serve.py, which scores them with the
// engine; this view polls GET api/live and shows rate, alerts, hosts, insider alerts and blocks.
// Without the local server (static site) it explains how to start live mode instead.
import { html, mount, on, $ } from '../core/dom.js';
import { fmtInt, fmtTime } from '../core/format.js';
import { sevBadge, riskCell } from '../components/security.js';
import { bindChart } from '../components/charts.js';
import { toast, confirmDialog } from '../components/overlays.js';
import { openFlowDrawer } from '../components/flow-detail.js';
import { pageHead, panel, SEV_COLOR } from './common.js';
import { apiAvailable, subscribeLive, liveState, liveFlows, liveLearn, liveReset, blockIp, unblockIp, approveBlock, rejectBlock } from '../data/index.js';

const kpi = (label, value, foot) => html`<div class="kpi"><div class="metric-label">${label}</div><div class="kpi-value num">${value}</div><div class="metric-foot">${foot}</div></div>`;

const howTo = (apiUp) => panel({
  title: 'How to start live monitoring', cls: 'lv-howto-panel',
  body: html`<div class="lv-howto">
    ${apiUp ? '' : html`<p class="panel-meta"><b>No local server found.</b> Live mode needs the local MAVIS server; the static site only shows the CIC-IDS2017 snapshot.</p>`}
    <ol>
      <li>Start the server (binds 127.0.0.1 only):<pre>.venv/bin/python scripts/serve.py</pre></li>
      <li>Start the sensor in another terminal (needs root to read packets). Use <code>en0</code> for your Wi-Fi/Ethernet, or <code>lo0</code> for the localhost demo:<pre>sudo .venv/bin/python scripts/sensor.py --iface en0
sudo .venv/bin/python scripts/sensor.py --iface lo0</pre></li>
      <li>Optionally generate test traffic against localhost:<pre>.venv/bin/python scripts/demo_traffic.py portscan</pre></li>
    </ol>
    <p class="panel-meta">Blocking defaults to dry-run: nothing touches your firewall until you change the backend in Settings.</p>
  </div>`,
});

function rateChart(w, timeline) {
  const h = 200, m = { l: 36, r: 8, t: 8, b: 20 };
  if (!timeline.length) return `<p class="panel-meta" style="padding:24px 0">Waiting for traffic.</p>`;
  // The server only sends seconds that had flows: rebuild a continuous 300 s window ending now,
  // so a single burst (e.g. a replayed capture) still draws as a spike instead of nothing.
  const bySec = new Map(timeline.map((p) => [Math.floor(Date.parse(p.t) / 1000), p]));
  const end = Math.max(Math.floor(Date.now() / 1000), ...bySec.keys());
  const pts = Array.from({ length: 300 }, (_, i) => {
    const s = end - 299 + i, p = bySec.get(s);
    return { t: new Date(s * 1000).toISOString(), flows: p?.flows || 0, alerts: p?.alerts || 0 };
  });
  const max = Math.max(1, ...pts.map((p) => p.flows));
  const x = (i) => m.l + (i / (pts.length - 1)) * (w - m.l - m.r);
  const y = (v) => m.t + (1 - v / max) * (h - m.t - m.b);
  const line = (key) => pts.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join('');
  const area = `${line('flows')}L${x(pts.length - 1).toFixed(1)},${y(0)}L${x(0).toFixed(1)},${y(0)}Z`;
  const grid = [0, 0.5, 1].map((k) => `<line class="grid" x1="${m.l}" x2="${w - m.r}" y1="${y(max * k)}" y2="${y(max * k)}"/><text class="tick" x="${m.l - 6}" y="${y(max * k) + 4}" text-anchor="end">${Math.round(max * k)}</text>`).join('');
  const t0 = fmtTime(pts[0].t, { date: false }), t1 = fmtTime(pts[pts.length - 1].t, { date: false });
  return `<svg class="chart-svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="Flows and alerts per second, last ${pts.length} seconds">
    ${grid}<path d="${area}" fill="var(--benign)" opacity="0.45"/><path d="${line('flows')}" fill="none" stroke="var(--ink-3)" stroke-width="1"/>
    <path d="${line('alerts')}" fill="none" stroke="var(--sev-critical)" stroke-width="1.5"/>
    <line class="axis-base" x1="${m.l}" x2="${w - m.r}" y1="${y(0)}" y2="${y(0)}"/>
    <text class="tick" x="${m.l}" y="${h - 4}">${t0}</text><text class="tick" x="${w - m.r}" y="${h - 4}" text-anchor="end">${t1}</text></svg>`;
}

const feedRow = (f) => html`<li><button class="lv-feed-row" data-open="${f.id}">
  <span>${sevBadge(f.severity)} <b>${f.familyTitle || f.family || 'Alert'}</b> ${riskCell(f.risk)}</span>
  <span class="when">${f.ts ? fmtTime(f.ts, { date: false }) : ''}</span>
  <span class="route">${f.src?.ip ?? '?'} → ${f.dst?.ip ?? '?'}:${f.dst?.port ?? '?'}${f.response ? ` · ${f.response.action}` : ''}</span></button></li>`;

export default {
  title: 'Live Monitor',
  render(root) {
    let apiUp = null;
    const sig = {};
    const region = (id, key, build) => { const e = $(`#${id}`, root); if (!e || sig[id] === key) return; sig[id] = key; mount(e, build()); };

    mount(root, html`
      ${pageHead({ title: 'Live Monitor', sub: 'Real traffic from the local sensor, scored by the same engine.' })}
      <div id="lv-top"></div>
      <div id="lv-learn"></div>
      <div id="lv-body"></div>`);

    const paint = (s) => {
      const conn = apiUp && s.sensor?.connected;
      region('lv-top', JSON.stringify([apiUp, s.sensor, s.stats.flows, s.stats.alerts, s.stats.timeline.length]), () => {
        const tl = s.stats.timeline.slice(-10);
        const fps = tl.length ? tl.reduce((a, p) => a + p.flows, 0) / tl.length : 0;
        return html`
          <div class="lv-status" role="status"><span class="live-dot" data-state="${conn ? 'real' : 'off'}"></span>
            <b>${conn ? 'Sensor connected' : apiUp ? 'Sensor disconnected' : 'Local server not reachable'}</b>
            ${apiUp && s.sensor?.id ? html`<span>interface <b class="mono">${s.sensor.iface || 'n/a'}</b></span><span>mode <b>${s.sensor.mode || 'live'}</b></span><span>last seen <b class="mono">${s.sensor.lastSeen ? fmtTime(s.sensor.lastSeen, { date: false }) : 'never'}</b></span>` : ''}
            ${apiUp ? html`<span class="spacer"></span><button class="btn btn-sm" data-reset>Reset live data</button>` : ''}</div>
          ${apiUp ? html`<div class="lv-metrics">${kpi('Flows', fmtInt(s.stats.flows), 'since reset')}${kpi('Flows per second', fps.toFixed(1), 'last 10 s')}${kpi('Alerts', fmtInt(s.stats.alerts), `${s.stats.flows ? ((s.stats.alerts / s.stats.flows) * 100).toFixed(2) : '0.00'}% of flows`)}${kpi('Blocked hosts', fmtInt(s.blocks.length), `${s.pending.length} awaiting approval`)}</div>` : ''}`;
      });
      region('lv-learn', JSON.stringify([apiUp, s.learning]), () => {
        if (!apiUp) return '';
        const L = s.learning || {};
        const pct = L.target ? Math.min(100, (L.flows / L.target) * 100) : 0;
        return html`<div class="lv-learn">
          <div class="lv-learn-row"><b>${L.active ? 'Learning normal traffic' : L.calibrated ? 'Calibrated on your network' : 'Not calibrated on your network'}</b>
            <span class="panel-meta">${L.active ? `${fmtInt(L.flows)} / ${fmtInt(L.target)} flows · applies automatically at the target` : L.error ? L.error : L.calibrated ? `applied ${L.calibratedAt ? new Date(L.calibratedAt).toLocaleString() : ''}` : 'Using the CIC-IDS2017 thresholds. Learning never starts on its own.'}</span>
            <span class="spacer" style="flex:1"></span>
            ${L.active ? html`<button class="btn btn-sm" data-learn="stop">Stop learning</button><button class="btn btn-sm btn-primary" data-learn="apply" ${L.flows ? '' : 'disabled'}>Apply</button>`
              : html`<button class="btn btn-sm btn-primary" data-learn="start">Start learning</button>${L.flows ? html`<button class="btn btn-sm" data-learn="apply">Apply ${fmtInt(L.flows)} flows</button>` : ''}`}</div>
          ${L.active ? html`<div class="lv-bar" role="progressbar" aria-valuemin="0" aria-valuemax="${L.target}" aria-valuenow="${L.flows}" aria-label="Learning progress"><i style="width:${pct.toFixed(1)}%"></i></div>
            <p class="panel-meta">Run only normal activity while this collects. Apply recalibrates the thresholds and rebuilds host profiles from it.</p>` : ''}
        </div>`;
      });
      region('lv-body', JSON.stringify([apiUp, conn, !!s.sensor?.id]), () => {
        ['chart', 'lv-feed', 'lv-hosts', 'lv-insider', 'lv-pending'].forEach((k) => delete sig[k]);
        if (!apiUp || (!conn && !s.stats.flows)) return html`<div style="margin-top:var(--s-4)">${howTo(apiUp)}</div>`;
        return html`<div class="lv-grid">
          ${panel({ title: 'Flow rate', meta: 'last 300 s, flows vs alerts per second', cls: 'lv-rate', body: html`<div class="chart" id="lv-chart"></div>
            <div class="legend-row"><span class="legend-item"><i class="swatch" style="background:var(--ink-3)"></i>Flows</span><span class="legend-item"><i class="swatch" style="background:var(--sev-critical)"></i>Alerts</span></div>` })}
          ${panel({ title: 'Live alerts', meta: 'newest first', cls: 'lv-feed', bodyCls: 'flush', body: html`<ul class="lv-feed-list" id="lv-feed"></ul>` })}
          ${panel({ title: 'Hosts', cls: 'lv-hosts', bodyCls: 'flush', body: html`<div class="table-wrap" id="lv-hosts"></div>` })}
          ${panel({ title: 'Insider and lateral-movement alerts', cls: 'lv-insider', bodyCls: 'flush', body: html`<ul class="ins-list" id="lv-insider"></ul>` })}
          ${panel({ title: 'Block approvals', meta: 'awaiting an analyst', cls: 'lv-pending', bodyCls: 'flush', body: html`<div id="lv-pending"></div>` })}
        </div>`;
      });
      if (!$('#lv-chart', root) && !$('#lv-feed', root)) return;
      const tl = s.stats.timeline;
      const chart = $('#lv-chart', root);
      if (chart && sig.chart !== tl.length + (tl.at(-1)?.t || '')) { sig.chart = tl.length + (tl.at(-1)?.t || ''); bindChart(chart, (w) => rateChart(w, tl)); }

      const alerts = liveFlows().filter((f) => f.verdict !== 'normal').slice(-40).reverse();
      region('lv-feed', alerts.map((f) => f.id).join(), () => alerts.length ? alerts.map(feedRow) : html`<li class="panel-body panel-meta">No alerts yet. Traffic that looks normal is not listed.</li>`);

      const blocked = new Set(s.blocks.map((b) => b.ip));
      const hosts = [...s.hosts].sort((a, b) => (b.maxRisk - a.maxRisk) || (b.flows - a.flows)).slice(0, 50);
      region('lv-hosts', JSON.stringify([hosts, [...blocked]]), () => hosts.length ? html`<table class="table"><thead><tr><th>Host</th><th>Role</th><th class="r">Flows</th><th class="r">Alerts</th><th class="r">Max risk</th><th>Services</th><th>State</th><th></th></tr></thead><tbody>
        ${hosts.map((h) => { const bl = blocked.has(h.ip) || h.blocked; return html`<tr>
          <td class="mono">${h.ip}</td><td class="muted">${h.role || 'none'}</td><td class="r mono">${fmtInt(h.flows)}</td><td class="r mono">${fmtInt(h.alerts)}</td>
          <td class="r mono" style="color:${h.maxRisk >= 85 ? SEV_COLOR.critical : h.maxRisk >= 70 ? SEV_COLOR.high : 'inherit'}">${Math.round(h.maxRisk || 0)}</td>
          <td><span class="lv-svc">${Object.entries(h.services || {}).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => html`<span class="tag-plain" title="${v} flows">${k}</span>`)}</span></td>
          <td>${bl ? html`<span class="tag-plain blocked-tag">blocked</span>` : ''}</td>
          <td class="r">${bl ? html`<button class="btn btn-sm" data-unblock="${h.ip}">Unblock</button>` : html`<button class="btn btn-sm btn-danger" data-block="${h.ip}">Block</button>`}</td></tr>`; })}
        </tbody></table>` : html`<p class="panel-body panel-meta">No hosts seen yet.</p>`);

      const ins = [...s.insider].reverse().slice(0, 30);
      region('lv-insider', ins.map((a) => a.id).join(), () => ins.length ? ins.map((a) => html`<li class="ins-item">
        <div class="ins-head">${sevBadge(a.severity)}<b>${a.title}</b><span class="tag-plain">${a.kind}</span>${a.ts ? html`<span class="panel-meta mono">${fmtTime(a.ts, { date: false })}</span>` : ''}</div>
        <p>${a.detail}</p>
        ${a.mitre?.length ? html`<div class="chips-inline">${a.mitre.map((m) => html`<span class="tag-plain">${m.tactic} · ${m.technique}</span>`)}</div>` : ''}
        ${a.actions?.length ? html`<p class="panel-meta">${a.actions.join(' · ')}</p>` : ''}
        ${a.flowId ? html`<div><button class="btn btn-sm" data-open="${a.flowId}">Open flow</button></div>` : ''}</li>`) : html`<li class="panel-body panel-meta">None. Hosts stay quiet while they warm up (first 10 minutes) unless you applied a learning window.</li>`);

      region('lv-pending', JSON.stringify(s.pending), () => s.pending.length ? s.pending.map((b) => html`<div class="pend-row" data-attention>
        <div class="grow"><b class="mono">${b.ip}</b> <span class="panel-meta">${b.reason}</span></div>
        <button class="btn btn-sm btn-primary" data-approve="${b.ip}">Approve</button><button class="btn btn-sm" data-reject="${b.ip}">Reject</button></div>`) : html`<p class="panel-body panel-meta">No blocks are waiting for approval.</p>`);
    };

    const act = async (fn, ok) => { try { await fn(); if (ok) toast(ok); } catch (e) { toast(e.message, { tone: 'error' }); } };
    on(root, 'click', '[data-open]', (_e, b) => openFlowDrawer(b.dataset.open));
    on(root, 'click', '[data-learn]', (_e, b) => act(() => liveLearn(b.dataset.learn, 400), b.dataset.learn === 'apply' ? 'Thresholds recalibrated from learned traffic' : ''));
    on(root, 'click', '[data-reset]', async () => {
      if (await confirmDialog({ title: 'Reset live data?', body: 'Clears live flows, stats and insider alerts. Blocks and host profiles are kept.', confirmLabel: 'Reset' })) act(liveReset, 'Live data cleared');
    });
    on(root, 'click', '[data-block]', async (_e, b) => {
      if (await confirmDialog({ title: `Block ${b.dataset.block}?`, body: 'The response backend applies this block (dry-run by default).', confirmLabel: 'Block', tone: 'danger' })) act(() => blockIp(b.dataset.block, 'Blocked from Live Monitor', 60), `${b.dataset.block} blocked`);
    });
    on(root, 'click', '[data-unblock]', (_e, b) => act(() => unblockIp(b.dataset.unblock), `${b.dataset.unblock} unblocked`));
    on(root, 'click', '[data-approve]', (_e, b) => act(() => approveBlock(b.dataset.approve), 'Block approved'));
    on(root, 'click', '[data-reject]', (_e, b) => act(() => rejectBlock(b.dataset.reject), 'Block rejected'));

    let stop = null;
    const first = () => paint({ ...liveState(), sensor: {}, stats: { flows: 0, alerts: 0, timeline: [] }, blocks: [], pending: [], hosts: [], insider: [] });
    apiAvailable().then((ok) => {
      apiUp = ok;
      if (!root.isConnected) return;
      if (!ok) { first(); return; }
      stop = subscribeLive((s) => { if (root.isConnected) paint(s); });
    });
    return () => stop?.();
  },
};
