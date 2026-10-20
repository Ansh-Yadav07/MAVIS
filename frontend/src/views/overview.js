// Overview: threat status, live KPIs, flow-rate chart, a compact attack graph, newest alerts,
// sensors and the learning control. Everything starts at zero and grows with live data.
import { html, mount, on, $ } from '../core/dom.js';
import { go } from '../core/router.js';
import { fmtInt, fmtTime } from '../core/format.js';
import { toast, confirmDialog } from '../components/overlays.js';
import { bindChart } from '../components/charts.js';
import { openFlowDrawer } from '../components/flow-detail.js';
import { createGraph } from '../components/attackgraph.js';
import { mountFlowMap, liveModel } from '../components/flowmap.js';
import { subscribeLive, liveFlows, liveReset, blockedSet } from '../data/index.js';
import { pageHead, panel, regions, kpi, flowsPerSec, feedRow, rateChart, learningBody, bindLearning } from './common.js';

const LEVEL = {
  calm: ['Calm', 'No active threats. Traffic looks normal.'],
  elevated: ['Elevated', 'Suspicious activity is being tracked.'],
  'under-attack': ['Under attack', 'A critical attack is in progress.'],
};

const statusCard = (s) => {
  const st = s.status || { level: 'calm' };
  const [name, fallback] = LEVEL[st.level] || LEVEL.calm;
  return html`<div class="threat-card" data-level="${st.level}">
    <div class="threat-level"><span class="threat-dot" aria-hidden="true"></span><b>${name}</b></div>
    <div class="threat-text"><span>${st.headline || fallback}</span>
      <span class="panel-meta">${st.since && st.level !== 'calm' ? `since ${fmtTime(st.since, { date: false })} · ` : ''}${st.activeEpisodes || 0} active incident${st.activeEpisodes === 1 ? '' : 's'} · ${(st.alertsPerSec || 0).toFixed(1)} alerts/s</span></div>
  </div>`;
};

const sensorRow = (x) => html`<li class="sensor-row"><span class="live-dot" data-state="${x.connected ? 'real' : 'off'}"></span>
  <span class="sensor-main"><b>${x.mode === 'sim' ? 'Simulator' : 'Real sensor'}</b> <span class="mono">${x.id}</span>${x.iface && x.mode !== 'sim' ? html` <span class="panel-meta">on ${x.iface}</span>` : ''}</span>
  <span class="panel-meta">${x.connected ? 'connected' : 'disconnected'} · ${fmtInt(x.flows || 0)} flows${x.lastSeen ? ` · ${fmtTime(x.lastSeen, { date: false })}` : ''}</span></li>`;

export default {
  title: 'Overview',
  render(root) {
    mount(root, html`
      ${pageHead({ title: 'Overview', sub: 'Live traffic from the sensor and simulator, scored by the MAVIS engine.', actions: html`<button class="btn btn-sm" data-reset>Reset live data</button>` })}
      <div id="ov-status"></div>
      <div id="ov-kpi"></div>
      ${panel({ title: 'Network flow', meta: '', cls: 'ov-flowmap', actions: html`<span class="panel-meta" id="fm-meta">waiting for traffic</span>`,
        body: html`<div class="fm-host" id="fm-host"></div><div class="legend-row" id="fm-legend">
          <span class="legend-item"><i class="swatch" style="background:var(--ink-3)"></i>Normal</span>
          <span class="legend-item"><i class="swatch" style="background:var(--sev-high)"></i>High</span>
          <span class="legend-item"><i class="swatch" style="background:var(--sev-critical)"></i>Critical</span>
          <span class="legend-item panel-meta">left: who is talking · right: which service · width = flows · dots = live movement</span></div>` })}
      <div class="ov-grid">
        ${panel({ title: 'Flow rate', meta: 'last 300 s, flows vs alerts per second', cls: 'ov-rate', body: html`<div class="chart" id="ov-chart"></div>
          <div class="legend-row"><span class="legend-item"><i class="swatch" style="background:var(--ink-3)"></i>Flows</span><span class="legend-item"><i class="swatch" style="background:var(--sev-critical)"></i>Alerts</span></div>` })}
        ${panel({ title: 'Attack graph', meta: 'last 30 s', cls: 'ov-graph', actions: html`<button class="btn btn-sm" data-go="graph">Open</button>`, body: html`<div class="ag-host" id="ov-graph"></div>` })}
        ${panel({ title: 'Latest alerts', meta: 'newest first', cls: 'ov-feed', bodyCls: 'flush', actions: html`<button class="btn btn-sm" data-go="alerts">All alerts</button>`, body: html`<ul class="lv-feed-list" id="ov-feed"></ul>` })}
        <div class="ov-side">
          ${panel({ title: 'Sensors', bodyCls: 'flush', body: html`<ul class="sensor-list" id="ov-sensors"></ul>` })}
          ${panel({ title: 'Learning', body: html`<div class="lv-learn" id="ov-learn"></div>` })}
        </div>
      </div>`);
    const region = regions(root);
    const graph = createGraph($('#ov-graph', root), { compact: true, onSelect: () => go('graph') });
    // Flow-movement map: the Mac's own traffic from the sensor (plus simulated flows when the
    // simulator runs). Redrawn at most every 2 s; the dots animate continuously in between.
    const FM_WINDOW = 600;
    let map = null, lastMap = 0;
    const drawMap = (s) => {
      const host = $('#fm-host', root);
      if (!host || Date.now() - lastMap < 2000) return;
      lastMap = Date.now();
      const list = liveFlows().slice(-FM_WINDOW);
      const real = s.sensors?.find((x) => x.mode !== 'sim' && x.connected);
      const sim = s.sensors?.find((x) => x.mode === 'sim' && x.connected);
      $('#fm-meta', root).textContent = !list.length
        ? (real ? `${real.iface} connected · waiting for flows` : 'start the sensor to see your Mac\'s traffic')
        : `${real ? `Mac sensor ${real.iface}` : 'no Mac sensor'}${sim ? ' + simulator' : ''} · last ${fmtInt(list.length)} flows`;
      if (!list.length) return;
      map ||= mountFlowMap(host, { onLink: (lk) => { if (lk.last) openFlowDrawer(lk.last); } });
      map.update(liveModel(list));
    };

    const paint = (s) => {
      if (!root.isConnected) return;
      region('ov-status', JSON.stringify([s.available, s.status]), () => s.available ? statusCard(s) : html`<div class="threat-card" data-level="offline"><div class="threat-level"><b>Server not reachable</b></div><div class="threat-text"><span>The console cannot reach the local MAVIS server. Retrying.</span></div></div>`);
      const fps = flowsPerSec(s);
      const active = (s.episodes || []).filter((e) => e.state === 'active').length;
      region('ov-kpi', JSON.stringify([s.stats.flows, s.stats.alerts, s.blocks.length, s.pending.length, active, Math.round(fps * 10)]), () => html`<div class="kpi-row">
        ${kpi('Flows', fmtInt(s.stats.flows), 'since reset')}
        ${kpi('Flows per second', fps.toFixed(1), 'last 10 s')}
        ${kpi('Alerts', fmtInt(s.stats.alerts), `${s.stats.flows ? ((s.stats.alerts / s.stats.flows) * 100).toFixed(2) : '0.00'}% of flows`)}
        ${kpi('Blocked hosts', fmtInt(blockedSet(s).size), `${s.pending.length} awaiting approval`)}
        ${kpi('Active incidents', fmtInt(active), `${(s.episodes || []).length} total`, active ? 'critical' : '')}</div>`);
      bindChart($('#ov-chart', root), (w) => rateChart(w, s.stats.timeline));
      graph.update(s);
      drawMap(s);
      const alerts = liveFlows().filter((f) => f.verdict !== 'normal').slice(-8).reverse();
      region('ov-feed', alerts.map((f) => f.id).join(), () => alerts.length ? alerts.map(feedRow) : html`<li class="panel-body panel-meta">No alerts yet. Normal traffic is not listed.</li>`);
      region('ov-sensors', JSON.stringify(s.sensors), () => s.sensors?.length ? s.sensors.map(sensorRow) : html`<li class="panel-body panel-meta">No sensor has reported yet. Start the sensor or run the simulator (see the commands on the landing page or in the README).</li>`);
      region('ov-learn', JSON.stringify(s.learning), () => learningBody(s));
    };

    on(root, 'click', '[data-open]', (_e, b) => openFlowDrawer(b.dataset.open));
    on(root, 'click', '[data-go]', (_e, b) => go(b.dataset.go));
    on(root, 'click', '[data-reset]', async () => {
      if (!(await confirmDialog({ title: 'Reset live data?', body: 'Clears live flows, stats, incidents and insider alerts. Blocks and host profiles are kept.', confirmLabel: 'Reset' }))) return;
      try { await liveReset(); toast('Live data cleared'); } catch (e) { toast(e.message, { tone: 'error' }); }
    });
    bindLearning(root);
    const stop = subscribeLive(paint);
    return () => { stop(); graph.destroy(); map?.destroy(); };
  },
};
