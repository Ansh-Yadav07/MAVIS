// Network Traffic: flows, protocols and endpoints, with a clearly labelled simulated replay.
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { fmtInt, fmtBytes, fmtDurationUs, fmtTime } from '../core/format.js';
import { icon } from '../components/icons.js';
import { bindChart, timeSeries, hBars } from '../components/charts.js';
import { sevBadge, ipText, protoTag, tagSample, tagReal, SEV_LABEL } from '../components/security.js';
import { createTable } from '../components/table.js';
import { openFlowDrawer } from '../components/flow-detail.js';
import { toast } from '../components/overlays.js';
import { flows, DAYS } from '../data/index.js';
import { pageHead, panel, activityBuckets } from './common.js';

const PROTOS = ['TCP', 'UDP', 'ICMP'];

export default {
  title: 'Network Traffic',
  render(root) {
    const f0 = store.session.networkFilters || { day: 'all', protos: [...PROTOS], sev: 'any', q: '' };
    const filters = { ...f0, protos: [...f0.protos] };
    let replay = { running: false, idx: 0, timer: null, shown: [] };

    mount(root, html`
      ${pageHead({
        title: 'Network Traffic',
        sub: 'Flows grouped by time, protocol and endpoint. Use the replay to step through sample flows in capture order.',
        actions: html`
          <button class="btn" data-replay="toggle" aria-pressed="false">${icon('play')}<span>Start simulated replay</span></button>
          <button class="btn btn-ghost" data-replay="reset" aria-label="Reset replay">${icon('reset')}Reset</button>`,
      })}

      <div class="mode-banner" role="note">
        <span class="live-dot" data-state="sample" id="replay-dot"></span>
        <div><b>Simulated replay</b> of sample flows across the CIC-IDS2017 capture week (3–7 July 2017). MAVIS does not capture live packets.</div>
        <span class="mode-banner-meta mono" id="replay-meta">Paused</span>
      </div>

      <div class="filters" role="group" aria-label="Traffic filters">
        <div class="segmented" role="group" aria-label="Capture day">
          <button data-day="all" aria-pressed="${filters.day === 'all'}">All days</button>
          ${DAYS.map((d) => html`<button data-day="${d.id}" aria-pressed="${filters.day === d.id}">${d.label.slice(0, 3)}</button>`)}
        </div>
        <div class="toolbar" role="group" aria-label="Protocol">
          ${PROTOS.map((p) => html`<button class="chip" data-proto="${p}" aria-pressed="${filters.protos.includes(p)}">${p}</button>`)}
        </div>
        <label class="visually-hidden" for="net-sev">Severity</label>
        <select class="select" id="net-sev" style="width:auto">
          <option value="any">Any severity</option>
          <option value="flagged" ${filters.sev === 'flagged' ? html`selected` : ''}>Flagged only</option>
          ${['critical', 'high', 'medium', 'low', 'none'].map((s) => html`<option value="${s}" ${filters.sev === s ? html`selected` : ''}>${SEV_LABEL[s]}</option>`)}
        </select>
        <div class="search" style="flex:1 1 200px;max-width:300px">${icon('search')}
          <input class="input" id="net-q" type="search" placeholder="Filter by IP address" aria-label="Filter by IP address" value="${filters.q}" inputmode="decimal">
        </div>
        <span class="panel-meta" id="net-count" aria-live="polite"></span>
      </div>

      <div class="net-grid">
        ${panel({ title: 'Traffic activity', tag: tagSample(), cls: 'span-2', id: 'p-activity',
          body: html`<div class="chart-legend-row"><div class="legend"><span class="legend-item"><i class="swatch" style="background:var(--ink-3)"></i>Flows</span><span class="legend-item"><i class="swatch" style="background:var(--accent)"></i>Flagged</span></div></div><div class="chart" id="ch-net"></div>` })}
        ${panel({ title: 'Data sources', body: html`
          <ul class="sources">
            <li><span class="live-dot" data-state="real"></span><div><b>CIC-IDS2017 profile</b><span>8 CSV files measured ${tagReal()}</span></div></li>
            <li><span class="live-dot" data-state="sample"></span><div><b>Detection replay</b><span>Sample flows generated in the browser ${tagSample()}</span></div></li>
            <li><span class="live-dot" data-state="off"></span><div><b>Live packet capture</b><span>Not connected. No capture agent exists in this project.</span></div></li>
            <li><span class="live-dot" data-state="off"></span><div><b>File upload</b><span>Not supported yet. Analysis runs on the bundled dataset.</span></div></li>
          </ul>` })}
        ${panel({ title: 'Protocols', tag: tagSample(), body: html`<div class="chart" id="ch-proto"></div>` })}
        ${panel({ title: 'Top sources', tag: tagSample(), body: html`<div class="chart" id="ch-src"></div>` })}
        ${panel({ title: 'Top destinations', tag: tagSample(), body: html`<div class="chart" id="ch-dst"></div>` })}
      </div>

      ${panel({ title: 'Flows', tag: tagSample(), bodyCls: 'flush', id: 'p-flows', body: html`<div id="net-table"></div>` })}
    `);

    const match = (f) =>
      (filters.day === 'all' || f.day === filters.day) &&
      filters.protos.includes(f.proto) &&
      (filters.sev === 'any' || (filters.sev === 'flagged' ? f.agree > 0 : f.severity === filters.sev)) &&
      (!filters.q || f.src.ip.includes(filters.q.trim()) || f.dst.ip.includes(filters.q.trim()));

    const table = createTable($('#net-table', root), {
      rows: [], pageSize: store.prefs.pageSize, caption: 'Sample network flows',
      initialSort: { key: 'ts', dir: 'desc' },
      rowAttrs: (f) => ({ 'data-sev': f.severity }),
      onRowClick: (f) => openFlowDrawer(f.id),
      columns: [
        { key: 'ts', label: 'Time (UTC)', render: (f) => html`<span class="mono muted">${fmtTime(f.ts)}</span>` },
        { key: 'src', label: 'Source', sort: (f) => f.src.ip, render: (f) => ipText(f.src.ip, f.src.port, { scope: true }) },
        { key: 'dst', label: 'Destination', sort: (f) => f.dst.ip, render: (f) => ipText(f.dst.ip, f.dst.port, { scope: true }) },
        { key: 'proto', label: 'Protocol', render: (f) => html`${protoTag(f.proto)} <span class="muted">${f.service}</span>` },
        { key: 'packets', label: 'Packets', align: 'right', render: (f) => html`<span class="mono">${fmtInt(f.packets)}</span>` },
        { key: 'bytes', label: 'Bytes', align: 'right', render: (f) => html`<span class="mono">${fmtBytes(f.bytes)}</span>` },
        { key: 'durationUs', label: 'Duration', align: 'right', render: (f) => html`<span class="mono">${fmtDurationUs(f.durationUs)}</span>` },
        { key: 'severity', label: 'Severity', className: 'sev-cell', sort: (f) => ['none', 'low', 'medium', 'high', 'critical'].indexOf(f.severity), render: (f) => sevBadge(f.severity) },
      ],
      card: (f) => html`<span class="event-card-row"><span class="mono muted" style="font-size:12px">${fmtTime(f.ts)}</span>${sevBadge(f.severity)}</span>
        <span class="event-card-row route">${ipText(f.src.ip, f.src.port)}<span class="muted">→</span>${ipText(f.dst.ip, f.dst.port)}</span>
        <span class="event-card-row"><span>${protoTag(f.proto)} <span class="muted">${f.service}</span></span><span class="mono muted">${fmtInt(f.packets)} pkts · ${fmtBytes(f.bytes)}</span></span>`,
      emptyTitle: 'No flows match these filters', emptyText: 'Widen the day, protocol or severity filters, or clear the IP search.',
    });

    const topN = (list, key) => {
      const c = {};
      list.forEach((f) => { c[f[key].ip] = (c[f[key].ip] || 0) + 1; });
      return Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 6)
        .map(([ip, v]) => ({ label: ip, value: v, color: list.some((f) => f[key].ip === ip && f.agree > 1) ? 'var(--accent)' : 'var(--ink-3)' }));
    };

    function draw(flash = []) {
      const base = replay.shown.length ? replay.shown : flows();
      const list = base.filter(match);
      $('#net-count', root).textContent = `${fmtInt(list.length)} flows`;
      table.setRows(list, { flash, resetPage: !flash.length });
      const act = activityBuckets(list, filters.day === 'all' ? null : filters.day);
      bindChart($('#ch-net', root), (w) => timeSeries(w, 200, {
        buckets: act.buckets, xLabels: act.xLabels, label: 'Sample flows over time',
        area: { key: 'total', name: 'Flows', color: 'var(--surface-3)', stroke: 'var(--ink-3)' },
        line: { key: 'flagged', name: 'Flagged', color: 'var(--accent)' },
      }));
      const protoRows = PROTOS.map((p) => ({ label: p, value: list.filter((f) => f.proto === p).length, color: 'var(--ink-3)' }));
      bindChart($('#ch-proto', root), (w) => hBars(w, 0, { rows: protoRows, label: 'Flows by protocol', labelWidth: 54, showShare: true }));
      bindChart($('#ch-src', root), (w) => hBars(w, 0, { rows: topN(list, 'src'), label: 'Top source addresses', labelWidth: 120 }));
      bindChart($('#ch-dst', root), (w) => hBars(w, 0, { rows: topN(list, 'dst'), label: 'Top destination addresses', labelWidth: 120 }));
      store.session.networkFilters = filters;
    }

    // Simulated replay: feeds sample flows in capture order. Never presented as live traffic.
    const ordered = () => flows().filter((f) => filters.day === 'all' || f.day === filters.day).sort((a, b) => a.ts.localeCompare(b.ts));
    const setReplayUi = () => {
      const btn = root.querySelector('[data-replay="toggle"]');
      btn.setAttribute('aria-pressed', String(replay.running));
      btn.querySelector('span').textContent = replay.running ? 'Pause replay' : replay.shown.length ? 'Resume replay' : 'Start simulated replay';
      btn.querySelector('svg').outerHTML = String(icon(replay.running ? 'pause' : 'play'));
      $('#replay-dot', root).dataset.state = replay.running ? 'running' : 'sample';
      const seq = ordered();
      $('#replay-meta', root).textContent = replay.shown.length
        ? `${fmtInt(replay.shown.length)} / ${fmtInt(seq.length)} · ${fmtTime(replay.shown[replay.shown.length - 1].ts)}`
        : 'Paused';
    };
    const tick = () => {
      const seq = ordered();
      const batch = seq.slice(replay.idx, replay.idx + 3);
      if (!batch.length) { stop(); toast('Replay reached the end of the sample week'); return; }
      replay.idx += batch.length;
      replay.shown = seq.slice(0, replay.idx);
      draw(batch.map((f) => f.id));
      setReplayUi();
    };
    const start = () => { replay.running = true; if (!replay.shown.length) replay.idx = 0; replay.timer = setInterval(tick, 900); tick(); };
    const stop = () => { replay.running = false; clearInterval(replay.timer); setReplayUi(); };

    on(root, 'click', '[data-replay]', (_e, b) => {
      if (b.dataset.replay === 'toggle') { replay.running ? stop() : start(); }
      else { stop(); replay = { running: false, idx: 0, timer: null, shown: [] }; setReplayUi(); draw(); }
    });
    on(root, 'click', '[data-day]', (_e, b) => {
      filters.day = b.dataset.day;
      root.querySelectorAll('[data-day]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      if (replay.shown.length) { stop(); replay = { running: false, idx: 0, timer: null, shown: [] }; setReplayUi(); }
      draw();
    });
    on(root, 'click', '[data-proto]', (_e, b) => {
      const p = b.dataset.proto;
      filters.protos = filters.protos.includes(p) ? filters.protos.filter((x) => x !== p) : [...filters.protos, p];
      b.setAttribute('aria-pressed', String(filters.protos.includes(p)));
      draw();
    });
    on(root, 'change', '#net-sev', (_e, s) => { filters.sev = s.value; draw(); });
    let qTimer;
    on(root, 'input', '#net-q', (_e, i) => { clearTimeout(qTimer); qTimer = setTimeout(() => { filters.q = i.value; draw(); }, 160); });

    draw();
    return () => clearInterval(replay.timer);
  },
};
