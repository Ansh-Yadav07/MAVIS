// Network Traffic: what the capture contained, by destination service and port.
// The public CIC-IDS2017 CSVs have no IP addresses, so there is no host graph. Per-service
// figures come from the exported flow sample (alerts of every family plus normal traffic),
// the per-file timeline from every flow in each file.
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { fmtInt, fmtBytes, fmtDurationUs, fmtPct } from '../core/format.js';
import { bindChart, hBars } from '../components/charts.js';
import { sevBadge, ipText, tagEngine, infoCallout } from '../components/security.js';
import { createTable } from '../components/table.js';
import { openFlowDrawer } from '../components/flow-detail.js';
import { flows, timeline, summary } from '../data/index.js';
import { pageHead, panel, curDay, dayName, scopeText, watch, activityChart, ratioBar } from './common.js';

const SEV_RANK = ['none', 'low', 'medium', 'high', 'critical'];

function byPort(list) {
  const m = new Map();
  for (const f of list) {
    const key = f.dst.port ?? -1;
    const e = m.get(key) || { id: String(key), port: f.dst.port, service: f.service, flows: 0, alerts: 0, packets: 0, bytes: 0, fam: {} };
    e.flows++; e.packets += f.packets || 0; e.bytes += f.bytes || 0;
    if (f.verdict !== 'normal') { e.alerts++; e.fam[f.familyTitle || f.family] = (e.fam[f.familyTitle || f.family] || 0) + 1; }
    m.set(key, e);
  }
  return [...m.values()].map((e) => ({ ...e, share: e.flows ? e.alerts / e.flows : 0, top: Object.entries(e.fam).sort((a, b) => b[1] - a[1])[0]?.[0] || '' }));
}

export default {
  title: 'Network Traffic',
  render(root) {
    let view = { service: 'all', flaggedOnly: false };

    const paint = () => {
      const day = curDay();
      const list = flows(day ? { day } : {});
      const ports = byPort(list).sort((a, b) => b.flows - a.flows);
      const services = [...new Set(list.map((f) => f.service))].sort();
      const s = summary(day);
      const topFlows = ports.slice(0, 8).map((p) => ({ label: `${p.service}${p.port != null ? ` ${p.port}` : ''}`, value: p.flows, color: 'var(--ink-3)' }));
      const topAlerts = [...ports].sort((a, b) => b.alerts - a.alerts).filter((p) => p.alerts).slice(0, 8)
        .map((p) => ({ label: `${p.service}${p.port != null ? ` ${p.port}` : ''}`, value: p.alerts, color: 'var(--accent)' }));

      mount(root, html`
        ${pageHead({ title: 'Network Traffic', sub: `Traffic composition for ${scopeText(day)}, by destination service and port.` })}
        ${infoCallout(html`<b>No host graph.</b> The public CIC-IDS2017 CSVs contain no IP addresses or timestamps, so traffic is grouped by destination port and service, and ordered by file position rather than clock time.`)}

        <div class="net-grid">
          ${panel({ title: 'Traffic per capture file', tag: tagEngine(), meta: `${fmtInt(s.flows)} flows · ${fmtInt(s.alerts)} alerts`, cls: 'span-3',
            body: html`<div class="chart" id="ch-net"></div><div class="legend-row"><span class="legend-item"><i class="swatch" style="background:var(--accent)"></i>Alerts</span><span class="legend-item"><i class="swatch" style="background:var(--benign)"></i>Normal</span></div>
              <p class="panel-meta">Every flow in each file, in 48 slices per file in file order. Hover a file label for its totals.</p>` })}
          ${panel({ title: 'Flows by destination service', tag: tagEngine('Exported sample'), meta: `${fmtInt(list.length)} sampled flows`,
            body: html`<div class="chart" id="ch-svc"></div><p class="panel-meta">Sample of exported flows: it over-represents alerts, so use it for composition, not volumes.</p>` })}
          ${panel({ title: 'Alerts by service', tag: tagEngine('Exported sample'),
            body: topAlerts.length ? html`<div class="chart" id="ch-alert"></div>` : html`<p class="panel-meta">No exported alerts for this selection.</p>` })}
          ${panel({ title: 'What is on the wire', tag: tagEngine('Exported sample'), body: html`
            <dl class="kv">
              <dt>Distinct ports</dt><dd class="mono">${fmtInt(ports.length)}</dd>
              <dt>Distinct services</dt><dd class="mono">${fmtInt(services.length)}</dd>
              <dt>Mean packets / flow</dt><dd class="mono">${fmtInt(list.reduce((a, f) => a + (f.packets || 0), 0) / Math.max(1, list.length))}</dd>
              <dt>Mean bytes / flow</dt><dd class="mono">${fmtBytes(list.reduce((a, f) => a + (f.bytes || 0), 0) / Math.max(1, list.length))}</dd>
              <dt>Protocol field</dt><dd>Not in the source CSV</dd>
            </dl>` })}
        </div>

        ${panel({ title: 'Services and ports', tag: tagEngine('Exported sample'), bodyCls: 'flush', body: html`<div id="port-table"></div>` })}

        ${panel({ title: 'Flows', tag: tagEngine('Exported sample'), bodyCls: 'flush',
          actions: html`
            <label class="visually-hidden" for="net-svc">Service</label>
            <select class="select" id="net-svc" style="width:auto"><option value="all">All services</option>${services.map((v) => html`<option value="${v}" ${view.service === v ? html`selected` : ''}>${v}</option>`)}</select>
            <button class="chip" data-flagged aria-pressed="${view.flaggedOnly}">Alerts only</button>`,
          body: html`<div id="net-table"></div>` })}`);

      bindChart($('#ch-net', root), (w) => activityChart(w, 210, { files: timeline(day), label: 'Alerts and normal flows per capture file' }));
      bindChart($('#ch-svc', root), (w) => hBars(w, 0, { rows: topFlows, label: 'Sampled flows by destination service', labelWidth: 112, showShare: true }));
      if (topAlerts.length) bindChart($('#ch-alert', root), (w) => hBars(w, 0, { rows: topAlerts, label: 'Sampled alerts by destination service', labelWidth: 112 }));

      createTable($('#port-table', root), {
        rows: ports, pageSize: 10, caption: 'Services and ports in the exported sample',
        initialSort: { key: 'flows', dir: 'desc' },
        columns: [
          { key: 'service', label: 'Service', render: (p) => html`<b>${p.service}</b>` },
          { key: 'port', label: 'Port', align: 'right', sort: (p) => p.port ?? -1, render: (p) => html`<span class="mono">${p.port ?? 'n/a'}</span>` },
          { key: 'flows', label: 'Flows', align: 'right', render: (p) => html`<span class="mono">${fmtInt(p.flows)}</span>` },
          { key: 'alerts', label: 'Alerts', align: 'right', render: (p) => html`<span class="mono">${fmtInt(p.alerts)}</span>` },
          { key: 'share', label: 'Alert share', render: (p) => ratioBar(p.share) },
          { key: 'bytes', label: 'Mean bytes', align: 'right', sort: (p) => p.bytes / p.flows, render: (p) => html`<span class="mono">${fmtBytes(p.bytes / Math.max(1, p.flows))}</span>` },
          { key: 'top', label: 'Main attack type', sortable: false, render: (p) => p.top || html`<span class="muted">none</span>` },
        ],
      });

      const shown = list.filter((f) => (view.service === 'all' || f.service === view.service) && (!view.flaggedOnly || f.verdict !== 'normal'));
      createTable($('#net-table', root), {
        rows: shown, pageSize: store.prefs.pageSize, caption: 'Exported flows',
        initialSort: { key: 'risk', dir: 'desc' },
        rowAttrs: (f) => ({ 'data-sev': f.severity }),
        onRowClick: (f) => openFlowDrawer(f.id),
        emptyTitle: 'No flows match', emptyText: 'Clear the service filter or include normal traffic.',
        columns: [
          { key: 'day', label: 'Capture', sort: (f) => `${f.file}${String(f.row).padStart(9, '0')}`, render: (f) => html`${dayName(f.day).split(' ')[0]} <span class="muted num">#${fmtInt(f.row)}</span>` },
          { key: 'dst', label: 'Destination', sort: (f) => f.dst.port ?? -1, render: (f) => html`${ipText(null, f.dst.port)} <span class="muted">${f.service}</span>` },
          { key: 'packets', label: 'Packets', align: 'right', render: (f) => html`<span class="mono">${fmtInt(f.packets)}</span>` },
          { key: 'bytes', label: 'Bytes', align: 'right', render: (f) => html`<span class="mono">${fmtBytes(f.bytes)}</span>` },
          { key: 'durationUs', label: 'Duration', align: 'right', render: (f) => html`<span class="mono">${fmtDurationUs(f.durationUs)}</span>` },
          { key: 'risk', label: 'Risk', className: 'sev-cell', sort: (f) => f.risk, render: (f) => f.verdict === 'normal' ? html`<span class="muted">normal</span>` : html`${sevBadge(f.severity)} <span class="mono">${Math.round(f.risk)}</span>` },
        ],
        card: (f) => html`<span class="event-card-row"><span class="mono muted" style="font-size:12px">${dayName(f.day).split(' ')[0]} #${fmtInt(f.row)}</span>${sevBadge(f.severity)}</span>
          <span class="event-card-row">${ipText(null, f.dst.port)}<span class="muted">${f.service}</span></span>
          <span class="event-card-row"><span class="mono muted">${fmtInt(f.packets)} pkts · ${fmtBytes(f.bytes)}</span><span class="mono muted">${fmtPct(f.pKnown, 0)} attack</span></span>`,
      });
    };

    paint();
    on(root, 'change', '#net-svc', (_e, sel) => { view.service = sel.value; paint(); $('#net-svc', root)?.focus(); });
    on(root, 'click', '[data-flagged]', () => { view.flaggedOnly = !view.flaggedOnly; paint(); $('[data-flagged]', root)?.focus(); });
    return watch(paint);
  },
};
