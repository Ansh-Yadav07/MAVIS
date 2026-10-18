// Reports: a printable analysis report for the selected capture day (or all days), built from
// engine output only. Print / Save as PDF uses the browser's print dialog (see the print
// stylesheet in views.css); JSON and CSV downloads are generated in the browser.
import { html, mount, on } from '../core/dom.js';
import { fmtInt, fmtPct } from '../core/format.js';
import { icon } from '../components/icons.js';
import { sevBadge, tagEngine, tagEval } from '../components/security.js';
import { toast } from '../components/overlays.js';
import { flagged, summary, incidents, insights, drift, snapshot, engine, currentBudget } from '../data/index.js';
import { pageHead, curDay, dayName, scopeText, watch, download, csvCell, ratioBar, pctText, detectedBy } from './common.js';

const CATS = ['DoS', 'DDoS', 'PortScan', 'BruteForce', 'WebAttack', 'Bot', 'Infiltration', 'Heartbleed'];
const sevKey = (s) => String(s || '').toLowerCase();

function build(day) {
  const s = summary(day);
  const alerts = flagged(day ? { day } : {});
  return {
    day, s, alerts,
    top: [...alerts].sort((a, b) => b.risk - a.risk).slice(0, 10),
    incidents: incidents(day).slice(0, 8),
    insights: insights(day),
    drift: drift(day),
  };
}

function toJson(r) {
  const snap = snapshot();
  return {
    report: 'MAVIS analysis report',
    scope: scopeText(r.day),
    snapshotGenerated: snap?.generated,
    alertBudget: currentBudget(),
    summary: { flows: r.s.flows, alerts: r.s.alerts, alertRate: r.s.alertRate, verdicts: r.s.verdicts, severity: r.s.severity,
      families: r.s.families, detectionModes: r.s.modes, modelAgreement: r.s.agreement, note: 'Totals are full-capture counts at the engine default budget.' },
    groundTruth: r.s.groundTruth,
    incidents: r.incidents.map(({ id, ...i }) => i),
    insights: r.insights.map((i) => ({ day: i.day, file: i.file, text: i.text })),
    drift: r.drift,
    topAlerts: r.top.map((f) => ({ id: f.id, day: f.day, file: f.file, row: f.row, family: f.family, severity: f.severity, risk: f.risk, destinationPort: f.dst.port, service: f.service, detectedBy: detectedBy(f) })),
  };
}

function toCsv(list) {
  const head = ['id', 'day', 'file', 'row', 'family', 'severity', 'risk', 'verdict', 'mode', 'confidence', 'destination_port', 'service', 'detected_by', 'label', 'outcome'];
  const rows = list.map((f) => [f.id, f.day, f.file, f.row, f.family, f.severity, f.risk, f.verdict, f.mode, f.confidence, f.dst.port, f.service, detectedBy(f).join('+'), f.label, f.outcome]);
  return [head, ...rows].map((r) => r.map(csvCell).join(',')).join('\n');
}

export default {
  title: 'Reports',
  render(root) {
    let r = null;
    const paint = () => {
      const day = curDay();
      r = build(day);
      const { s } = r;
      const gt = s.groundTruth;
      const generated = snapshot()?.generated ? new Date(snapshot().generated).toISOString().slice(0, 10) : 'unknown';
      const hi = (s.severity.critical || 0) + (s.severity.high || 0);
      const topFam = Object.entries(s.families).sort((a, b) => b[1] - a[1])[0];

      mount(root, html`
        ${pageHead({ title: 'Reports', sub: 'A report for the day selected in the top bar, or for all days. Print it, save it as PDF, or download the data.',
          actions: html`
            <button class="btn" data-action="print">${icon('reports')}Print / Save as PDF</button>
            <button class="btn" data-action="json">${icon('copy')}Download JSON</button>
            <button class="btn" data-action="csv">${icon('copy')}Download alerts CSV</button>` })}

        <article class="report" aria-label="Analysis report">
          <header class="report-head">
            <div class="report-kicker">MAVIS analysis report</div>
            <h2 class="report-title">CIC-IDS2017 · ${scopeText(day)}</h2>
            <div class="report-meta"><span>Snapshot ${generated}</span><span>Alert budget ${fmtPct(currentBudget(), 2)}</span><span>${fmtInt(s.files)} capture file${s.files === 1 ? '' : 's'}</span><span>Capture order, not clock time: the source CSVs have no timestamps</span></div>
          </header>

          <section class="report-sec">
            <h3>Summary ${tagEngine()}</h3>
            <p>The engine analysed <b>${fmtInt(s.flows)}</b> flows and raised <b>${fmtInt(s.alerts)}</b> alerts (${fmtPct(s.alertRate, 2)}), of which <b>${fmtInt(hi)}</b> are High or Critical.
              ${topFam ? html` The most frequent attack type is <b>${topFam[0]}</b> with ${fmtInt(topFam[1])} alerts.` : ''}
              ${s.modes ? html` ${fmtInt((s.modes.known || 0) + (s.modes['known+novel'] || 0))} alerts match a known attack family and ${fmtInt(s.modes.novel || 0)} were flagged only as novel (anomalous, no known family).` : ''}
              Among the exported alerts, ${fmtPct(s.agreement, 0)} were confirmed by at least two detectors.</p>
            <dl class="kv report-kv">
              ${['critical', 'high', 'medium', 'low'].map((k) => html`<dt>${sevBadge(k)}</dt><dd class="mono">${fmtInt(s.severity[k] || 0)}</dd>`)}
            </dl>
            <p class="panel-meta">Totals are full-capture counts at the engine default budget (${fmtPct(engine().alertBudgetFpr)}); tables below use the budget selected in the top bar.</p>
          </section>

          <section class="report-sec">
            <h3>Performance against ground truth ${gt ? tagEngine() : ''}</h3>
            ${gt ? html`
              <p>The capture files carry labels, so the verdicts can be scored. ${CATS.some((c) => gt.perCategory[c]) ? html`Attack recall is <b>${pctText(gt.recall)}</b> and the` : html`This selection contains no attacks, so only the`} false-positive rate on benign flows is <b>${pctText(gt.fpr, 2)}</b>. “Named correctly” is the share of alerted flows that received the right attack family.</p>
              <div class="table-wrap"><table class="table table-tight"><thead><tr><th scope="col">Category</th><th scope="col" class="r">Flows</th><th scope="col">Alerted</th><th scope="col" class="r">Named correctly</th></tr></thead>
                <tbody>${['Benign', ...CATS].filter((c) => gt.perCategory[c]).map((c) => html`<tr><td>${c === 'Benign' ? 'Benign (false alerts)' : c}</td><td class="r mono">${fmtInt(gt.perCategory[c].n)}</td><td>${ratioBar(gt.perCategory[c].alerted, c === 'Benign' ? 'var(--sev-medium)' : 'var(--accent)')}</td><td class="r mono">${c === 'Benign' ? '' : pctText(gt.perCategory[c].named)}</td></tr>`)}</tbody></table></div>`
              : html`<p>No ground-truth labels for this selection.</p>`}
          </section>

          <section class="report-sec">
            <h3>Top incidents ${tagEngine()}</h3>
            ${r.incidents.length ? html`<ol class="incident-list">${r.incidents.map((i) => html`
              <li><div class="inc-head">${sevBadge(sevKey(i.severity))}<b>${i.title}</b><span class="muted">${dayName(i.day)} · ${i.file.split('.')[0]}</span></div>
                <div class="inc-meta"><span class="mono">${fmtInt(i.flows)} flows</span><span class="mono">max risk ${Math.round(i.max_risk)}</span>${i.distinct_dst_ports ? html`<span class="mono">${fmtInt(i.distinct_dst_ports)} destination ports</span>` : ''}${i.top_dst_ports ? html`<span class="mono muted">top ports ${Object.keys(i.top_dst_ports).join(', ')}</span>` : ''}</div>
                ${i.mitre?.length ? html`<div class="panel-meta">MITRE ATT&amp;CK: ${i.mitre.join('; ')}</div>` : ''}
                ${i.actions?.length ? html`<div class="panel-meta">Suggested: ${i.actions.slice(0, 2).join(' ')}</div>` : ''}
              </li>`)}</ol>` : html`<p>No incidents for this selection.</p>`}
          </section>

          <section class="report-sec">
            <h3>Highest-risk alerts <span class="panel-meta">exported sample</span></h3>
            ${r.top.length ? html`<div class="table-wrap"><table class="table table-tight"><thead><tr><th scope="col">Capture</th><th scope="col">Attack type</th><th scope="col">Destination</th><th scope="col">Risk</th><th scope="col">Detected by</th></tr></thead>
              <tbody>${r.top.map((f) => html`<tr><td>${dayName(f.day).split(' ')[0]} <span class="muted num">#${fmtInt(f.row)}</span></td><td>${f.familyTitle || f.family}</td><td><span class="mono">${f.dst.port ?? 'n/a'}</span> <span class="muted">${f.service}</span></td><td>${sevBadge(f.severity)} <span class="mono">${Math.round(f.risk)}</span></td><td class="mono">${detectedBy(f).join(' · ') || 'none'}</td></tr>`)}</tbody></table></div>` : html`<p>No exported alerts at this budget.</p>`}
          </section>

          <section class="report-sec">
            <h3>Insights ${tagEngine()}</h3>
            ${r.insights.length ? html`<ul class="recs">${r.insights.map((i) => html`<li>${i.text} <span class="muted">${dayName(i.day).split(' ')[0]}</span></li>`)}</ul>` : html`<p>No insights.</p>`}
          </section>

          <section class="report-sec">
            <h3>Drift check ${tagEngine()}</h3>
            <p>Compares the flows judged normal with the benign baseline the engine was trained on (population stability index per feature). More than a few drifted features means the engine should be recalibrated for that network.</p>
            <div class="table-wrap"><table class="table table-tight"><thead><tr><th scope="col">File</th><th scope="col">Status</th><th scope="col" class="r">Drifted features</th><th scope="col">Most shifted (PSI)</th></tr></thead>
              <tbody>${r.drift.map((d) => html`<tr><td>${dayName(d.day).split(' ')[0]} <span class="muted">${d.file.split('.')[0]}</span></td><td>${d.status}</td><td class="r mono">${d.features_drifted ?? 'n/a'}</td><td class="mono muted">${(d.top || []).slice(0, 3).map((t) => `${t.feature} ${t.psi}`).join(', ') || 'n/a'}</td></tr>`)}</tbody></table></div>
          </section>

          <footer class="report-foot">Generated by the MAVIS console from the engine snapshot. ${tagEval('Detector metrics')} are on the Models page.</footer>
        </article>`);
    };

    paint();
    on(root, 'click', '[data-action="print"]', () => {
      // Print on paper colours even when the console is in the dark theme.
      const el = document.documentElement, prev = el.dataset.appearance;
      el.dataset.appearance = 'light';
      try { window.print(); } finally { el.dataset.appearance = prev; }
    });
    on(root, 'click', '[data-action="json"]', () => {
      download(`mavis-report-${curDay() || 'all'}.json`, 'application/json', JSON.stringify(toJson(r), null, 2));
      toast('Report JSON downloaded');
    });
    on(root, 'click', '[data-action="csv"]', () => {
      const list = [...r.alerts].sort((a, b) => b.risk - a.risk);
      download(`mavis-alerts-${curDay() || 'all'}.csv`, 'text/csv', toCsv(list));
      toast(`${fmtInt(list.length)} exported alerts downloaded`);
    });
    return watch(paint);
  },
};
