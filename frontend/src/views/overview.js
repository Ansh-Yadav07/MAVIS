// Overview: the analyst's first screen. Leads with what is real (the profiled dataset and the
// pipeline's actual state), then the sample detection picture, then what needs attention.
import { html, raw, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { go } from '../core/router.js';
import { fmtInt, fmtPct, fmtTime, fmtBytes } from '../core/format.js';
import { icon } from '../components/icons.js';
import { bindChart, stackedColumns, timeSeries, hBars, agreementMatrix, meter } from '../components/charts.js';
import { sevBadge, statusBadge, modelStrip, ipText, tagSample, tagReal, tagCode, tagPlanned } from '../components/security.js';
import { createTable } from '../components/table.js';
import { openFlowDrawer } from '../components/flow-detail.js';
import { flows, cicSummary, cicByDay, DAYS } from '../data/index.js';
import { MODELS } from '../data/model-registry.js';
import { PIPELINE, STATE_LABEL } from '../data/pipeline-status.js';
import { SAMPLE_ACTIVITY } from '../data/sample/events.js';
import { remount, pageHead, panel, severityRows, severityCounts, SEV_COLOR, activityBuckets, agreementCombos } from './common.js';

const STATE_TAG = { done: tagReal('Has output'), code: tagCode('Code only'), planned: tagPlanned('Not built'), ui: tagCode('This UI') };

function pipelineList() {
  return html`<ol class="pipeline">${PIPELINE.map((p) => html`
    <li class="pipe-step" data-state="${p.state}">
      <span class="pipe-node" aria-hidden="true"></span>
      <div class="pipe-text">
        <div class="pipe-top"><span class="pipe-label">${p.label}</span>${STATE_TAG[p.state]}</div>
        <div class="pipe-detail">${p.detail}</div>
        <div class="pipe-evidence mono">${p.evidence}</div>
      </div>
      <span class="visually-hidden">${STATE_LABEL[p.state]}</span>
    </li>`)}</ol>`;
}

export default {
  title: 'Overview',
  render(root) {
    const cic = cicSummary();
    const range = store.prefs.overviewRange; // 'week' | 'fri'
    const all = flows();
    const inRange = range === 'week' ? all : all.filter((f) => f.day === 'fri');
    const flagged = inRange.filter((f) => f.agree > 0);
    const sev = severityCounts(inRange);
    const highRisk = sev.critical + sev.high;
    const allThree = flagged.filter((f) => f.agree === 3).length;
    const open = flagged.filter((f) => (f.severity === 'critical' || f.severity === 'high') && (f.status === 'New' || f.status === 'Triaging')).length;
    const attackShare = cic.attack / cic.rows;

    mount(root, html`
      ${pageHead({
        title: 'Overview',
        sub: 'What MAVIS knows about CIC-IDS2017 so far, and a sample of what the detectors will show once they are trained.',
        actions: html`
          <div class="segmented" role="group" aria-label="Replay window for sample detections">
            <button data-range="week" aria-pressed="${range === 'week'}">Full week</button>
            <button data-range="fri" aria-pressed="${range === 'fri'}">Fri 7 Jul</button>
          </div>`,
      })}

      <div class="ov-top">
        <section class="panel posture" aria-label="Analysis posture">
          <div class="posture-main">
            <div class="metric metric-hero">
              <div class="metric-label">Flows profiled ${tagReal()}</div>
              <div class="metric-value num" data-count-to="${cic.rows}">${fmtInt(cic.rows)}</div>
              <div class="metric-foot">8 capture files · ${cic.columns - 1} features · ${fmtBytes(cic.bytes)} raw CSV</div>
            </div>
            <div class="top-classes">
              <div class="metric-label">Largest attack classes ${tagReal()}</div>
              <ol class="class-list">${Object.entries(cic.labels).filter(([k]) => k !== 'BENIGN').sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => html`
                <li><span class="class-name">${k}</span><span class="class-bar"><span style="width:${((v / 231073) * 100).toFixed(1)}%"></span></span><span class="num mono">${fmtInt(v)}</span></li>`)}</ol>
              <div class="metric-foot">${Object.keys(cic.labels).length - 6} smaller classes, down to 11 Heartbleed flows · <a href="#dataset">Dataset analysis</a></div>
            </div>
            <div class="share">
              <div class="share-bar" role="img" aria-label="Attack-labelled share ${fmtPct(attackShare)}">
                <span style="flex:${cic.benign}"></span><span class="attack" style="flex:${cic.attack}"></span>
              </div>
              <div class="share-legend">
                <span><i class="swatch" style="background:var(--benign)"></i>Benign <b class="num">${fmtInt(cic.benign)}</b></span>
                <span><i class="swatch" style="background:var(--accent)"></i>Attack-labelled <b class="num">${fmtInt(cic.attack)}</b> <span class="muted">${fmtPct(attackShare)}</span></span>
              </div>
            </div>
          </div>
          <div class="posture-side">
            <div class="metric">
              <div class="metric-label">Anomalies flagged ${tagSample()}</div>
              <div class="metric-value num" data-count-to="${flagged.length}">${fmtInt(flagged.length)}<small>of ${fmtInt(inRange.length)} flows</small></div>
              <div class="metric-foot">At least one detector above its cut-off</div>
            </div>
            <div class="metric metric-alert">
              <div class="metric-label">High-risk events ${tagSample()}</div>
              <div class="metric-value num" data-count-to="${highRisk}">${fmtInt(highRisk)}</div>
              <div class="metric-foot"><button class="linklike" data-go-threats>${open} awaiting triage ${icon('arrowRight')}</button></div>
            </div>
            <div class="metric">
              <div class="metric-label">All three agree ${tagSample()}</div>
              <div class="metric-value num">${flagged.length ? fmtPct(allThree / flagged.length, 0) : '0%'}</div>
              <div class="metric-foot">${fmtInt(allThree)} flows flagged by IF, LOF and AE</div>
            </div>
          </div>
        </section>

        ${panel({
          title: 'Pipeline status',
          meta: 'From the repository',
          cls: 'pipeline-panel',
          body: pipelineList(),
        })}
      </div>

      <div class="ov-grid">
        ${panel({
          title: 'Labelled flows by capture day',
          tag: tagReal(),
          cls: 'span-2',
          actions: html`<div class="segmented" role="group" aria-label="Chart scale">
            <button data-day-mode="count" aria-pressed="true">Count</button><button data-day-mode="share" aria-pressed="false">Share</button></div>`,
          body: html`<div class="chart-legend-row"><div class="legend">
              <span class="legend-item"><i class="swatch" style="background:var(--benign)"></i>Benign</span>
              <span class="legend-item"><i class="swatch" style="background:var(--accent)"></i>Attack-labelled</span></div>
              <span class="panel-meta">Dataset ground truth, not detections</span></div>
            <div class="chart" id="ch-days"></div>`,
        })}

        ${panel({
          title: 'Severity mix',
          tag: tagSample(),
          meta: `${fmtInt(flagged.length)} flagged flows`,
          body: html`${raw(meter(severityRows(inRange).map((r) => ({ ...r })), 'Severity mix of flagged flows'))}
            <div class="chart" id="ch-sev" style="margin-top:14px"></div>
            <p class="panel-meta" style="margin-top:10px">Severity here comes from a sample triage rule (how many detectors agree and how far past the cut-off). MAVIS has no risk engine yet.</p>`,
        })}

        ${panel({
          title: 'Network activity',
          tag: tagSample(),
          cls: 'span-2',
          meta: range === 'week' ? 'Hourly, 08:00–18:00 UTC each day' : '20-minute slots, Fri 7 Jul',
          body: html`<div class="chart-legend-row"><div class="legend">
              <span class="legend-item"><i class="swatch" style="background:var(--ink-3)"></i>Flows replayed</span>
              <span class="legend-item"><i class="swatch" style="background:var(--accent)"></i>Flagged by any detector</span></div></div>
            <div class="chart" id="ch-activity"></div>`,
        })}

        ${panel({
          title: 'Detector agreement',
          tag: tagSample(),
          meta: 'Which combinations flagged each flow',
          body: html`<div class="chart" id="ch-agree"></div>
            <div class="legend" style="margin-top:8px">${MODELS.map((m) => html`<span class="legend-item"><span class="mdot" data-m="${m.id}"></span>${m.name}</span>`)}</div>`,
        })}

        ${panel({
          title: 'Recent suspicious events',
          tag: tagSample(),
          cls: 'span-2',
          bodyCls: 'flush',
          actions: html`<button class="btn btn-ghost btn-sm" data-go-threats>View all ${icon('arrowRight')}</button>`,
          body: html`<div id="recent"></div>`,
        })}

        ${panel({
          title: 'Latest analysis activity',
          body: html`<ol class="feed">
            <li class="feed-item" data-kind="real"><span class="feed-dot"></span><div><div>Raw dataset profile generated</div><div class="feed-meta">${tagReal()} reports/raw_data_profile.json · no models trained</div></div></li>
            ${SAMPLE_ACTIVITY.map((a) => html`<li class="feed-item" data-kind="${a.kind}"><span class="feed-dot"></span><div><div>${a.text}</div><div class="feed-meta">${tagSample()} <span class="mono">${fmtTime(a.ts, { seconds: false })}</span></div></div></li>`)}
          </ol>`,
        })}
      </div>`);

    // Charts
    let dayMode = 'count';
    const drawDays = () => bindChart($('#ch-days', root), (w) => stackedColumns(w, 230, {
      data: cicByDay().map((d) => ({ ...d, full: `${d.label} 2017` })),
      series: [{ key: 'benign', name: 'Benign', color: 'var(--benign)' }, { key: 'attack', name: 'Attack-labelled', color: 'var(--accent)' }],
      label: 'Benign and attack-labelled flows per capture day', mode: dayMode,
    }));
    drawDays();
    bindChart($('#ch-sev', root), (w) => hBars(w, 0, { rows: severityRows(inRange), label: 'Flagged flows by severity', labelWidth: 78, showShare: true }));
    const act = activityBuckets(inRange, range === 'week' ? null : 'fri');
    bindChart($('#ch-activity', root), (w) => timeSeries(w, 220, {
      buckets: act.buckets, xLabels: act.xLabels, label: 'Sample flows over time with flagged flows',
      area: { key: 'total', name: 'Flows replayed', color: 'var(--surface-3)', stroke: 'var(--ink-3)' },
      line: { key: 'flagged', name: 'Flagged', color: 'var(--accent)' },
    }));
    bindChart($('#ch-agree', root), (w) => agreementMatrix(w, 0, { combos: agreementCombos(flagged), models: MODELS, label: 'Detector agreement combinations' }));

    // Recent table
    const recent = flagged.filter((f) => f.severity !== 'low').sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, 8);
    createTable($('#recent', root), {
      rows: recent, pageSize: 8, caption: 'Recent suspicious events (sample)',
      rowAttrs: (f) => ({ 'data-sev': f.severity }),
      onRowClick: (f) => openFlowDrawer(f.id),
      columns: [
        { key: 'severity', label: 'Severity', className: 'sev-cell', render: (f) => sevBadge(f.severity, { pulse: f.status === 'New' }), sort: (f) => ['none', 'low', 'medium', 'high', 'critical'].indexOf(f.severity) },
        { key: 'ts', label: 'Time (UTC)', render: (f) => html`<span class="mono muted">${fmtTime(f.ts, { seconds: false })}</span>` },
        { key: 'src', label: 'Source → destination', sortable: false, render: (f) => html`${ipText(f.src.ip)} <span class="muted">→</span> ${ipText(f.dst.ip, f.dst.port)}` },
        { key: 'agree', label: 'Detectors', render: (f) => modelStrip(f.flags) },
        { key: 'status', label: 'Status', render: (f) => statusBadge(f.status) },
      ],
      card: (f) => html`<span class="event-card-row">${sevBadge(f.severity)}<span class="mono muted" style="font-size:12px">${fmtTime(f.ts, { seconds: false })}</span></span>
        <span class="event-card-row route">${ipText(f.src.ip)}<span class="muted">→</span>${ipText(f.dst.ip, f.dst.port)}</span>
        <span class="event-card-row">${modelStrip(f.flags)}${statusBadge(f.status)}</span>`,
      emptyTitle: 'No suspicious events in this window', emptyText: 'Switch the replay window to see more sample events.',
    });

    on(root, 'click', '[data-range]', (_e, b) => { store.setPref('overviewRange', b.dataset.range); remount(this, root); });
    on(root, 'click', '[data-day-mode]', (_e, b) => {
      dayMode = b.dataset.dayMode;
      root.querySelectorAll('[data-day-mode]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      drawDays();
    });
    on(root, 'click', '[data-go-threats]', () => go('threats'));
  },
};

