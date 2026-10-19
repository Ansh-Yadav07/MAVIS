// Small shared pieces for views: page header, panel, repaint-on-change regions, live widgets.
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { fmtInt, fmtTime } from '../core/format.js';
import { toast } from '../components/overlays.js';
import { sevBadge, riskCell } from '../components/security.js';
import { liveLearn } from '../data/index.js';

export const pageHead = ({ title, sub, actions = '' }) => html`
  <header class="page-head">
    <div class="page-head-text"><h1 class="page-title">${title}</h1>${sub ? html`<p class="page-sub">${sub}</p>` : ''}</div>
    ${actions ? html`<div class="page-actions">${actions}</div>` : ''}
  </header>`;

export const panel = ({ title, meta = '', actions = '', body, cls = '', bodyCls = '', id = '' }) => html`
  <section class="panel ${cls}" ${id ? html`id="${id}"` : ''} aria-label="${title}">
    <div class="panel-head"><h2 class="panel-title">${title}</h2>${meta ? html`<span class="panel-meta">${meta}</span>` : ''}<span class="spacer"></span>${actions}</div>
    <div class="panel-body ${bodyCls}">${body}</div>
  </section>`;

// Repaint a region only when its signature changed, so polling does not reset scroll, focus or hover.
export function regions(root) {
  const sig = {};
  return (id, key, build) => {
    const e = $(`#${id}`, root);
    if (!e || sig[id] === key) return;
    sig[id] = key;
    mount(e, build());
  };
}

export const kpi = (label, value, foot, tone = '') => html`<div class="kpi" ${tone ? html`data-tone="${tone}"` : ''}><div class="metric-label">${label}</div><div class="kpi-value num">${value}</div><div class="metric-foot">${foot}</div></div>`;

export const flowsPerSec = (s) => {
  const tl = (s.stats?.timeline || []).slice(-10);
  return tl.length ? tl.reduce((a, p) => a + p.flows, 0) / tl.length : 0;
};

export const feedRow = (f) => html`<li><button class="lv-feed-row" data-open="${f.id}">
  <span>${sevBadge(f.severity)} <b>${f.familyTitle || f.family || 'Alert'}</b> ${riskCell(f.risk)}</span>
  <span class="when">${f.ts ? fmtTime(f.ts, { date: false }) : ''}</span>
  <span class="route">${f.src?.ip ?? '?'} → ${f.dst?.ip ?? '?'}:${f.dst?.port ?? '?'}${f.response ? ` · ${f.response.action}` : ''}</span></button></li>`;

export const insiderItem = (a) => html`<li class="ins-item">
  <div class="ins-head">${sevBadge(a.severity)}<b>${a.title}</b><span class="tag-plain">${a.kind}</span>${a.ts ? html`<span class="panel-meta mono">${fmtTime(a.ts, { date: false })}</span>` : ''}</div>
  <p>${a.detail}</p>
  ${a.mitre?.length ? html`<div class="chips-inline">${a.mitre.map((m) => html`<span class="tag-plain">${m.tactic} · ${m.technique}</span>`)}</div>` : ''}
  ${a.actions?.length ? html`<p class="panel-meta">${a.actions.join(' · ')}</p>` : ''}
  ${a.flowId ? html`<div><button class="btn btn-sm" data-open="${a.flowId}">Open flow</button></div>` : ''}</li>`;

// Flows vs alerts per second over the last 300 s, drawn as SVG at the container width.
export function rateChart(w, timeline) {
  const h = 190, m = { l: 36, r: 8, t: 8, b: 20 };
  // The server only sends seconds that had flows: rebuild a continuous 300 s window ending now.
  const bySec = new Map(timeline.map((p) => [Math.floor(Date.parse(p.t) / 1000), p]));
  const end = Math.floor(Date.now() / 1000);
  const pts = Array.from({ length: 300 }, (_, i) => {
    const sec = end - 299 + i, p = bySec.get(sec);
    return { t: new Date(sec * 1000).toISOString(), flows: p?.flows || 0, alerts: p?.alerts || 0 };
  });
  const max = Math.max(1, ...pts.map((p) => p.flows));
  const x = (i) => m.l + (i / (pts.length - 1)) * (w - m.l - m.r);
  const y = (v) => m.t + (1 - v / max) * (h - m.t - m.b);
  const line = (key) => pts.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join('');
  const area = `${line('flows')}L${x(pts.length - 1).toFixed(1)},${y(0)}L${x(0).toFixed(1)},${y(0)}Z`;
  const grid = [0, 0.5, 1].map((k) => `<line class="grid" x1="${m.l}" x2="${w - m.r}" y1="${y(max * k)}" y2="${y(max * k)}"/><text class="tick" x="${m.l - 6}" y="${y(max * k) + 4}" text-anchor="end">${Math.round(max * k)}</text>`).join('');
  return `<svg class="chart-svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="Flows and alerts per second, last 300 seconds">
    ${grid}<path d="${area}" fill="var(--benign)" opacity="0.45"/><path d="${line('flows')}" fill="none" stroke="var(--ink-3)" stroke-width="1"/>
    <path d="${line('alerts')}" fill="none" stroke="var(--sev-critical)" stroke-width="1.5"/>
    <line class="axis-base" x1="${m.l}" x2="${w - m.r}" y1="${y(0)}" y2="${y(0)}"/>
    <text class="tick" x="${m.l}" y="${h - 4}">-5 min</text><text class="tick" x="${w - m.r}" y="${h - 4}" text-anchor="end">now</text></svg>`;
}

// Learning control: collect normal traffic, then calibrate. Never starts on its own.
export function learningBody(s) {
  const L = s.learning || {};
  const pct = L.target ? Math.min(100, (L.flows / L.target) * 100) : 0;
  return html`<div class="lv-learn-row"><b>${L.active ? 'Learning normal traffic' : L.calibrated ? 'Calibrated on your network' : 'Not calibrated on your network'}</b>
      <span class="panel-meta">${L.active ? `${fmtInt(L.flows)} / ${fmtInt(L.target)} flows, applied automatically at the target` : L.error ? L.error : L.calibrated ? `applied ${L.calibratedAt ? new Date(L.calibratedAt).toLocaleString() : ''}` : 'Using the CIC-IDS2017 thresholds. Run only normal activity while learning.'}</span></div>
    ${L.active ? html`<div class="lv-bar" role="progressbar" aria-valuemin="0" aria-valuemax="${L.target}" aria-valuenow="${L.flows}" aria-label="Learning progress"><i style="width:${pct.toFixed(1)}%"></i></div>` : ''}
    <div class="lv-learn-row">${L.active ? html`<button class="btn btn-sm" data-learn="stop">Stop learning</button><button class="btn btn-sm btn-primary" data-learn="apply" ${L.flows ? '' : 'disabled'}>Apply now</button>`
      : html`<button class="btn btn-sm btn-primary" data-learn="start">${L.calibrated ? 'Learn again' : 'Start learning'}</button>${L.flows ? html`<button class="btn btn-sm" data-learn="apply">Apply ${fmtInt(L.flows)} flows</button>` : ''}`}</div>`;
}

export function bindLearning(root) {
  on(root, 'click', '[data-learn]', async (_e, b) => {
    try { await liveLearn(b.dataset.learn, store.prefs.learnTarget); if (b.dataset.learn === 'apply') toast('Thresholds recalibrated from learned traffic'); } catch (e) { toast(e.message, { tone: 'error' }); }
  });
}
