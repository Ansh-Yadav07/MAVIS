// Small shared pieces for views: page header, provenance-aware panel, selectors over exported engine flows.
import { html, esc, raw } from '../core/dom.js';
import { store } from '../core/store.js';
import { fmtInt, fmtCompact, fmtPct } from '../core/format.js';
import { DAYS } from '../data/index.js';
import { MODELS } from '../data/model-registry.js';
import { tip } from '../components/overlays.js';
import { SEV_ORDER, SEV_LABEL } from '../components/security.js';

export const pageHead = ({ title, sub, actions = '' }) => html`
  <header class="page-head">
    <div class="page-head-text"><h1 class="page-title">${title}</h1>${sub ? html`<p class="page-sub">${sub}</p>` : ''}</div>
    ${actions ? html`<div class="page-actions">${actions}</div>` : ''}
  </header>`;

export const panel = ({ title, meta = '', tag = '', actions = '', body, cls = '', bodyCls = '', foot = '', id = '' }) => html`
  <section class="panel ${cls}" ${id ? html`id="${id}"` : ''} aria-label="${title}">
    <div class="panel-head"><h2 class="panel-title">${title}</h2>${tag}${meta ? html`<span class="panel-meta">${meta}</span>` : ''}<span class="spacer"></span>${actions}</div>
    <div class="panel-body ${bodyCls}">${body}</div>
    ${foot ? html`<div class="panel-foot">${foot}</div>` : ''}
  </section>`;

export const SEV_COLOR = {
  critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)', none: 'var(--sev-none)',
};

export function severityCounts(list) {
  const c = Object.fromEntries(SEV_ORDER.map((s) => [s, 0]));
  list.forEach((f) => { c[f.severity]++; });
  return c;
}

export const severityRows = (list, { includeNone = false } = {}) => {
  const c = severityCounts(list);
  return SEV_ORDER.filter((s) => includeNone || s !== 'none').map((s) => ({ label: SEV_LABEL[s], value: c[s], color: SEV_COLOR[s] }));
};

// Buckets for the activity chart: hourly across the week, or 20-minute slots for one day.
export function activityBuckets(list, dayId = null) {
  const out = [];
  const days = dayId ? DAYS.filter((d) => d.id === dayId) : DAYS;
  const slot = dayId ? 1 / 3 : 1;
  const xLabels = [];
  days.forEach((d) => {
    xLabels.push({ index: out.length, text: dayId ? '08:00' : d.label });
    for (let h = 8; h < 18; h += slot) {
      const hh = Math.floor(h), mm = Math.round((h - hh) * 60);
      out.push({ day: d.id, h0: h, h1: h + slot, total: 0, flagged: 0,
        title: `${d.label} · ${String(hh).padStart(2, '0')}:${String(mm).padStart(2, '0')}–${String(Math.floor(h + slot)).padStart(2, '0')}:${String(Math.round(((h + slot) % 1) * 60)).padStart(2, '0')} UTC` });
    }
  });
  if (dayId) [10, 12, 14, 16].forEach((h) => xLabels.push({ index: (h - 8) * 3, text: `${h}:00` }));
  list.forEach((f) => {
    const t = new Date(f.ts);
    const hour = t.getUTCHours() + t.getUTCMinutes() / 60;
    const b = out.find((x) => x.day === f.day && hour >= x.h0 && hour < x.h1);
    if (!b) return;
    b.total++;
    if (f.agree > 0) b.flagged++;
  });
  return { buckets: out, xLabels };
}

export function agreementCombos(list) {
  const ids = MODELS.map((m) => m.id);
  const sets = ids.reduce((acc, id) => acc.concat(acc.map((s) => [...s, id])), [[]]).filter((s) => s.length)
    .sort((a, b) => b.length - a.length);
  return sets.map((set) => ({
    set,
    count: list.filter((f) => ids.every((m) => !!f.flags[m] === set.includes(m))).length,
  }));
}

// Re-render a view into a fresh element so delegated listeners never stack up.
export function remount(view, root, param) {
  const fresh = document.createElement('div');
  fresh.className = root.className;
  root.replaceWith(fresh);
  view.render(fresh, param);
  return fresh;
}

// ---------------------------------------------------------------- shared view helpers
// Selected capture day (set by the top bar); undefined means all days.
export const curDay = () => store.session.day || undefined;
export const dayName = (id) => (id === 'upload' ? 'Your upload' : DAYS.find((d) => d.id === id)?.label || id);
export const scopeText = (day) => (day ? dayName(day) : 'all five days');

// Re-run `fn` when a preference, the selected day or an analyst edit changes. Returns the unsubscribe.
export function watch(fn) {
  return store.subscribe((ev) => { if (ev.type !== 'notes') fn(ev); });
}

// Which parts of the engine flagged a flow: the anomaly detectors and the classifier.
export const detectedBy = (f) => {
  const names = MODELS.filter((m) => f.flags?.[m.id]).map((m) => m.short);
  if (f.mode && f.mode.includes('known')) names.push('CLF');
  return names;
};
export const detectedStrip = (f) => {
  const on = new Set(detectedBy(f));
  const cells = [...MODELS.map((m) => [m.id, m.short]), ['clf', 'CLF']];
  return html`<span class="mstrip" role="img" aria-label="${on.size ? `Detected by ${[...on].join(', ')}` : 'No detector above its cut-off'}">${
    cells.map(([id, short]) => html`<span class="mcell" data-m="${id}" data-on="${on.has(short)}">${short}</span>`)}</span>`;
};

export function download(name, type, text) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const csvCell = (v) => {
  const s = v == null ? '' : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

const svgOpen = (w, h, label, extra = '') =>
  `<svg class="chart-svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="${esc(label)}" ${extra}>`;

// Per-day bar sparkline for KPI tiles. values/labels are parallel arrays.
export function miniBars(values, labels, { fmt = fmtCompact, label }) {
  const W = 100, H = 30, n = values.length, max = Math.max(...values, 1);
  const bw = W / n;
  let s = `<svg class="mini" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" width="100%" height="${H}" role="img" aria-label="${esc(label)}">`;
  values.forEach((v, i) => {
    const h = Math.max(v > 0 ? 1.5 : 0, (v / max) * (H - 2));
    s += `<rect x="${(i * bw + 1).toFixed(2)}" y="${(H - h).toFixed(2)}" width="${(bw - 2).toFixed(2)}" height="${h.toFixed(2)}" class="mini-bar"/>`;
    s += `<rect class="hit" x="${(i * bw).toFixed(2)}" y="0" width="${bw.toFixed(2)}" height="${H}" tabindex="0" data-tip='${esc(tip(labels[i], [[label, fmt(v)]]))}'/>`;
  });
  return raw(`${s}<line x1="0" x2="${W}" y1="${H - 0.5}" y2="${H - 0.5}" class="axis-base"/></svg>`);
}

// Donut: rows [{label, value, color}], centre text in the hole.
export function donut(size, { rows, centre, sub, label }) {
  const r = size / 2 - 14, c = size / 2, circ = 2 * Math.PI * r;
  const total = rows.reduce((a, x) => a + x.value, 0) || 1;
  let acc = 0, s = svgOpen(size, size, label);
  s += `<circle cx="${c}" cy="${c}" r="${r}" fill="none" class="donut-track" stroke-width="16"/>`;
  rows.forEach((x) => {
    if (x.value <= 0) return;
    const len = Math.max(2, (x.value / total) * circ);
    s += `<circle class="mark donut-seg" cx="${c}" cy="${c}" r="${r}" fill="none" stroke="${x.color}" stroke-width="16" stroke-dasharray="${(len - 1).toFixed(2)} ${(circ - len + 1).toFixed(2)}" stroke-dashoffset="${(-acc).toFixed(2)}" transform="rotate(-90 ${c} ${c})" tabindex="0" data-tip='${esc(tip(x.label, [['Flows', fmtInt(x.value)], ['Share', fmtPct(x.value / total, x.value / total < 0.01 ? 2 : 1)]]))}'/>`;
    acc += len;
  });
  s += `<text x="${c}" y="${c - 1}" text-anchor="middle" class="donut-num">${esc(centre)}</text><text x="${c}" y="${c + 16}" text-anchor="middle" class="tick">${esc(sub)}</text>`;
  return `${s}</svg>`;
}

// Alerts vs normal flows per capture-sequence bin, across files in order. files = timeline().
const shortFile = (day, file) => {
  const d = dayName(day).split(' ')[0];
  const part = /DDos/i.test(file) ? 'DDoS' : /PortScan/i.test(file) ? 'Scan' : /Morning/i.test(file) ? 'am' : /Afternoon/i.test(file) ? 'pm' : '';
  return `${d} ${part}`.trim();
};
export function activityChart(w, h = 220, { files, label }) {
  const m = { t: 10, r: 8, b: 30, l: 46 };
  const iw = w - m.l - m.r, ih = h - m.t - m.b;
  const bins = files.flatMap((f, fi) => f.bins.map((b) => ({ ...b, fi, day: f.day, file: f.file })));
  if (!bins.length) return svgOpen(w, h, label) + '</svg>';
  const rawMax = Math.max(...bins.map((b) => b.flows), 1);
  const mag = 10 ** Math.floor(Math.log10(rawMax));
  const max = Math.ceil(rawMax / mag) * mag;
  const y = (v) => m.t + ih - (v / max) * ih;
  const bw = iw / bins.length;
  let s = svgOpen(w, h, label);
  for (let i = 0; i <= 4; i++) {
    const v = (max / 4) * i, yy = y(v);
    s += `<line x1="${m.l}" x2="${w - m.r}" y1="${yy}" y2="${yy}" class="${i === 0 ? 'axis-base' : 'grid'}"/><text x="${m.l - 8}" y="${yy + 4}" class="tick" text-anchor="end">${fmtCompact(v)}</text>`;
  }
  bins.forEach((b, i) => {
    const x = m.l + i * bw, normal = b.flows - b.alerts, g = bw > 3 ? 0.6 : 0;
    s += `<rect class="mark" x="${(x + g / 2).toFixed(2)}" y="${y(normal).toFixed(2)}" width="${Math.max(0.5, bw - g).toFixed(2)}" height="${(y(0) - y(normal)).toFixed(2)}" fill="var(--benign)"/>`;
    if (b.alerts) s += `<rect class="mark" x="${(x + g / 2).toFixed(2)}" y="${y(b.flows).toFixed(2)}" width="${Math.max(0.5, bw - g).toFixed(2)}" height="${Math.max(1, y(normal) - y(b.flows)).toFixed(2)}" fill="var(--accent)"/>`;
    const rows = [['Alerts', fmtInt(b.alerts), 'var(--accent)'], ['Normal', fmtInt(normal), 'var(--benign)']];
    if (b.attacks != null) rows.push(['Labelled attacks', fmtInt(b.attacks)]);
    s += `<rect class="hit" x="${x.toFixed(2)}" y="${m.t}" width="${bw.toFixed(2)}" height="${ih}" data-tip='${esc(tip(`${shortFile(b.day, b.file)} · flows ${fmtInt(b.start)}–${fmtInt(b.end)}`, rows))}'/>`;
  });
  let i0 = 0;
  files.forEach((f, fi) => {
    const x0 = m.l + i0 * bw, fw = f.bins.length * bw;
    if (fi > 0) s += `<line x1="${x0}" x2="${x0}" y1="${m.t}" y2="${m.t + ih}" class="sep"/>`;
    const text = shortFile(f.day, f.file);
    if (fw > text.length * 6.2 + 4) s += `<text x="${x0 + fw / 2}" y="${h - 10}" class="tick" text-anchor="middle">${esc(text)}</text>`;
    const a = f.bins.reduce((t, b) => t + b.alerts, 0), n = f.bins.reduce((t, b) => t + b.flows, 0);
    s += `<rect class="hit" x="${x0}" y="${m.t + ih}" width="${fw}" height="${m.b}" tabindex="0" data-tip='${esc(tip(f.file, [['Flows', fmtInt(n)], ['Alerts', `${fmtInt(a)} (${fmtPct(n ? a / n : 0)})`]]))}'/>`;
    i0 += f.bins.length;
  });
  return `${s}</svg>`;
}

// Horizontal bars on a fixed 0..max scale with a custom value label (e.g. ROC-AUC).
export function valueBars(w, _h, { rows, max = 1, fmt = (v) => v.toFixed(3), labelWidth = 120, label }) {
  const rowH = 28, m = { l: Math.min(labelWidth, w * 0.42), r: 56 };
  const iw = w - m.l - m.r, h = rows.length * rowH;
  let s = svgOpen(w, h, label);
  rows.forEach((r, i) => {
    const yy = i * rowH, bw = Math.max(1, (r.value / max) * iw);
    s += `<text x="${m.l - 10}" y="${yy + rowH / 2 + 4}" class="row-label" text-anchor="end">${esc(r.label)}</text>`;
    s += `<rect x="${m.l}" y="${yy + 8}" width="${iw}" height="${rowH - 16}" class="track"/>`;
    s += `<rect class="mark growx" x="${m.l}" y="${yy + 8}" width="${bw.toFixed(1)}" height="${rowH - 16}" fill="${r.color}" style="animation-delay:${i * 35}ms"/>`;
    s += `<text x="${w - m.r + 8}" y="${yy + rowH / 2 + 4}" class="val">${fmt(r.value)}</text>`;
    s += `<rect class="hit" x="0" y="${yy}" width="${w}" height="${rowH}" tabindex="0" data-tip='${esc(tip(r.label, [[r.metric || 'Value', fmt(r.value)], ...(r.extra || [])], r.note))}'/>`;
  });
  return `${s}</svg>`;
}

export const pctText = (v, d = 1) => (v == null ? 'n/a' : fmtPct(v, d));
export const ratioBar = (v, color = 'var(--accent)') =>
  html`<span class="rate"><span class="rate-bar"><span style="width:${Math.min(100, Math.max(0, (v || 0) * 100)).toFixed(1)}%;background:${color}"></span></span><span class="mono">${pctText(v, v > 0 && v < 0.001 ? 2 : 1)}</span></span>`;

// Sections shown when a view needs data that the snapshot lacks.
export const noData = (what) => html`<div class="empty"><div class="empty-title">${what} is not in the snapshot</div><p>Run <code>python scripts/export_frontend.py</code> to regenerate it.</p></div>`;
