// Chart system. Every chart is plain SVG drawn at the container's real width (so text never
// stretches), redrawn on resize, with one shared hover tooltip (see overlays.installTooltips).
// Marks: thin bars with 2px gaps, 2px lines, recessive grid, text in ink tokens only.
import { esc } from '../core/dom.js';
import { fmtCompact, fmtInt } from '../core/format.js';
import { tip } from './overlays.js';
import { store } from '../core/store.js';

const observers = new WeakMap();

// Bind a draw(width) => svgString function to a container and keep it sized.
export function bindChart(el, draw, { height } = {}) {
  if (!el) return;
  const paint = () => {
    const w = Math.max(240, Math.floor(el.clientWidth));
    el.innerHTML = draw(w, height);
  };
  paint();
  observers.get(el)?.disconnect();
  let last = el.clientWidth;
  const ro = new ResizeObserver(() => {
    if (Math.abs(el.clientWidth - last) < 2) return;
    last = el.clientWidth;
    paint();
  });
  ro.observe(el);
  observers.set(el, ro);
}

const niceStep = (max, ticks = 4) => {
  const raw = max / ticks;
  const mag = Math.pow(10, Math.floor(Math.log10(raw || 1)));
  const norm = raw / mag;
  return (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10) * mag;
};
const niceMax = (max, ticks = 4) => Math.ceil(max / niceStep(max, ticks)) * niceStep(max, ticks) || 1;

const gridOn = () => store.prefs.chartGrid !== false;

const svgOpen = (w, h, label) =>
  `<svg class="chart-svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="${esc(label)}">`;

function yAxis(x0, x1, y, max, h, fmt = fmtCompact, ticks = 4) {
  const step = niceStep(max, ticks);
  let s = '';
  for (let v = 0; v <= max + 1e-9; v += step) {
    const yy = y(v);
    if (gridOn() || v === 0) s += `<line x1="${x0}" x2="${x1}" y1="${yy}" y2="${yy}" class="${v === 0 ? 'axis-base' : 'grid'}"/>`;
    s += `<text x="${x0 - 8}" y="${yy + 4}" class="tick" text-anchor="end">${fmt(v)}</text>`;
  }
  return s;
}

/* ---------- Stacked columns (e.g. labelled flows per capture day) ---------- */
export function stackedColumns(w, h = 220, { data, series, label, mode = 'count', fmt = fmtCompact }) {
  const m = { t: 12, r: 8, b: 28, l: mode === 'share' ? 44 : 52 };
  const iw = w - m.l - m.r, ih = h - m.t - m.b;
  const totals = data.map((d) => series.reduce((a, s) => a + d[s.key], 0));
  const max = mode === 'share' ? 1 : niceMax(Math.max(...totals));
  const y = (v) => m.t + ih - (v / max) * ih;
  const band = iw / data.length;
  const bw = Math.min(56, band * 0.56);
  let s = svgOpen(w, h, label);
  s += yAxis(m.l, w - m.r, y, max, ih, mode === 'share' ? (v) => `${Math.round(v * 100)}%` : fmt);
  data.forEach((d, i) => {
    const x = m.l + band * i + (band - bw) / 2;
    let acc = 0;
    const total = totals[i];
    series.forEach((ser, si) => {
      const v = mode === 'share' ? d[ser.key] / total : d[ser.key];
      if (v <= 0) return;
      const y0 = y(acc), y1 = y(acc + v);
      const gap = si > 0 ? 2 : 0;
      const hgt = Math.max(1, y0 - y1 - gap);
      s += `<rect class="mark grow" x="${x}" y="${y1}" width="${bw}" height="${hgt}" rx="${si === series.length - 1 ? 3 : 0}" fill="${ser.color}" style="animation-delay:${i * 40}ms"/>`;
      acc += v;
    });
    s += `<text x="${x + bw / 2}" y="${h - 8}" class="tick" text-anchor="middle">${esc(d.label)}</text>`;
    const rows = series.map((ser) => [ser.name, `${fmtInt(d[ser.key])} (${((d[ser.key] / total) * 100).toFixed(1)}%)`, ser.color]);
    s += `<rect class="hit" x="${m.l + band * i}" y="${m.t}" width="${band}" height="${ih}" tabindex="0" data-tip='${esc(tip(d.full || d.label, [...rows, ['Total', fmtInt(total)]]))}'/>`;
  });
  return s + '</svg>';
}

/* ---------- Time series: area for volume + line for flagged ---------- */
export function timeSeries(w, h = 220, { buckets, label, area, line, xLabels }) {
  const m = { t: 14, r: 10, b: 28, l: 40 };
  const iw = w - m.l - m.r, ih = h - m.t - m.b;
  const max = niceMax(Math.max(...buckets.map((b) => b[area.key])));
  const n = buckets.length;
  const x = (i) => m.l + (n === 1 ? iw / 2 : (i / (n - 1)) * iw);
  const y = (v) => m.t + ih - (v / max) * ih;
  let s = svgOpen(w, h, label);
  s += yAxis(m.l, w - m.r, y, max, ih, (v) => fmtInt(v));
  const pts = (key) => buckets.map((b, i) => `${x(i).toFixed(1)},${y(b[key]).toFixed(1)}`);
  const areaPath = `M${x(0)},${y(0)} L${pts(area.key).join(' L')} L${x(n - 1)},${y(0)} Z`;
  s += `<path d="${areaPath}" fill="${area.color}" opacity="0.55" class="fade"/>`;
  s += `<polyline points="${pts(area.key).join(' ')}" fill="none" stroke="${area.stroke || area.color}" stroke-width="1.5" class="fade"/>`;
  s += `<polyline points="${pts(line.key).join(' ')}" fill="none" stroke="${line.color}" stroke-width="2" stroke-linejoin="round" class="draw" pathLength="1"/>`;
  // Day separators + labels
  (xLabels || []).forEach(({ index, text }) => {
    const xx = x(index);
    if (index > 0) s += `<line x1="${xx}" x2="${xx}" y1="${m.t}" y2="${m.t + ih}" class="sep"/>`;
    s += `<text x="${xx + 4}" y="${h - 8}" class="tick">${esc(text)}</text>`;
  });
  // Peak marker on the flagged line
  let pk = 0; buckets.forEach((b, i) => { if (b[line.key] > buckets[pk][line.key]) pk = i; });
  s += `<circle cx="${x(pk)}" cy="${y(buckets[pk][line.key])}" r="4" fill="${line.color}" stroke="var(--surface-1)" stroke-width="2"/>`;
  // Hover columns with crosshair
  const bw = iw / Math.max(1, n - 1);
  buckets.forEach((b, i) => {
    const rows = [[area.name, fmtInt(b[area.key]), area.stroke || area.color], [line.name, fmtInt(b[line.key]), line.color]];
    s += `<g class="xhair"><rect class="hit" x="${x(i) - bw / 2}" y="${m.t}" width="${bw}" height="${ih}" data-tip='${esc(tip(b.title, rows, b.note))}'/><line x1="${x(i)}" x2="${x(i)}" y1="${m.t}" y2="${m.t + ih}"/></g>`;
  });
  return s + '</svg>';
}

/* ---------- Horizontal bars (severity, protocols, labels) ---------- */
export function hBars(w, _h, { rows, label, scale = 'linear', fmt = fmtInt, labelWidth = 120, showShare = false }) {
  const rowH = 26, gap = 6;
  const m = { t: 4, r: showShare ? 104 : 64, b: 4, l: Math.min(labelWidth, w * 0.42) };
  const h = m.t + m.b + rows.length * (rowH + gap) - gap;
  const iw = w - m.l - m.r;
  const total = rows.reduce((a, r) => a + r.value, 0);
  const max = Math.max(...rows.map((r) => r.value), 1);
  const sx = scale === 'log'
    ? (v) => (v <= 0 ? 0 : (Math.log10(v + 1) / Math.log10(max + 1)) * iw)
    : (v) => (v / max) * iw;
  let s = svgOpen(w, h, label);
  rows.forEach((r, i) => {
    const y = m.t + i * (rowH + gap);
    const bw = Math.max(r.value > 0 ? 2 : 0, sx(r.value));
    s += `<text x="${m.l - 10}" y="${y + rowH / 2 + 4}" class="row-label" text-anchor="end">${esc(r.label)}</text>`;
    s += `<rect x="${m.l}" y="${y + 6}" width="${iw}" height="${rowH - 12}" rx="2" class="track"/>`;
    s += `<rect class="mark growx" x="${m.l}" y="${y + 6}" width="${bw}" height="${rowH - 12}" rx="2" fill="${r.color || 'var(--ink-3)'}" style="animation-delay:${i * 35}ms"/>`;
    s += `<text x="${m.l + bw + 8}" y="${y + rowH / 2 + 4}" class="val">${fmt(r.value)}${showShare && total ? ` · ${((r.value / total) * 100).toFixed(r.value / total < 0.001 ? 3 : 1)}%` : ''}</text>`;
    const rowsTip = [['Count', fmtInt(r.value)], ['Share', `${((r.value / total) * 100).toFixed(3)}%`]];
    if (r.extra) rowsTip.push(...r.extra);
    s += `<rect class="hit" x="0" y="${y}" width="${w}" height="${rowH}" tabindex="0" data-tip='${esc(tip(r.label, rowsTip, r.note))}'/>`;
  });
  return s + '</svg>';
}

/* ---------- Score histogram, two overlaid groups, cut-off marked ---------- */
export function histogram(w, h = 170, { values, groups, range, bins = 28, cutoff, cutoffLabel, label, color, fmt = (v) => v.toFixed(2) }) {
  const m = { t: 16, r: 8, b: 26, l: 34 };
  const iw = w - m.l - m.r, ih = h - m.t - m.b;
  const [lo, hi] = range;
  const step = (hi - lo) / bins;
  const counts = groups.map((g) => {
    const c = new Array(bins).fill(0);
    values.filter((v) => v.group === g.key).forEach((v) => {
      const i = Math.min(bins - 1, Math.max(0, Math.floor((v.value - lo) / step)));
      c[i]++;
    });
    return c;
  });
  const max = niceMax(Math.max(...counts.flat(), 1), 3);
  const x = (v) => m.l + ((v - lo) / (hi - lo)) * iw;
  const y = (v) => m.t + ih - (v / max) * ih;
  const bw = iw / bins;
  let s = svgOpen(w, h, label);
  s += yAxis(m.l, w - m.r, y, max, ih, (v) => fmtInt(v), 3);
  groups.forEach((g, gi) => {
    counts[gi].forEach((c, i) => {
      if (!c) return;
      const xx = m.l + i * bw + 1;
      const fill = g.key === 'attack' ? color : 'var(--benign)';
      s += `<rect class="mark grow" x="${xx}" y="${y(c)}" width="${Math.max(1, bw - 2)}" height="${y(0) - y(c)}" fill="${fill}" opacity="${g.key === 'attack' ? 0.9 : 1}" rx="1"/>`;
    });
  });
  for (let i = 0; i < bins; i++) {
    const a = lo + i * step;
    const rows = groups.map((g, gi) => [g.name, fmtInt(counts[gi][i]), g.key === 'attack' ? color : 'var(--benign)']);
    s += `<rect class="hit" x="${m.l + i * bw}" y="${m.t}" width="${bw}" height="${ih}" data-tip='${esc(tip(`${fmt(a)} to ${fmt(a + step)}`, rows))}'/>`;
  }
  if (cutoff != null) {
    const cx = x(cutoff);
    s += `<line x1="${cx}" x2="${cx}" y1="${m.t - 6}" y2="${m.t + ih}" class="cutoff"/>`;
    s += `<text x="${cx + 4}" y="${m.t - 4}" class="tick strong">${esc(cutoffLabel)}</text>`;
  }
  s += `<text x="${m.l}" y="${h - 6}" class="tick">${fmt(lo)}</text><text x="${w - m.r}" y="${h - 6}" class="tick" text-anchor="end">${fmt(hi)}</text>`;
  return s + '</svg>';
}

/* ---------- Agreement matrix (UpSet style): which detector combinations flagged a flow ---------- */
export function agreementMatrix(w, _h, { combos, models, label }) {
  const rowH = 22;
  const m = { t: 8, r: 8, l: 46 };
  const colW = Math.max(28, Math.min(56, (w - m.l - m.r) / combos.length));
  const barH = 96;
  const h = m.t + barH + 18 + models.length * rowH + 6;
  const max = Math.max(...combos.map((c) => c.count), 1);
  const ox = m.l + ((w - m.l - m.r) - colW * combos.length) / 2;
  let s = svgOpen(w, h, label);
  combos.forEach((c, i) => {
    const cx = ox + i * colW + colW / 2;
    const bh = (c.count / max) * barH;
    const fill = c.set.length === 3 ? 'var(--accent)' : 'var(--ink-3)';
    s += `<rect class="mark grow" x="${cx - colW * 0.3}" y="${m.t + barH - bh}" width="${colW * 0.6}" height="${Math.max(1, bh)}" rx="2" fill="${fill}" style="animation-delay:${i * 40}ms"/>`;
    s += `<text x="${cx}" y="${m.t + barH - bh - 5}" class="val" text-anchor="middle">${fmtInt(c.count)}</text>`;
    const dotsY = models.map((_, mi) => m.t + barH + 18 + mi * rowH + rowH / 2);
    const on = models.map((mm) => c.set.includes(mm.id));
    const ys = dotsY.filter((_, mi) => on[mi]);
    if (ys.length > 1) s += `<line x1="${cx}" x2="${cx}" y1="${Math.min(...ys)}" y2="${Math.max(...ys)}" stroke="var(--ink-2)" stroke-width="2"/>`;
    models.forEach((mm, mi) => {
      s += on[mi]
        ? `<circle cx="${cx}" cy="${dotsY[mi]}" r="5" fill="var(--m-${mm.id})" stroke="var(--surface-1)" stroke-width="2"/>`
        : `<circle cx="${cx}" cy="${dotsY[mi]}" r="3.5" fill="var(--surface-3)"/>`;
    });
    const name = c.set.length ? c.set.map((id) => models.find((x) => x.id === id).short).join(' + ') : 'None';
    s += `<rect class="hit" x="${cx - colW / 2}" y="${m.t}" width="${colW}" height="${h - m.t}" tabindex="0" data-tip='${esc(tip(name, [['Flows', fmtInt(c.count)]], c.set.length === 1 ? 'Only this detector flagged these flows' : c.set.length === 3 ? 'All detectors agree' : 'Partial agreement'))}'/>`;
  });
  models.forEach((mm, mi) => {
    s += `<text x="${m.l - 8}" y="${m.t + barH + 18 + mi * rowH + rowH / 2 + 4}" class="row-label" text-anchor="end">${mm.short}</text>`;
  });
  return s + '</svg>';
}

/* ---------- Sparkline ---------- */
export function sparkline(w, h = 36, { values, color = 'var(--accent)', label }) {
  const max = Math.max(...values, 1);
  const x = (i) => 2 + (i / (values.length - 1)) * (w - 4);
  const y = (v) => h - 3 - (v / max) * (h - 8);
  const pts = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  return `${svgOpen(w, h, label)}<path d="M2,${h - 3} L${pts.replace(/ /g, ' L')} L${w - 2},${h - 3} Z" fill="${color}" opacity=".14"/><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.6" class="draw" pathLength="1"/><circle cx="${x(values.length - 1)}" cy="${y(values[values.length - 1])}" r="2.6" fill="${color}"/></svg>`;
}

/* ---------- Single stacked meter (severity mix) ---------- */
export function meter(parts, label) {
  const total = parts.reduce((a, p) => a + p.value, 0) || 1;
  return `<div class="meter" role="img" aria-label="${esc(label)}">${parts.filter((p) => p.value > 0).map((p) =>
    `<span style="flex:${p.value} 1 0;background:${p.color}" data-tip='${esc(tip(p.label, [['Flows', fmtInt(p.value)], ['Share', `${((p.value / total) * 100).toFixed(1)}%`]]))}' tabindex="0"></span>`).join('')}</div>`;
}
