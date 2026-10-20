// Network flow map: sources on the left, destination services on the right, a curved path per
// (source, service, kind) whose stroke width follows the flow count, and small dots travelling
// along each path. Flat 1px-class marks, theme tokens only. Motion stops when the pane is off
// screen, the tab is hidden, or reduced motion is on (the static map still reads in full).
import { prefersReducedMotion } from '../core/dom.js';
import { tip } from './overlays.js';
import { fmtInt } from '../core/format.js';

const NS = 'http://www.w3.org/2000/svg';
const SEV_VAR = { critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)' };

const SERVICE_PORTS = {
  web: [80, 443, 8080, 8443], dns: [53], mail: [25, 465, 587, 110, 143, 993, 995],
  db: [1433, 1521, 3306, 5432, 6379, 9200, 27017], admin: [22, 23, 3389, 5900, 5985, 5986],
  file: [21, 139, 445, 2049], directory: [88, 389, 636, 3268],
};
const PORT_CLASS = {};
for (const [k, ports] of Object.entries(SERVICE_PORTS)) ports.forEach((p) => { PORT_CLASS[p] = k; });
export const serviceClass = (port) => (port == null ? 'other' : PORT_CLASS[port] || 'other');

const el = (name, attrs = {}) => {
  const n = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  return n;
};
const colour = (kind) => (kind === 'normal' ? 'var(--ink-3)' : SEV_VAR[kind] || 'var(--accent)');

// model: { left: [{id,label}], right: [{id,label}], links: [{from,to,kind,n,family?}] }
export function mountFlowMap(host, { onLink } = {}) {
  let model = { left: [], right: [], links: [] };
  let svg = null, dots = [], pulses = [], raf = 0, running = false, visible = true, W = 0;
  const reduce = () => prefersReducedMotion();

  function layout() {
    W = Math.max(280, Math.floor(host.clientWidth));
    const narrow = W < 520;
    const rows = Math.max(model.left.length, model.right.length, 3);
    const rowH = narrow ? 30 : 34;
    const H = rows * rowH + 24;
    const labelW = narrow ? 82 : 132;
    const xL = labelW + 8, xR = W - labelW - 8;
    svg = el('svg', { class: 'fm-svg', viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: 'img',
      'aria-label': 'Network flow map: traffic from sources to destination services' });
    const yOf = (list, i) => (list.length === 1 ? H / 2 : 14 + ((H - 28) * i) / (list.length - 1));
    const pos = {};
    model.left.forEach((n, i) => { pos[`l:${n.id}`] = { x: xL, y: yOf(model.left, i) }; });
    model.right.forEach((n, i) => { pos[`r:${n.id}`] = { x: xR, y: yOf(model.right, i) }; });

    const maxN = Math.max(1, ...model.links.map((l) => l.n));
    const gLinks = el('g'), gHit = el('g'), gDots = el('g'), gNodes = el('g');
    dots = []; pulses = [];
    // draw normal links first so alerts sit on top
    const links = [...model.links].sort((a, b) => (a.kind === 'normal' ? -1 : 1) - (b.kind === 'normal' ? -1 : 1) || a.n - b.n);
    const slot = {};
    links.forEach((lk, idx) => {
      const a = pos[`l:${lk.from}`], b = pos[`r:${lk.to}`];
      if (!a || !b) return;
      const key = `${lk.from}>${lk.to}`;
      const off = ((slot[key] = (slot[key] ?? -1) + 1) - 0.5) * 3;   // keep parallel kinds from overlapping
      const mid = (a.x + b.x) / 2;
      const d = `M${a.x},${a.y + off} C${mid},${a.y + off} ${mid},${b.y + off} ${b.x},${b.y + off}`;
      const w = 1 + 3.5 * Math.sqrt(lk.n / maxN);
      const alert = lk.kind !== 'normal';
      const p = el('path', { d, fill: 'none', stroke: colour(lk.kind), 'stroke-width': w.toFixed(2),
        'stroke-opacity': alert ? 0.5 : 0.22, 'stroke-linecap': 'round', class: 'fm-link' });
      gLinks.appendChild(p);
      const nodeL = model.left.find((n) => n.id === lk.from), nodeR = model.right.find((n) => n.id === lk.to);
      const hit = el('path', { d, fill: 'none', stroke: 'transparent', 'stroke-width': Math.max(12, w + 8), class: 'fm-hit', tabindex: 0, role: 'button',
        'aria-label': `${nodeL?.label} to ${nodeR?.label}, ${fmtInt(lk.n)} ${alert ? `${lk.kind} alert` : 'normal'} flows`,
        'data-tip': tip(`${nodeL?.label} → ${nodeR?.label}`, [[alert ? `${lk.kind} alerts` : 'Normal flows', fmtInt(lk.n), colour(lk.kind)]], onLink ? 'Click to inspect' : '') });
      hit.addEventListener('click', () => onLink?.(lk));
      hit.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onLink?.(lk); } });
      hit.addEventListener('pointerenter', () => p.setAttribute('stroke-opacity', '0.9'));
      hit.addEventListener('pointerleave', () => p.setAttribute('stroke-opacity', alert ? 0.5 : 0.22));
      gHit.appendChild(hit);
      const len = p.getTotalLength();
      const k = Math.min(5, 1 + Math.floor(Math.log2(1 + lk.n)));
      for (let i = 0; i < k; i++) {
        const c = el('circle', { r: alert ? 2.4 : 2, fill: alert ? colour(lk.kind) : 'var(--accent)', 'pointer-events': 'none' });
        gDots.appendChild(c);
        dots.push({ c, p, len, t: (i / k + (idx * 0.137) % 1) % 1, v: (alert ? 0.11 : 0.07) * (0.8 + ((idx * 7 + i * 3) % 5) / 12) });
      }
      if (lk.kind === 'critical') {
        const ring = el('circle', { cx: b.x, cy: b.y + off, r: 4, fill: 'none', stroke: 'var(--signal)', 'stroke-width': 1, opacity: 0, 'pointer-events': 'none' });
        gDots.appendChild(ring);
        pulses.push({ ring, t: (idx * 0.31) % 1 });
      }
    });

    const label = (n, x, anchor, y, sub) => {
      const t = el('text', { x: anchor === 'end' ? x - 10 : x + 10, y: y + 4, 'text-anchor': anchor, class: 'fm-label' });
      const lab = n.label.length > (narrow ? 11 : 18) ? `${n.label.slice(0, narrow ? 10 : 17)}…` : n.label;
      t.textContent = lab;
      if (n.count != null) { const s = el('tspan', { class: 'fm-count', dx: 5 }); s.textContent = fmtInt(n.count); t.appendChild(s); }
      return t;
    };
    model.left.forEach((n) => { const { x, y } = pos[`l:${n.id}`]; gNodes.append(el('rect', { x: x - 3, y: y - 6, width: 3, height: 12, fill: n.alert ? 'var(--sev-critical)' : 'var(--ink-2)' }), label(n, x, 'end', y)); });
    model.right.forEach((n) => { const { x, y } = pos[`r:${n.id}`]; gNodes.append(el('rect', { x, y: y - 6, width: 3, height: 12, fill: 'var(--accent)' }), label(n, x + 3, 'start', y)); });
    svg.append(gLinks, gDots, gHit, gNodes);
    host.replaceChildren(svg);
    frame(performance.now(), true);
  }

  let last = 0;
  function frame(now, once) {
    const dt = Math.min(0.05, (now - last) / 1000 || 0);
    last = now;
    const still = reduce();
    for (const d of dots) {
      if (still) { d.c.setAttribute('opacity', 0); continue; }
      if (!once) d.t = (d.t + d.v * dt) % 1;
      const pt = d.p.getPointAtLength(d.t * d.len);
      d.c.setAttribute('cx', pt.x.toFixed(1)); d.c.setAttribute('cy', pt.y.toFixed(1));
      d.c.setAttribute('opacity', Math.min(1, Math.sin(d.t * Math.PI) * 2.2).toFixed(2));
    }
    for (const q of pulses) {
      if (still) { q.ring.setAttribute('opacity', 0); continue; }
      if (!once) q.t = (q.t + 0.22 * dt) % 1;
      q.ring.setAttribute('r', (3 + q.t * 9).toFixed(1));
      q.ring.setAttribute('opacity', (0.8 * (1 - q.t)).toFixed(2));
    }
    if (!once && running) raf = requestAnimationFrame((t) => frame(t, false));
  }
  function sync() {
    const should = visible && !document.hidden && !reduce() && !!svg;
    if (should && !running) { running = true; last = performance.now(); raf = requestAnimationFrame((t) => frame(t, false)); }
    if (!should && running) { running = false; cancelAnimationFrame(raf); }
  }

  const ro = new ResizeObserver(() => { if (Math.abs(host.clientWidth - W) > 2 && model.links.length) { layout(); sync(); } });
  ro.observe(host);
  const io = new IntersectionObserver((es) => { visible = es[es.length - 1].isIntersecting; sync(); });
  io.observe(host);
  const onVis = () => sync();
  document.addEventListener('visibilitychange', onVis);

  return {
    update(m) { model = m; if (host.clientWidth) { layout(); sync(); } },
    destroy() { running = false; cancelAnimationFrame(raf); ro.disconnect(); io.disconnect(); document.removeEventListener('visibilitychange', onVis); },
  };
}

// ---- model builders
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const topN = (counts, n) => Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, n).map(([k]) => k);

function build(list, leftOf, leftLabel, maxLeft) {
  const lc = {}, rc = {};
  for (const f of list) { const l = leftOf(f); lc[l] = (lc[l] || 0) + 1; }
  const left = topN(lc, maxLeft);
  const sel = list.filter((f) => left.includes(leftOf(f)));
  for (const f of sel) { const s = serviceClass(f.dst?.port); rc[s] = (rc[s] || 0) + 1; }
  const right = topN(rc, 7);
  const links = {};
  for (const f of sel) {
    const to = serviceClass(f.dst?.port);
    if (!right.includes(to)) continue;
    const kind = f.verdict === 'normal' || f.severity === 'none' ? 'normal' : f.severity;
    const k = `${leftOf(f)}|${to}|${kind}`;
    (links[k] ||= { from: leftOf(f), to, kind, n: 0, family: f.family || null, last: f.id }).n++;
    links[k].last = f.id;
  }
  const alertL = {};
  for (const f of sel) if (f.verdict !== 'normal') alertL[leftOf(f)] = true;
  return {
    left: left.map((id) => ({ id, label: leftLabel(id), count: lc[id], alert: !!alertL[id] })),
    right: right.map((id) => ({ id, label: id, count: rc[id] })),
    links: Object.values(links),
  };
}

// Snapshot: attack family (or Normal) -> destination service class.
// Live: source IP -> destination service class.
export const liveModel = (list) => build(list, (f) => f.src?.ip || 'unknown', (id) => id, 7);
export { SEV_RANK };
