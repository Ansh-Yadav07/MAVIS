// Live attack graph (plain SVG, no physics library). Protected/internal hosts sit in a centre
// cluster, external hosts on an outer ring (at most CAP, the rest folded into "+N more").
// Edges are the flows seen in the last 30 s (width grows with their count), coloured by the worst
// severity on them; blocked hosts are greyed with a cross. Particles move along active edges
// with requestAnimationFrame (paused when the tab is hidden, off under reduced motion).
import { esc, prefersReducedMotion } from '../core/dom.js';
import { fmtInt } from '../core/format.js';
import { liveFlows, blockedSet, isProtected } from '../data/index.js';
import { SEV_COLOR, sevRank } from './security.js';

const WINDOW_MS = 30000;
const CAP = 120;
const MORE = '__more';

function compute(s) {
  const now = Date.now();
  const flows = liveFlows();
  const nodes = new Map();
  const pairs = new Map();
  const targets = new Set((s.episodes || []).filter((e) => e.state === 'active').map((e) => e.target));
  const node = (ip) => {
    let n = nodes.get(ip);
    if (!n) { n = { ip, flows: 0, alerts: 0, sev: 0, hit: 0 }; nodes.set(ip, n); }
    return n;
  };
  for (let i = flows.length - 1; i >= 0; i--) {
    const f = flows[i];
    if (now - f._rx > WINDOW_MS) break;
    const a = f.src?.ip, b = f.dst?.ip;
    if (!a || !b) continue;
    const r = f.verdict !== 'normal' ? sevRank(f.severity) : 0;
    const na = node(a), nb = node(b);
    na.flows++; nb.flows++;
    if (r) { na.alerts++; na.sev = Math.max(na.sev, r); nb.hit = Math.max(nb.hit, r); }
    const key = a < b ? `${a}|${b}` : `${b}|${a}`;
    const p = pairs.get(key) || { a: a < b ? a : b, b: a < b ? b : a, ab: 0, ba: 0, sev: 0 };
    if (a === p.a) p.ab++; else p.ba++;
    p.sev = Math.max(p.sev, r);
    pairs.set(key, p);
  }
  const blocked = blockedSet(s);
  nodes.forEach((n) => { n.prot = isProtected(n.ip) || targets.has(n.ip); n.blocked = blocked.has(n.ip); });
  const prot = [...nodes.values()].filter((n) => n.prot).sort((x, y) => (x.ip < y.ip ? -1 : 1));
  let ext = [...nodes.values()].filter((n) => !n.prot);
  let more = null;
  if (ext.length > CAP) {
    ext.sort((x, y) => (y.sev - x.sev) || (y.flows - x.flows));
    const rest = ext.slice(CAP);
    ext = ext.slice(0, CAP);
    more = { ip: MORE, flows: rest.reduce((t, n) => t + n.flows, 0), alerts: rest.reduce((t, n) => t + n.alerts, 0), sev: Math.max(...rest.map((n) => n.sev)), hit: 0, blocked: false, count: rest.length, prot: false };
    const gone = new Set(rest.map((n) => n.ip));
    const merged = new Map();
    pairs.forEach((p) => {
      const a = gone.has(p.a) ? MORE : p.a, b = gone.has(p.b) ? MORE : p.b;
      if (a === MORE && b === MORE) return;
      const aa = a < b ? a : b, bb = a < b ? b : a;
      const k = `${aa}|${bb}`;
      const m = merged.get(k) || { a: aa, b: bb, ab: 0, ba: 0, sev: 0 };
      const swap = aa !== a;
      m.ab += swap ? p.ba : p.ab; m.ba += swap ? p.ab : p.ba; m.sev = Math.max(m.sev, p.sev);
      merged.set(k, m);
    });
    merged.forEach((v, k) => pairs.set(k, v));
    [...pairs.keys()].forEach((k) => { const p = pairs.get(k); if (gone.has(p.a) || gone.has(p.b)) pairs.delete(k); });
  }
  ext.sort((x, y) => (x.ip < y.ip ? -1 : 1));
  if (more) ext.push(more);
  return { prot, ext, edges: [...pairs.values()] };
}

export function createGraph(host, { compact = false, onSelect } = {}) {
  const W = compact ? 640 : 960, H = compact ? 300 : 560;
  host.innerHTML = `<svg class="ag-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Attack graph: hosts seen in the last 30 seconds and the traffic between them"><g class="ag-edges"></g><g class="ag-particles"></g><g class="ag-nodes"></g></svg><p class="ag-empty" hidden>Waiting for traffic. Hosts appear here as soon as the sensor or simulator sends flows.</p>`;
  const svg = host.querySelector('svg');
  const gEdges = svg.querySelector('.ag-edges'), gPart = svg.querySelector('.ag-particles'), gNodes = svg.querySelector('.ag-nodes');
  const empty = host.querySelector('.ag-empty');
  const pos = new Map();       // ip -> {x, y, tx, ty}
  let edgeEls = [], nodeEls = [], selected = null, raf = 0, destroyed = false;
  const reduced = () => prefersReducedMotion();

  function layout(g) {
    const cx = W / 2, cy = H / 2;
    const rc = g.prot.length > 1 ? Math.min(H * 0.2, 26 + g.prot.length * 12) : 0;
    g.prot.forEach((n, i) => { const t = (2 * Math.PI * i) / g.prot.length - Math.PI / 2; n.tx = cx + rc * Math.cos(t); n.ty = cy + rc * Math.sin(t); });
    const rx = W * 0.44, ry = H * 0.42;
    g.ext.forEach((n, i) => { const t = (2 * Math.PI * i) / g.ext.length - Math.PI / 2; n.tx = cx + rx * Math.cos(t); n.ty = cy + ry * Math.sin(t); });
    [...g.prot, ...g.ext].forEach((n) => {
      let p = pos.get(n.ip);
      if (!p) { p = { x: n.tx, y: n.ty }; pos.set(n.ip, p); }
      p.tx = n.tx; p.ty = n.ty;
    });
    const live = new Set([...g.prot, ...g.ext].map((n) => n.ip));
    pos.forEach((_v, k) => { if (!live.has(k)) pos.delete(k); });
  }

  function nodeSvg(n, labelAll) {
    const r = n.prot ? (compact ? 7 : 10) : n.ip === MORE ? 9 : 3.5 + Math.min(4, Math.log10(n.flows + 1) * 1.6);
    const sevCol = SEV_COLOR[['none', 'low', 'medium', 'high', 'critical'][n.sev]];
    let fill = n.prot ? 'var(--accent)' : n.sev ? sevCol : 'var(--surface-3)';
    let stroke = n.prot ? (n.hit >= 2 ? SEV_COLOR[['none', 'low', 'medium', 'high', 'critical'][n.hit]] : 'var(--surface-1)') : 'var(--ink-3)';
    if (n.blocked) { fill = 'var(--surface-3)'; stroke = 'var(--ink-3)'; }
    const label = n.ip === MORE ? `+${fmtInt(n.count)} more` : (n.prot || labelAll.has(n.ip)) && !compact ? n.ip : (n.prot && compact ? n.ip : '');
    const cross = n.blocked ? `<path d="M${-r * 0.7} ${-r * 0.7}L${r * 0.7} ${r * 0.7}M${r * 0.7} ${-r * 0.7}L${-r * 0.7} ${r * 0.7}" stroke="var(--ink-1)" stroke-width="1.6" fill="none"/>` : '';
    const sel = n.ip === selected ? `<circle r="${r + 5}" fill="none" stroke="var(--accent)" stroke-width="2"/>` : '';
    const title = n.ip === MORE ? `${fmtInt(n.count)} more external hosts, ${fmtInt(n.flows)} flows` : `${n.ip}: ${fmtInt(n.flows)} flows, ${fmtInt(n.alerts)} alerts${n.blocked ? ', blocked' : ''}`;
    return `<g class="ag-node${n.ip === MORE ? ' is-more' : ''}" data-ip="${esc(n.ip)}" ${n.ip === MORE ? '' : 'tabindex="0" role="button"'} aria-label="${esc(title)}"><title>${esc(title)}</title>${sel}<circle r="${r}" fill="${fill}" stroke="${stroke}" stroke-width="${n.prot && n.hit >= 2 ? 3 : 1.5}"/>${cross}${label ? `<text class="ag-label" y="${r + 13}" text-anchor="middle">${esc(label)}</text>` : ''}</g>`;
  }

  function build(g) {
    const maxN = Math.max(1, ...g.edges.map((e) => e.ab + e.ba));
    const blockedSet_ = new Set([...g.prot, ...g.ext].filter((n) => n.blocked).map((n) => n.ip));
    edgeEls = [];
    let eh = '', ph = '', pc = 0;
    g.edges.forEach((e, i) => {
      const n = e.ab + e.ba, w = (0.8 + 5 * Math.sqrt(n / maxN)).toFixed(2);
      const from = e.ab >= e.ba ? e.a : e.b, to = from === e.a ? e.b : e.a;
      const dead = blockedSet_.has(from);
      const col = dead ? 'var(--ink-3)' : e.sev ? SEV_COLOR[['none', 'low', 'medium', 'high', 'critical'][e.sev]] : 'var(--ink-3)';
      eh += `<line stroke="${col}" stroke-width="${w}" stroke-opacity="${dead ? 0.35 : e.sev ? 0.75 : 0.4}" ${dead ? 'stroke-dasharray="4 4"' : ''}/>`;
      const k = dead ? 0 : Math.min(4, Math.ceil(Math.sqrt(n) / 2));
      for (let j = 0; j < k; j++) ph += `<circle r="${e.sev ? 2.6 : 2}" fill="${col}"/>`;
      edgeEls.push({ from, to, k, base: pc, i });
      pc += k;
    });
    gEdges.innerHTML = eh;
    gPart.innerHTML = reduced() ? '' : ph;
    const lines = gEdges.children, circles = gPart.children;
    edgeEls.forEach((e) => { e.line = lines[e.i]; e.circles = [...Array(e.k)].map((_, j) => circles[e.base + j]).filter(Boolean); });
    const top = [...g.ext].filter((n) => n.ip !== MORE).sort((a, b) => (b.sev - a.sev) || (b.flows - a.flows));
    const labelAll = new Set(top.slice(0, g.ext.length <= 8 ? 8 : 4).map((n) => n.ip));   // keep the ring readable
    const keep = document.activeElement?.closest?.('.ag-node')?.dataset.ip;
    gNodes.innerHTML = [...g.prot, ...g.ext].map((n) => nodeSvg(n, labelAll)).join('');
    nodeEls = [...gNodes.children].map((el) => ({ el, ip: el.dataset.ip }));
    if (keep) gNodes.querySelector(`[data-ip="${CSS.escape(keep)}"]`)?.focus({ preventScroll: true });
    empty.hidden = nodeEls.length > 0;
    step(performance.now(), true);
  }

  function step(ts, snap) {
    const still = reduced() || snap;
    pos.forEach((p) => {
      if (still) { p.x = p.tx; p.y = p.ty; return; }
      p.x += (p.tx - p.x) * 0.18; p.y += (p.ty - p.y) * 0.18;
    });
    nodeEls.forEach((n) => { const p = pos.get(n.ip); if (p) n.el.setAttribute('transform', `translate(${p.x.toFixed(1)} ${p.y.toFixed(1)})`); });
    edgeEls.forEach((e, idx) => {
      const a = pos.get(e.from), b = pos.get(e.to);
      if (!a || !b) return;
      e.line.setAttribute('x1', a.x.toFixed(1)); e.line.setAttribute('y1', a.y.toFixed(1));
      e.line.setAttribute('x2', b.x.toFixed(1)); e.line.setAttribute('y2', b.y.toFixed(1));
      e.circles.forEach((c, j) => {
        const t = (ts / 1700 + j / e.k + idx * 0.137) % 1;
        c.setAttribute('cx', (a.x + (b.x - a.x) * t).toFixed(1)); c.setAttribute('cy', (a.y + (b.y - a.y) * t).toFixed(1));
      });
    });
  }

  function frame(ts) {
    raf = 0;
    if (destroyed || document.hidden || !host.isConnected) return;
    step(ts);
    raf = requestAnimationFrame(frame);
  }
  const ensure = () => { if (!raf && !destroyed && !reduced() && !document.hidden) raf = requestAnimationFrame(frame); };
  const onVis = () => { if (document.hidden) { cancelAnimationFrame(raf); raf = 0; } else ensure(); };
  document.addEventListener('visibilitychange', onVis);

  const pick = (el) => {
    const ip = el.dataset.ip;
    if (!ip || ip === MORE) return;
    onSelect?.(ip);
  };
  host.addEventListener('click', (ev) => { const n = ev.target.closest('.ag-node'); if (n) pick(n); });
  host.addEventListener('keydown', (ev) => { if (ev.key !== 'Enter' && ev.key !== ' ') return; const n = ev.target.closest('.ag-node'); if (n) { ev.preventDefault(); pick(n); } });

  let last = null;
  return {
    update(state) {
      if (destroyed) return;
      last = state;
      const g = compute(state);
      layout(g);
      build(g);
      ensure();
    },
    select(ip) { selected = ip; if (last) this.update(last); },
    destroy() { destroyed = true; cancelAnimationFrame(raf); document.removeEventListener('visibilitychange', onVis); },
  };
}
