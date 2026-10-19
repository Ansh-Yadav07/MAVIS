// Live-mode client for the local API (scripts/serve.py, see docs/LIVE_SPEC.md).
// Polls GET api/live while something is subscribed and the tab is visible. Every call degrades
// to an empty state when the API is absent (static site), so nothing here ever throws into a view.
const POLL_MS = 1500;
const CAP = 5000;

let state = {
  available: false, seq: 0, sensor: { connected: false }, learning: { active: false, flows: 0, target: 3000 },
  stats: { flows: 0, alerts: 0, bySeverity: {}, byFamily: {}, byVerdict: {}, timeline: [] },
  hosts: [], insider: [], blocks: [], pending: [], response: null, error: null, updated: 0,
};
let buffer = [];                 // live flows, oldest first
const byId = new Map();
const subs = new Set();
let timer = null;
let busy = false;

const notify = () => subs.forEach((fn) => { try { fn(state); } catch (e) { console.error(e); } });

export const liveState = () => state;
export const liveFlows = () => buffer;
export const liveFlowById = (id) => byId.get(id) || null;

function merge(flows) {
  for (const f of flows) {
    const flow = { ...f, day: 'live', status: f.status || (f.verdict === 'normal' ? 'Closed' : 'New'), note: '' };
    if (byId.has(flow.id)) { buffer[buffer.findIndex((x) => x.id === flow.id)] = flow; } else buffer.push(flow);
    byId.set(flow.id, flow);
  }
  if (buffer.length > CAP) {
    for (const f of buffer.splice(0, buffer.length - CAP)) byId.delete(f.id);
  }
}

async function call(path, opts) {
  const r = await fetch(path, { cache: 'no-store', ...opts });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
  return body;
}
const post = (path, data, method = 'POST') => call(path, { method, headers: { 'Content-Type': 'application/json' }, body: data == null ? undefined : JSON.stringify(data) });

export async function pollNow() {
  if (busy) return;
  busy = true;
  try {
    const d = await call(`api/live?since=${state.seq}`);
    if (typeof d.seq === 'number' && d.seq < state.seq) { buffer = []; byId.clear(); }   // server restarted
    if (d.epoch != null && state.epoch != null && d.epoch !== state.epoch) { buffer = []; byId.clear(); }   // live data was reset
    merge(d.flows || []);
    const blocks = d.blocks || [];
    state = {
      ...state, available: true, error: null, updated: Date.now(),
      seq: d.seq ?? state.seq, epoch: d.epoch ?? state.epoch, sensor: d.sensor || { connected: false }, learning: d.learning || state.learning,
      stats: d.stats || state.stats, hosts: d.hosts || [], insider: d.insider || [],
      blocks: blocks.filter((b) => b.status !== 'pending'), pending: blocks.filter((b) => b.status === 'pending'),
      response: d.response || state.response,
    };
  } catch (e) {
    state = { ...state, available: false, error: e.message, sensor: { connected: false } };
  } finally { busy = false; }
  notify();
}

function schedule() {
  clearTimeout(timer);
  timer = null;
  if (!subs.size || document.hidden) return;
  timer = setTimeout(async () => { await pollNow(); schedule(); }, state.available ? POLL_MS : 8000);   // back off when the API is absent
}
document.addEventListener('visibilitychange', () => { if (!document.hidden && subs.size) pollNow().then(schedule); else schedule(); });

export function subscribeLive(fn) {
  subs.add(fn);
  fn(state);
  if (subs.size === 1 || !timer) pollNow().then(schedule);
  return () => { subs.delete(fn); if (!subs.size) schedule(); };
}

// ---- actions (each refreshes state afterwards)
const refresh = async (res) => { await pollNow(); return res; };
export const liveLearn = (action, target) => post('api/live/learn', action === 'start' ? { action, target: target || 3000 } : { action }).then(refresh);
export const liveReset = () => post('api/live/reset', {}).then((r) => { buffer = []; byId.clear(); state = { ...state, seq: 0 }; return refresh(r); });

export const blocks = () => call('api/blocks').catch(() => ({ blocks: [], pending: [] }));
export const blockIp = (ip, reason, ttlMinutes, alertId) => post('api/blocks', { ip, reason, ...(ttlMinutes ? { ttlMinutes } : {}), ...(alertId ? { alertId } : {}) }).then(refresh);
export const unblockIp = (ip) => post(`api/blocks/${encodeURIComponent(ip)}`, null, 'DELETE').then(refresh);
export const approveBlock = (ip) => post(`api/blocks/${encodeURIComponent(ip)}/approve`, {}).then(refresh);
export const rejectBlock = (ip) => post(`api/blocks/${encodeURIComponent(ip)}/reject`, {}).then(refresh);
export const responseConfig = () => call('api/response/config');
export const updateResponseConfig = (patch) => post('api/response/config', patch);
export const responseAudit = () => call('api/response/audit').catch(() => ({ audit: [] }));
