// Data access for every view. Everything is live: flows, hosts, episodes and status come from the
// local API (scripts/serve.py) through live.js. Engine facts (thresholds, evaluation) come from
// GET api/engine, falling back to data/engine.json on a static site.
import { liveFlows, liveFlowById } from './live.js';

export * from './live.js';

let ENGINE = null;
let EVAL = null;
let apiState = null;

async function getJson(url) {
  try {
    const r = await fetch(url, { cache: 'no-cache' });
    return r.ok ? await r.json() : null;
  } catch { return null; }
}

// Resolves once at start: is the local API reachable, and what do we know about the engine.
export async function loadData() {
  const health = await getJson('api/health');
  apiState = !!(health && health.ok === true);
  const d = (apiState && await getJson('api/engine')) || await getJson('data/engine.json');
  if (d) {
    ENGINE = d.engine && !d.thresholds ? d.engine : d;
    EVAL = d.evaluation || ENGINE.evaluation || null;
  }
  return { api: apiState, engine: !!ENGINE };
}

export const apiKnown = () => apiState === true;
export const apiAvailable = async () => apiState ?? (await loadData()).api;
export const engine = () => ENGINE;                 // thresholds, cutoffs, params, classes (may be null)
export const evaluation = () => EVAL;               // { engine, anomaly, ... } (may be null)

export const SEV_BANDS = [['critical', 85], ['high', 70], ['medium', 50], ['low', 0]];

export const flows = () => liveFlows();
export const flowById = (id) => liveFlowById(id);
export const alertFlows = () => liveFlows().filter((f) => f.verdict !== 'normal');

// IPs with an active block (from the block list and the host table).
export function blockedSet(s) {
  const set = new Set((s.blocks || []).map((b) => b.ip));
  (s.hosts || []).forEach((h) => { if (h.blocked) set.add(h.ip); });
  return set;
}

// Documentation and simulator ranges count as external even though 10.66/16 is private.
export const isProtected = (ip) => /^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip) && !ip.startsWith('10.66.');
