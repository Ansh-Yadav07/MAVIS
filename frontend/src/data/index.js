// Data access for every view. All flows, scores and verdicts are real MAVIS engine output:
// the committed snapshot data/mavis.json (scripts/export_frontend.py) plus any capture the
// analyst uploads while the local API (scripts/serve.py) is running.
// Analyst edits (status, notes) and the alert budget live in the store and are applied here.
import { datasetProfile } from './dataset-profile.js';
import { store } from '../core/store.js';

export { datasetProfile };

// Capture days, filled by loadData() (live binding: read it after the app has started).
export let DAYS = [];

export const STATUS_OPTIONS = ['New', 'Triaging', 'Escalated', 'Resolved', 'False positive'];
export const SEV_BANDS = [['critical', 85], ['high', 70], ['medium', 50], ['low', 0]];

let snap = null;          // data/mavis.json
const uploads = [];       // captures analysed through the local API this session
let cache = null;         // flows with edits + budget applied, rebuilt on change

// ---------------------------------------------------------------- loading
export async function loadData() {
  const res = await fetch('data/mavis.json', { cache: 'no-cache' });
  if (!res.ok) throw new Error(`data/mavis.json: HTTP ${res.status}. Run scripts/export_frontend.py.`);
  snap = await res.json();
  DAYS = snap.days;
  cache = null;
  store.subscribe((ev) => { if (ev.type === 'edit' || (ev.type === 'pref' && (ev.key === 'alertBudget' || ev.key === '*'))) cache = null; });
  return snap;
}

export const snapshot = () => snap;
export const engine = () => snap.engine;                       // thresholds, cutoffs, params, threats, baseline
export const evaluation = () => snap.evaluation;               // engine / anomaly / preprocess reports
export const DAYS_LIST = () => snap.days;                      // [{ id, label, date }]
export const captures = () => [...snap.captures, ...uploads];  // one entry per CSV file analysed
export const threatInfo = (family) => snap.engine.threats[family] || null;
export const FEATURE_KEYS = () => Object.keys(snap.engine.baseline);

// ---------------------------------------------------------------- alert budget
// The engine's thresholds for each false-positive budget were calibrated on held-out benign
// flows; re-applying them here changes verdicts without re-running any model.
export const budgets = () => Object.keys(snap.engine.budgets).map(Number).sort((a, b) => a - b);
export const currentBudget = () => {
  const b = store.prefs.alertBudget;
  return budgets().includes(b) ? b : snap.engine.alertBudgetFpr;
};

const severityFor = (risk) => SEV_BANDS.find(([, floor]) => risk >= floor)[0];

function applyBudget(f, thr) {
  const recognised = f.pKnown >= thr.known;
  const novel = f.anomalyPct >= thr.novel;
  const alert = recognised || novel;
  const family = alert ? (recognised ? f.predictedType : 'Novel') : null;
  const info = family ? threatInfo(family) : null;
  return {
    ...f,
    verdict: !alert ? 'normal' : recognised ? 'malicious' : 'suspicious',
    family,
    familyTitle: info?.title || null,
    mode: !alert ? null : recognised && novel ? 'known+novel' : recognised ? 'known' : 'novel',
    severity: alert ? severityFor(f.risk) : 'none',
    mitre: info?.mitre || [],
    actions: info?.actions || [],
    outcome: f.category == null ? undefined
      : f.category !== 'Benign' ? (alert ? 'TP' : 'FN') : (alert ? 'FP' : 'TN'),
  };
}

function build() {
  const thr = snap.engine.budgets[String(currentBudget())] || snap.engine.thresholds;
  const out = [];
  for (const c of captures()) {
    for (const f0 of c.flows) {
      const f = applyBudget(f0, thr);
      const e = store.edit(f.id);
      out.push(e.status || e.note
        ? { ...f, status: e.status || f.status, note: e.note || '' }
        : { ...f, status: f.verdict === 'normal' ? 'Closed' : f.status, note: '' });
    }
  }
  return out;
}

// ---------------------------------------------------------------- flows
// filter: { day, file, upload } (all optional)
export function flows(filter = {}) {
  cache ||= build();
  if (!filter.day && !filter.file && filter.upload == null) return cache;
  return cache.filter((f) => (!filter.day || f.day === filter.day) && (!filter.file || f.file === filter.file)
    && (filter.upload == null || !!f.upload === filter.upload));
}
export const flowById = (id) => flows().find((f) => f.id === id) || null;
export const flagged = (filter) => flows(filter).filter((f) => f.verdict !== 'normal');

// ---------------------------------------------------------------- full-capture aggregates
// These come from every flow in each file (not just the exported sample), at the engine's
// calibrated budget. Use them for totals and charts; use flows() for tables and drill-down.
export function summary(day) {
  const cs = captures().filter((c) => !day || c.day === day);
  const sum = (key) => cs.reduce((acc, c) => {
    for (const [k, v] of Object.entries(c.summary[key] || {})) acc[k] = (acc[k] || 0) + v;
    return acc;
  }, {});
  const flowsN = cs.reduce((a, c) => a + (c.summary.flows || 0), 0);
  const alerts = cs.reduce((a, c) => a + (c.summary.alerts || 0), 0);
  const gt = cs.filter((c) => c.ground_truth);
  return {
    files: cs.length,
    flows: flowsN,
    alerts,
    alertRate: flowsN ? alerts / flowsN : 0,
    verdicts: sum('verdicts'),          // { normal, malicious, suspicious }
    severity: sum('severity'),          // { critical, high, medium, low }
    families: sum('threat_families'),   // { DoS: n, PortScan: n, Novel: n, ... }
    modes: sum('detection_modes'),      // { known, novel, 'known+novel' }
    categories: sum('categories'),      // ground-truth families when labels exist
    // share of alerts where at least two detectors agree (classifier + any anomaly model, or 2+ models)
    agreement: agreementRate(day),
    groundTruth: gt.length ? mergeGroundTruth(gt.map((c) => c.ground_truth)) : null,
  };
}

function agreementRate(day) {
  const a = flagged(day ? { day } : {});
  return a.length ? a.filter((f) => f.votes >= 2).length / a.length : 0;
}

function mergeGroundTruth(list) {
  const per = {};
  for (const g of list) {
    for (const [cat, e] of Object.entries(g.per_category)) {
      const p = (per[cat] ||= { n: 0, alerted: 0, named: 0 });
      p.n += e.n; p.alerted += e.alerted * e.n; p.named += (e.named_correctly || 0) * e.alerted * e.n;
    }
  }
  for (const p of Object.values(per)) { p.named = p.alerted ? p.named / p.alerted : 0; p.alerted = p.n ? p.alerted / p.n : 0; }
  const benign = per.Benign || { n: 0, alerted: 0 };
  const attacks = Object.entries(per).filter(([k]) => k !== 'Benign');
  const attackN = attacks.reduce((a, [, p]) => a + p.n, 0);
  const recall = attackN ? attacks.reduce((a, [, p]) => a + p.alerted * p.n, 0) / attackN : 0;
  return { perCategory: per, recall, fpr: benign.alerted };
}

// Capture-sequence timeline (the public CSVs have no timestamps): bins in file order.
export function timeline(day) {
  return captures().filter((c) => !day || c.day === day).map((c) => ({ day: c.day, file: c.file, bins: c.timeline }));
}

// Incidents: alerts grouped per threat family (per source IP when the capture has IPs).
export function incidents(day) {
  return captures().filter((c) => !day || c.day === day).flatMap((c, ci) => c.incidents.map((inc, i) => {
    const id = `inc:${c.file}:${inc.threat_family}:${inc.src_ip ?? i}`;
    const e = store.edit(id);
    return { ...inc, id, day: c.day, file: c.file, status: e.status || 'New', note: e.note || '' };
  })).sort((a, b) => b.priority - a.priority);
}

export function insights(day) {
  return captures().filter((c) => !day || c.day === day)
    .flatMap((c) => c.insights.map((text, i) => ({ id: `ins:${c.file}:${i}`, day: c.day, file: c.file, text })));
}

export function drift(day) {
  return captures().filter((c) => !day || c.day === day).map((c) => ({ day: c.day, file: c.file, ...c.drift }));
}

// ---------------------------------------------------------------- live analysis (local API)
let apiState = null;
export async function apiAvailable() {
  if (apiState !== null) return apiState;
  try {
    const r = await fetch('api/health', { cache: 'no-store' });
    apiState = r.ok && (await r.json()).ok === true;
  } catch { apiState = false; }
  return apiState;
}

// Sends a CICFlowMeter CSV to the engine; the result joins captures() as an uploaded capture.
export async function analyzeCsv(file, { onProgress } = {}) {
  onProgress?.('uploading');
  const res = await fetch(`api/analyze?name=${encodeURIComponent(file.name)}`, {
    method: 'POST', headers: { 'Content-Type': 'text/csv' }, body: file,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `Analysis failed (HTTP ${res.status})`);
  const cap = { ...body, upload: true, day: 'upload', file: file.name };
  cap.flows = cap.flows.map((f) => ({ ...f, day: 'upload', file: file.name, upload: true }));
  uploads.push(cap);
  cache = null;
  return cap;
}

// ---------------------------------------------------------------- dataset profile (measured)
export function cicSummary() {
  const files = datasetProfile.files.filter((f) => f.dataset === 'CIC-IDS2017');
  const labels = {};
  let rows = 0, missing = 0, infinite = 0, dups = 0, bytes = 0, seenEarlier = 0;
  for (const f of files) {
    rows += f.rows; infinite += f.infiniteValues; dups += f.duplicateRows; bytes += f.fileSizeBytes; seenEarlier += f.rowsSeenEarlier;
    missing += Object.values(f.missingValues).reduce((a, b) => a + b, 0);
    for (const [k, v] of Object.entries(f.targetCounts)) labels[k] = (labels[k] || 0) + v;
  }
  const benign = labels.BENIGN || 0;
  return { files, rows, labels, benign, attack: rows - benign, missing, infinite, dups, bytes, seenEarlier, columns: files[0].columns };
}

// Measured per-day label counts from the dataset profile (all rows, before cleaning).
const DAY_OF = { Monday: 'mon', Tuesday: 'tue', Wednesday: 'wed', Thursday: 'thu', Friday: 'fri' };
export function cicByDay() {
  const out = DAYS.map((d) => ({ ...d, benign: 0, attack: 0, labels: {} }));
  for (const f of cicSummary().files) {
    const day = out.find((d) => d.id === DAY_OF[f.source.split('-')[0]]);
    if (!day) continue;
    for (const [k, v] of Object.entries(f.targetCounts)) {
      if (k === 'BENIGN') day.benign += v; else day.attack += v;
      day.labels[k] = (day.labels[k] || 0) + v;
    }
  }
  return out;
}
