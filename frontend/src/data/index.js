// Data access for views. Real data and sample data stay in separate modules;
// this layer only joins sample flows with the analyst's local edits.
import { SAMPLE_FLOWS, DAYS } from './sample/events.js';
import { datasetProfile } from './dataset-profile.js';
import { store } from '../core/store.js';

export { DAYS, datasetProfile };

export function flows() {
  return SAMPLE_FLOWS.map((f) => {
    const e = store.edit(f.id);
    return e.status || e.note ? { ...f, status: e.status || f.status, note: e.note || '' } : f;
  });
}

export const flowById = (id) => flows().find((f) => f.id === id) || null;
export const flagged = () => flows().filter((f) => f.agree > 0);

// Real totals for CIC-IDS2017 from the profile.
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

// Map each CIC file to its capture day for the per-day chart.
const DAY_OF = { Monday: 'mon', Tuesday: 'tue', Wednesday: 'wed', Thursday: 'thu', Friday: 'fri' };
export function cicByDay() {
  const out = DAYS.map((d) => ({ ...d, benign: 0, attack: 0, labels: {} }));
  for (const f of cicSummary().files) {
    const day = out.find((d) => d.id === DAY_OF[f.source.split('-')[0]]);
    for (const [k, v] of Object.entries(f.targetCounts)) {
      if (k === 'BENIGN') day.benign += v; else day.attack += v;
      day.labels[k] = (day.labels[k] || 0) + v;
    }
  }
  return out;
}
