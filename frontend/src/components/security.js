// Security vocabulary: severity, status, detector verdicts, addresses, scores, provenance.
import { html, raw } from '../core/dom.js';
import { fmtScore } from '../core/format.js';
import { sevGlyph, icon } from './icons.js';
import { MODELS } from '../data/model-registry.js';
import { engine, DAYS } from '../data/index.js';

export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'none'];
export const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'Normal' };

export const sevBadge = (sev, { pulse = false } = {}) =>
  html`<span class="sev ${pulse && sev === 'critical' ? 'sev-pulse' : ''}" data-sev="${sev}">${sevGlyph(sev)}${SEV_LABEL[sev]}</span>`;

export const statusBadge = (status) => html`<span class="status" data-status="${status}">${status}</span>`;

export const modelStrip = (flags) => html`<span class="mstrip" role="img" aria-label="${
  MODELS.map((m) => `${m.name} ${flags[m.id] ? 'flagged' : 'not flagged'}`).join(', ')
}">${MODELS.map((m) => html`<span class="mcell" data-m="${m.id}" data-on="${!!flags[m.id]}">${m.short}</span>`)}</span>`;

const isInternal = (ip) => /^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
// The public CIC-IDS2017 ML CSVs carry no addresses: show the port/service instead of a fake IP.
export const ipText = (ip, port, { scope = false } = {}) => ip == null
  ? html`<span class="ip ip-none" title="Not in the source CSV">${port != null ? html`port <span class="port">${port}</span>` : '—'}</span>`
  : html`<span class="ip">${ip}${port != null ? html`<span class="port">:${port}</span>` : ''}${scope ? html`<span class="ip-scope">${isInternal(ip) ? 'int' : 'ext'}</span>` : ''}</span>`;

export const protoTag = (p) => (p ? html`<span class="proto">${p}</span>` : '');

// Score bars use each detector's benign percentile (0..1), so the three share one scale;
// the cut-off is the engine's vote percentile (a detector "flags" above it).
export const SCORE_RANGE = { if: [0.5, 1], lof: [0.5, 1], ae: [0.5, 1] };
export const cutoffFor = () => engine().votePercentile;
export const nativeCutoff = (id) => engine().cutoffs[id];

// value: the flow's percentile for detector `id` (flow.pct[id])
export function scoreBar(id, value, { color = true } = {}) {
  const [lo, hi] = SCORE_RANGE[id];
  const pos = (v) => Math.max(0, Math.min(1, (v - lo) / (hi - lo))) * 100;
  const over = value > cutoffFor(id);
  const fill = color && over ? `var(--m-${id})` : 'var(--ink-3)';
  const text = `p${(value * 100).toFixed(value >= 0.999 ? 2 : 1)}`;
  return html`<span class="score" title="${over ? 'Above cut-off' : 'Below cut-off'}">
    <span class="score-track"><span class="score-fill" style="width:${pos(value).toFixed(1)}%;background:${fill}"></span><span class="score-cut" style="left:${pos(cutoffFor(id)).toFixed(1)}%"></span></span>
    <span class="score-val">${text}</span></span>`;
}

// Provenance tags. Used everywhere a number appears so its source is never ambiguous.
export const tagEngine = (text = 'Engine output') => html`<span class="tag tag-real" title="Produced by the trained MAVIS engine (scripts/export_frontend.py)">${text}</span>`;
export const tagEval = (text = 'Evaluated') => html`<span class="tag tag-code" title="Measured on held-out flows (reports/*.json)">${text}</span>`;
export const tagUpload = (text = 'Your upload') => html`<span class="tag tag-sample" title="Analysed live by the local engine">${text}</span>`;
/** @deprecated sample data is gone; kept so old imports do not break */
export const tagSample = tagEngine;
export const tagReal = (text = 'Measured') => html`<span class="tag tag-real" title="Measured from the dataset files in this repo">${text}</span>`;
export const tagPlanned = (text = 'Not built') => html`<span class="tag tag-planned">${text}</span>`;
export const tagCode = (text = 'From code') => html`<span class="tag tag-code" title="Transcribed from src/models">${text}</span>`;

export const sampleCallout = (text) => /* legacy name */ html`<div class="callout" data-tone="sample" role="note">${icon('flask')}<div>${text}</div></div>`;
export const infoCallout = (text, tone = '') => html`<div class="callout" data-tone="${tone}" role="note">${icon('info')}<div>${text}</div></div>`;

// Engine-output helpers shared by the alert queue, explorer and drawer.
export const MODE_LABEL = { known: 'Known', novel: 'Novel', 'known+novel': 'Known + novel' };
export const modeTag = (mode) => (mode ? html`<span class="mode-tag" data-mode="${mode}" title="${mode === 'known' ? 'Matches a known attack signature' : mode === 'novel' ? 'Anomalous but no known signature matched' : 'Recognised and also anomalous'}">${MODE_LABEL[mode]}</span>` : html`<span class="mode-tag">—</span>`);
export const riskCell = (risk) => html`<span class="risk-cell" title="Risk 0-100"><i><b style="width:${Math.max(0, Math.min(100, risk)).toFixed(0)}%"></b></i>${Math.round(risk)}</span>`;
export const OUTCOME_TITLE = { TP: 'True positive: attack, alerted', FP: 'False positive: benign, alerted', FN: 'False negative: attack, missed', TN: 'True negative: benign, not alerted' };
export const outcomeTag = (o) => (o ? html`<span class="tag-plain mono" title="${OUTCOME_TITLE[o]}">${o}</span>` : '');
export const dayLabel = (id) => (id === 'upload' ? 'Upload' : (DAYS.find((d) => d.id === id)?.label || id || ''));
export { raw };
