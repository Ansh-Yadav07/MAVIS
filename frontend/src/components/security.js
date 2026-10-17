// Security vocabulary: severity, status, detector verdicts, addresses, scores, provenance.
import { html, raw } from '../core/dom.js';
import { fmtScore } from '../core/format.js';
import { sevGlyph, icon } from './icons.js';
import { MODELS } from '../data/model-registry.js';
import { SAMPLE_AE_THRESHOLD } from '../data/sample/events.js';

export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'none'];
export const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'Normal' };

export const sevBadge = (sev, { pulse = false } = {}) =>
  html`<span class="sev ${pulse && sev === 'critical' ? 'sev-pulse' : ''}" data-sev="${sev}">${sevGlyph(sev)}${SEV_LABEL[sev]}</span>`;

export const statusBadge = (status) => html`<span class="status" data-status="${status}">${status}</span>`;

export const modelStrip = (flags) => html`<span class="mstrip" role="img" aria-label="${
  MODELS.map((m) => `${m.name} ${flags[m.id] ? 'flagged' : 'not flagged'}`).join(', ')
}">${MODELS.map((m) => html`<span class="mcell" data-m="${m.id}" data-on="${!!flags[m.id]}">${m.short}</span>`)}</span>`;

const isInternal = (ip) => ip.startsWith('192.168.') || ip.startsWith('10.');
export const ipText = (ip, port, { scope = false } = {}) =>
  html`<span class="ip">${ip}${port != null ? html`<span class="port">:${port}</span>` : ''}${scope ? html`<span class="ip-scope">${isInternal(ip) ? 'int' : 'ext'}</span>` : ''}</span>`;

export const protoTag = (p) => html`<span class="proto">${p}</span>`;

// Display range per detector for the score bar. Native units, cut-off marked.
export const SCORE_RANGE = { if: [-0.2, 0.25], lof: [-1.4, 1.6], ae: [0, 1.45] };
export const cutoffFor = (id) => (id === 'ae' ? SAMPLE_AE_THRESHOLD : 0);

export function scoreBar(id, value, { color = true } = {}) {
  const [lo, hi] = SCORE_RANGE[id];
  const pos = (v) => Math.max(0, Math.min(1, (v - lo) / (hi - lo))) * 100;
  const over = value > cutoffFor(id);
  const fill = color && over ? `var(--m-${id})` : 'var(--ink-3)';
  const text = id === 'ae' ? value.toFixed(3) : fmtScore(value);
  return html`<span class="score" title="${over ? 'Above cut-off' : 'Below cut-off'}">
    <span class="score-track"><span class="score-fill" style="width:${pos(value).toFixed(1)}%;background:${fill}"></span><span class="score-cut" style="left:${pos(cutoffFor(id)).toFixed(1)}%"></span></span>
    <span class="score-val">${text}</span></span>`;
}

// Provenance tags. Used everywhere a number appears so its source is never ambiguous.
export const tagSample = (text = 'Sample') => html`<span class="tag tag-sample" title="Generated for design. Not model output.">${text}</span>`;
export const tagReal = (text = 'Measured') => html`<span class="tag tag-real" title="Measured from the dataset files in this repo">${text}</span>`;
export const tagPlanned = (text = 'Not built') => html`<span class="tag tag-planned">${text}</span>`;
export const tagCode = (text = 'From code') => html`<span class="tag tag-code" title="Transcribed from src/models">${text}</span>`;

export const sampleCallout = (text) => html`<div class="callout" data-tone="sample" role="note">${icon('flask')}<div>${text}</div></div>`;
export const infoCallout = (text, tone = '') => html`<div class="callout" data-tone="${tone}" role="note">${icon('info')}<div>${text}</div></div>`;
export { raw };
