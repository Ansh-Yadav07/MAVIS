// Security vocabulary: severity, detector verdicts, addresses, scores.
import { html } from '../core/dom.js';
import { fmtScore } from '../core/format.js';
import { sevGlyph, icon } from './icons.js';
import { MODELS } from '../data/model-registry.js';
import { engine } from '../data/index.js';

export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'none'];
export const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'Normal' };
export const SEV_COLOR = {
  critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)', none: 'var(--sev-none)',
};
export const sevRank = (s) => SEV_ORDER.length - 1 - Math.max(0, SEV_ORDER.indexOf(s));   // critical = 4 ... none = 0

export const sevBadge = (sev, { pulse = false } = {}) =>
  html`<span class="sev ${pulse && sev === 'critical' ? 'sev-pulse' : ''}" data-sev="${sev}">${sevGlyph(sev)}${SEV_LABEL[sev] || sev}</span>`;

export const modelStrip = (flags) => html`<span class="mstrip" role="img" aria-label="${
  MODELS.map((m) => `${m.name} ${flags[m.id] ? 'flagged' : 'not flagged'}`).join(', ')
}">${MODELS.map((m) => html`<span class="mcell" data-m="${m.id}" data-on="${!!flags[m.id]}">${m.short}</span>`)}</span>`;

export const ipText = (ip, port) => html`<span class="ip">${ip ?? '?'}${port != null ? html`<span class="port">:${port}</span>` : ''}</span>`;

// Score bars use each detector's benign percentile (0..1); a detector "flags" above the vote cut-off.
const cutoff = () => engine()?.votePercentile ?? 0.99;
export function scoreBar(id, value) {
  const lo = 0.5, hi = 1;
  const pos = (v) => Math.max(0, Math.min(1, (v - lo) / (hi - lo))) * 100;
  const over = value > cutoff();
  const fill = over ? `var(--m-${id})` : 'var(--ink-3)';
  const text = `p${(value * 100).toFixed(value >= 0.999 ? 2 : 1)}`;
  return html`<span class="score" title="${over ? 'Above cut-off' : 'Below cut-off'}">
    <span class="score-track"><span class="score-fill" style="width:${pos(value).toFixed(1)}%;background:${fill}"></span><span class="score-cut" style="left:${pos(cutoff()).toFixed(1)}%"></span></span>
    <span class="score-val">${text}</span></span>`;
}

export const infoCallout = (text, tone = '') => html`<div class="callout" data-tone="${tone}" role="note">${icon('info')}<div>${text}</div></div>`;

export const MODE_LABEL = { known: 'Known', novel: 'Novel', 'known+novel': 'Known + novel' };
export const modeTag = (mode) => (mode ? html`<span class="mode-tag" data-mode="${mode}" title="${mode === 'known' ? 'Matches a known attack signature' : mode === 'novel' ? 'Anomalous but no known signature matched' : 'Recognised and also anomalous'}">${MODE_LABEL[mode]}</span>` : html`<span class="mode-tag">—</span>`);
export const riskCell = (risk) => html`<span class="risk-cell" title="Risk 0-100"><i><b style="width:${Math.max(0, Math.min(100, risk || 0)).toFixed(0)}%"></b></i>${Math.round(risk || 0)}</span>`;
export { fmtScore };
