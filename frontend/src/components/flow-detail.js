// Building blocks for inspecting one flow. Used by the quick-look drawer and the Event Explorer.
import { html, on } from '../core/dom.js';
import { store } from '../core/store.js';
import { go } from '../core/router.js';
import { fmtInt, fmtBytes, fmtDurationUs, fmtFeature, fmtTime, fmtScore } from '../core/format.js';
import { icon } from './icons.js';
import { sevBadge, statusBadge, modelStrip, ipText, protoTag, scoreBar, tagSample, cutoffFor } from './security.js';
import { openDrawer, toast } from './overlays.js';
import { MODELS } from '../data/model-registry.js';
import { BENIGN_BASELINE, STATUS_OPTIONS, SAMPLE_FEATURE_KEYS } from '../data/sample/events.js';
import { flowById } from '../data/index.js';

export const flowHeadline = (f) => html`
  <div class="flow-head">
    <div class="flow-head-top">${sevBadge(f.severity, { pulse: true })}<span class="mono flow-id">${f.id}</span>${tagSample()}</div>
    <div class="flow-route">${ipText(f.src.ip, f.src.port, { scope: true })}<span class="route-arrow">${icon('arrowRight')}</span>${ipText(f.dst.ip, f.dst.port, { scope: true })}</div>
    <div class="flow-sub">${protoTag(f.proto)} <span>${f.service}</span><span>·</span><span class="mono">${fmtTime(f.ts)} UTC</span></div>
  </div>`;

export const flowMeta = (f) => html`
  <dl class="kv">
    <dt>Captured</dt><dd class="mono">${fmtTime(f.ts)} UTC</dd>
    <dt>Protocol</dt><dd>${f.proto} · ${f.service}</dd>
    <dt>Duration</dt><dd class="mono">${fmtDurationUs(f.durationUs)}</dd>
    <dt>Packets</dt><dd class="mono">${fmtInt(f.packets)}</dd>
    <dt>Bytes</dt><dd class="mono">${fmtBytes(f.bytes)}</dd>
    <dt>Dataset label</dt><dd>${f.label === 'BENIGN' ? 'Benign' : f.label} <span class="panel-meta">(${f.attackClass})</span></dd>
    <dt>Status</dt><dd>${statusBadge(f.status)}</dd>
  </dl>`;

// Per-model verdicts in each detector's own units, with its cut-off.
export const verdicts = (f) => html`
  <div class="verdicts">
    ${MODELS.map((m) => html`
      <div class="verdict" data-on="${f.flags[m.id]}">
        <div class="verdict-head"><span class="mdot" data-m="${m.id}"></span><span class="verdict-name">${m.name}</span>
          <span class="verdict-call">${f.flags[m.id] ? html`${icon('alert')}Flagged` : html`${icon('check')}Within normal`}</span></div>
        ${scoreBar(m.id, f.scores[m.id])}
        <div class="verdict-foot">${m.scoreName} · cut-off ${m.id === 'ae' ? html`${cutoffFor('ae')} <em>(sample)</em>` : fmtScore(cutoffFor(m.id))}</div>
      </div>`)}
  </div>
  <div class="agree-line">${modelStrip(f.flags)}<span><b>${f.agree} of 3</b> detectors flagged this flow</span></div>`;

// Feature evidence: sample flow features against a sample benign median.
export function evidence(f, { limit = 6 } = {}) {
  const rows = SAMPLE_FEATURE_KEYS.map((k) => {
    const base = BENIGN_BASELINE[k] || 0;
    const v = f.features[k];
    const ratio = base > 0 ? v / base : v > 0 ? Infinity : 1;
    const dev = Math.abs(Math.log10(Math.max(ratio, 1e-6)));
    return { k, v, base, ratio, dev };
  }).sort((a, b) => b.dev - a.dev).slice(0, limit);
  const maxDev = Math.max(...rows.map((r) => (isFinite(r.dev) ? r.dev : 3)), 0.5);
  return html`
    <div class="evidence">
      ${rows.map((r) => {
        const d = isFinite(r.dev) ? r.dev : 3;
        const up = r.ratio >= 1;
        const pct = Math.min(100, (d / maxDev) * 100);
        const ratioText = !isFinite(r.ratio) ? 'present, usually 0' : r.ratio >= 1 ? `${r.ratio >= 10 ? Math.round(r.ratio) : r.ratio.toFixed(1)}× usual` : `${(1 / r.ratio) >= 10 ? Math.round(1 / r.ratio) : (1 / r.ratio).toFixed(1)}× lower`;
        return html`<div class="ev-row">
          <span class="ev-name">${r.k}</span>
          <span class="ev-bar"><span class="ev-mid"></span><span class="ev-fill ${up ? 'up' : 'down'}" style="width:${(pct / 2).toFixed(1)}%"></span></span>
          <span class="ev-val mono">${fmtFeature(r.v)}</span>
          <span class="ev-ratio">${ratioText}</span>
        </div>`;
      })}
    </div>
    <div class="panel-meta" style="margin-top:8px">Bars show distance from a sample benign median on a log scale. Right of centre is higher than usual, left is lower.</div>`;
}

// Plain-language summary. Explicitly illustrative: MAVIS has no explanation module yet.
export function explanation(f) {
  if (f.agree === 0) return html`<p>No detector scored this flow above its cut-off. It is listed for context only.</p>`;
  const flaggedBy = MODELS.filter((m) => f.flags[m.id]).map((m) => m.name);
  const missed = MODELS.filter((m) => !f.flags[m.id]).map((m) => m.name);
  const top = SAMPLE_FEATURE_KEYS.map((k) => ({ k, r: (BENIGN_BASELINE[k] ? f.features[k] / BENIGN_BASELINE[k] : 1) }))
    .sort((a, b) => Math.abs(Math.log10(b.r || 1e-6)) - Math.abs(Math.log10(a.r || 1e-6)))[0];
  const phr = top.r >= 1 ? `${top.r >= 10 ? Math.round(top.r) : top.r.toFixed(1)} times higher than` : `well below`;
  return html`
    <p><b>${flaggedBy.join(' and ')}</b> scored this flow above ${flaggedBy.length > 1 ? 'their' : 'its'} cut-off${missed.length ? html`, while ${missed.join(' and ')} did not` : ''}.
    Its strongest deviation is <b>${top.k}</b>, ${phr} the benign median.</p>
    ${f.label !== 'BENIGN'
      ? html`<p>The dataset labels this flow <b>${f.label}</b> (${f.attackClass.toLowerCase()}), so a detection here would be a true positive.</p>`
      : html`<p>The dataset labels this flow benign, so this would be a <b>false positive</b> worth reviewing before tuning thresholds.</p>`}`;
}

export const statusSelect = (f, id = 'status-select') => html`
  <div class="field">
    <label class="field-label" for="${id}">Investigation status</label>
    <select class="select" id="${id}" data-status-for="${f.id}">
      ${STATUS_OPTIONS.map((s) => html`<option ${s === f.status ? html`selected` : ''}>${s}</option>`)}
    </select>
    <span class="field-hint">Saved in this browser only.</span>
  </div>`;

export function bindStatus(root, after) {
  on(root, 'change', '[data-status-for]', (_e, sel) => {
    store.setEdit(sel.dataset.statusFor, { status: sel.value });
    toast(`${sel.dataset.statusFor} marked ${sel.value.toLowerCase()}`);
    after?.();
  });
}

export function openFlowDrawer(id, { onChange } = {}) {
  const f = flowById(id);
  if (!f) return;
  const { el } = openDrawer((close) => html`
    <div class="drawer-head">
      <div style="flex:1;min-width:0">${flowHeadline(f)}</div>
      <button class="icon-btn" data-close aria-label="Close">${icon('close')}</button>
    </div>
    <div class="drawer-body">
      <section class="dsec"><h3 class="section-title">Detector verdicts</h3>${verdicts(f)}</section>
      <section class="dsec"><h3 class="section-title">Why it stands out <span class="tag tag-sample">Illustrative</span></h3><div class="prose">${explanation(f)}</div></section>
      <section class="dsec"><h3 class="section-title">Feature evidence</h3>${evidence(f, { limit: 5 })}</section>
      <section class="dsec"><h3 class="section-title">Flow</h3>${flowMeta(f)}</section>
      <section class="dsec">${statusSelect(f, 'drawer-status')}</section>
    </div>
    <div class="drawer-foot">
      <button class="btn btn-primary" data-open-explorer="${f.id}">${icon('explorer')}Open in Event Explorer</button>
      <button class="btn btn-ghost" data-close>Close</button>
    </div>`, { label: `Flow ${f.id}` });
  bindStatus(el, onChange);
  on(el, 'click', '[data-open-explorer]', (_e, b) => { el.querySelector('[data-close]').click(); go('explorer', b.dataset.openExplorer); });
}
