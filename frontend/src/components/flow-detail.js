// Building blocks for inspecting one flow: the quick-look drawer used by the alert queue,
// the Event Explorer and the overview. Everything shown is engine output for that flow.
import { html, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { go } from '../core/router.js';
import { fmtInt, fmtBytes, fmtDurationUs, fmtFeature, fmtScore, fmtPct } from '../core/format.js';
import { icon } from './icons.js';
import { sevBadge, statusBadge, modelStrip, ipText, scoreBar, tagEngine, modeTag, outcomeTag, riskCell, dayLabel, OUTCOME_TITLE } from './security.js';
import { openDrawer, toast } from './overlays.js';
import { MODELS } from '../data/model-registry.js';
import { STATUS_OPTIONS, engine, FEATURE_KEYS, flowById, apiKnown, liveState } from '../data/index.js';
import { blockControl, bindBlock } from './block.js';

export const flowHeadline = (f) => html`
  <div class="flow-head">
    <div class="flow-head-top">${sevBadge(f.severity, { pulse: true })}<span class="mono flow-id">${f.id}</span>${tagEngine()}</div>
    <div class="flow-route">${ipText(f.src?.ip ?? null, f.src?.port ?? null)}<span class="route-arrow">${icon('arrowRight')}</span>${ipText(f.dst.ip, f.dst.port)}</div>
    <div class="flow-sub"><span>${f.service || 'unknown service'}</span><span>·</span><span>${dayLabel(f.day)}</span><span>·</span><span class="mono">${f.file}${f.row != null ? ` #${fmtInt(f.row)}` : ''}</span></div>
  </div>`;

export const flowMeta = (f) => html`
  <dl class="kv">
    <dt>Capture</dt><dd>${dayLabel(f.day)} · <span class="mono">${f.file}</span> · row ${fmtInt(f.row ?? 0)}</dd>
    <dt>Destination</dt><dd>port <span class="mono">${f.dst.port}</span> · ${f.service || 'unknown'}</dd>
    <dt>Duration</dt><dd class="mono">${fmtDurationUs(f.durationUs)}</dd>
    <dt>Packets</dt><dd class="mono">${fmtInt(f.packets)}</dd>
    <dt>Bytes</dt><dd class="mono">${fmtBytes(f.bytes)}</dd>
    <dt>Status</dt><dd>${statusBadge(f.status)}</dd>
  </dl>`;

// Verdict summary: risk, severity, family, detection mode, confidence.
export const verdictSummary = (f) => html`
  <dl class="kv">
    <dt>Verdict</dt><dd><b>${f.verdict}</b></dd>
    <dt>Risk</dt><dd>${riskCell(f.risk)}</dd>
    <dt>Severity</dt><dd>${sevBadge(f.severity)}</dd>
    <dt>Family</dt><dd>${f.familyTitle || f.family || '—'}${f.family && f.familyTitle && f.familyTitle !== f.family ? html` <span class="panel-meta">(${f.family})</span>` : ''}</dd>
    <dt>Detection mode</dt><dd>${modeTag(f.mode)}</dd>
    <dt>Confidence</dt><dd>${f.confidence || '—'} <span class="panel-meta">· ${f.votes ?? f.agree} detector vote${(f.votes ?? f.agree) === 1 ? '' : 's'}</span></dd>
  </dl>`;

// Detector verdicts: benign-percentile score bar per model plus the native score.
export const verdicts = (f) => html`
  <div class="verdicts">
    ${MODELS.map((m) => html`
      <div class="verdict" data-on="${!!f.flags[m.id]}">
        <div class="verdict-head"><span class="mdot" data-m="${m.id}"></span><span class="verdict-name">${m.name}</span>
          <span class="verdict-call">${f.flags[m.id] ? html`${icon('alert')}Flagged` : html`${icon('check')}Within normal`}</span></div>
        ${scoreBar(m.id, f.pct[m.id])}
        <div class="verdict-foot">Percentile of benign flows · native ${m.scoreName.toLowerCase()} ${fmtScore(f.scores[m.id])}</div>
      </div>`)}
  </div>
  <div class="agree-line">${modelStrip(f.flags)}<span><b>${f.agree} of ${MODELS.length}</b> anomaly detectors flagged this flow</span></div>`;

export const classifier = (f) => html`
  <dl class="kv">
    <dt>P(known attack)</dt><dd class="mono">${fmtPct(f.pKnown, 1)}</dd>
    <dt>Predicted type</dt><dd>${f.predictedType || '—'}</dd>
    <dt>Type confidence</dt><dd class="mono">${f.typeConfidence != null ? fmtPct(f.typeConfidence, 1) : '—'}</dd>
    <dt>Novelty</dt><dd class="mono">${f.anomalyPct != null ? `p${(f.anomalyPct * 100).toFixed(1)}` : '—'} <span class="panel-meta">anomaly percentile</span></dd>
  </dl>`;

const times = (r) => (!isFinite(r) ? 'present, usually 0' : r >= 1 ? `${r >= 10 ? Math.round(r) : r.toFixed(1)}× usual` : `${(1 / r) >= 10 ? Math.round(1 / r) : (1 / r).toFixed(1)}× lower`);

// The engine's own explanation: features that deviate most from the benign median.
export function whyList(f) {
  if (!f.why?.length) return html`<p class="panel-meta">${f.verdict === 'normal' ? 'Not alerted, so no explanation was generated.' : 'No explanation was exported for this flow.'}</p>`;
  return html`<div class="evidence">${f.why.map((w) => {
    // ratio = this feature's autoencoder reconstruction error / its typical error on benign flows
    const ratio = w.ratio ?? 1;
    const up = (w.z ?? 0) >= 0;
    return html`<div class="ev-row" title="${w.text || ''}">
      <span class="ev-name">${w.feature}</span>
      <span class="ev-bar"><span class="ev-mid"></span><span class="ev-fill ${up ? 'up' : 'down'}" style="width:${Math.min(50, Math.log10(Math.max(ratio, 1)) * 16).toFixed(1)}%"></span></span>
      <span class="ev-val mono">${fmtFeature(w.value ?? 0)}</span>
      <span class="ev-ratio">${Math.round(ratio)}× usual error <span class="panel-meta">(median value ${fmtFeature(w.baseline ?? 0)})</span></span>
    </div>`;
  })}</div>${f.why[0]?.text ? html`<ul class="prose" style="margin:8px 0 0;padding-left:18px">${f.why.map((w) => html`<li>${w.text}</li>`)}</ul>` : ''}`;
}

// Feature evidence: this flow's features against the benign median (engine().baseline).
export function evidence(f, { limit = 6 } = {}) {
  const base = engine().baseline;
  const rows = FEATURE_KEYS().map((k) => {
    const b = base[k] || 0, v = f.features[k] ?? 0;
    const ratio = b > 0 ? v / b : v > 0 ? Infinity : 1;
    return { k, v, b, ratio, dev: Math.abs(Math.log10(Math.max(ratio, 1e-6))) };
  }).sort((a, c) => (isFinite(c.dev) ? c.dev : 9) - (isFinite(a.dev) ? a.dev : 9)).slice(0, limit);
  const maxDev = Math.max(...rows.map((r) => (isFinite(r.dev) ? r.dev : 3)), 0.5);
  return html`
    <div class="evidence">
      ${rows.map((r) => {
        const d = isFinite(r.dev) ? r.dev : 3;
        return html`<div class="ev-row">
          <span class="ev-name">${r.k}</span>
          <span class="ev-bar"><span class="ev-mid"></span><span class="ev-fill ${r.ratio >= 1 ? 'up' : 'down'}" style="width:${(Math.min(100, (d / maxDev) * 100) / 2).toFixed(1)}%"></span></span>
          <span class="ev-val mono">${fmtFeature(r.v)}</span>
          <span class="ev-ratio">${times(r.ratio)}</span>
        </div>`;
      })}
    </div>
    <div class="panel-meta" style="margin-top:8px">Bars show distance from the benign median on a log scale. Right of centre is higher than usual, left is lower.</div>`;
}

// Kept for older callers: plain-language one-liner built from the engine's own fields.
export function explanation(f) {
  if (f.verdict === 'normal') return html`<p>The engine did not alert on this flow at the current alert budget.</p>`;
  const top = f.why?.[0];
  return html`<p><b>${f.familyTitle || f.family}</b> at ${f.confidence} confidence (${f.mode} detection).${top ? html` Strongest deviation: <b>${top.feature}</b>.` : ''}</p>`;
}

export const mitreList = (f) => (f.mitre?.length
  ? html`<div class="chips-inline">${f.mitre.map((m) => html`<span class="tag-plain" title="${m.technique}">${m.tactic} · ${m.technique}</span>`)}</div>`
  : html`<p class="panel-meta">No ATT&amp;CK mapping for this verdict.</p>`);

export const actionList = (f) => (f.actions?.length
  ? html`<ol class="prose" style="margin:0;padding-left:18px">${f.actions.map((a) => html`<li>${a}</li>`)}</ol>`
  : html`<p class="panel-meta">No recommended actions: the flow is not alerted.</p>`);

export const groundTruth = (f) => (f.category == null ? '' : html`
  <dl class="kv">
    <dt>Dataset label</dt><dd class="mono">${f.label}</dd>
    <dt>Category</dt><dd>${f.category}</dd>
    <dt>Outcome</dt><dd>${outcomeTag(f.outcome)} <span class="panel-meta">${OUTCOME_TITLE[f.outcome] || ''}</span></dd>
  </dl>`);

export const statusSelect = (f, id = 'status-select') => html`
  <div class="field">
    <label class="field-label" for="${id}">Investigation status</label>
    <select class="select" id="${id}" data-status-for="${f.id}">
      ${(STATUS_OPTIONS.includes(f.status) ? STATUS_OPTIONS : [...STATUS_OPTIONS, f.status]).map((s) => html`<option ${s === f.status ? html`selected` : ''}>${s}</option>`)}
    </select>
    <span class="field-hint">Saved in this browser only.</span>
  </div>`;

export const noteField = (f, id = 'flow-note') => html`
  <div class="field">
    <label class="field-label" for="${id}">Analyst note</label>
    <textarea class="textarea" id="${id}" maxlength="2000" placeholder="What did you check? What should happen next?">${store.edit(f.id).note || ''}</textarea>
    <div><button class="btn btn-sm" data-save-note="${f.id}" data-note-from="${id}">${icon('note')}Save note</button></div>
  </div>`;

export function bindStatus(root, after) {
  on(root, 'change', '[data-status-for]', (_e, sel) => {
    store.setEdit(sel.dataset.statusFor, { status: sel.value });
    toast(`${sel.dataset.statusFor} marked ${sel.value.toLowerCase()}`);
    after?.();
  });
  on(root, 'click', '[data-save-note]', (_e, b) => {
    store.setEdit(b.dataset.saveNote, { note: $(`#${b.dataset.noteFrom}`, root).value.trim() });
    toast(`Note saved on ${b.dataset.saveNote}`);
    after?.();
  });
}

// Response decision, insider alerts and the Block action. Shown for live flows and, when the
// local API is up, for any flow that carries a source address.
export function responseSection(f) {
  const ip = f.src?.ip;
  const ins = (f.insider || []).map((id) => liveState().insider.find((a) => a.id === id)).filter(Boolean);
  if (!f.response && !ins.length && !(ip && apiKnown())) return '';
  const blocked = ip && liveState().blocks.some((b) => b.ip === ip);
  return html`
    ${f.response ? html`<section class="dsec"><h3 class="section-title">Response decision</h3>
      <dl class="kv"><dt>Action</dt><dd><span class="tag-plain mono">${f.response.action}</span></dd><dt>Reason</dt><dd>${f.response.reason || '—'}</dd></dl></section>` : ''}
    ${ins.length ? html`<section class="dsec"><h3 class="section-title">Insider alerts</h3>
      <ul class="prose" style="margin:0;padding-left:18px">${ins.map((a) => html`<li><b>${a.title}</b> <span class="panel-meta">${a.kind} · ${a.severity}</span><br><span class="panel-meta">${a.detail}</span></li>`)}</ul></section>` : ''}
    ${ip && apiKnown() ? html`<section class="dsec"><h3 class="section-title">Block source</h3>
      ${blocked ? html`<p class="panel-meta"><span class="mono">${ip}</span> already has an active block. Manage it in Settings, Blocks &amp; audit.</p>` : blockControl(ip, f.family, f.id)}</section>` : ''}`;
}

export function openFlowDrawer(id, { onChange } = {}) {
  const f = flowById(id);
  if (!f) return;
  const { el } = openDrawer(() => html`
    <div class="drawer-head">
      <div style="flex:1;min-width:0">${flowHeadline(f)}</div>
      <button class="icon-btn" data-close aria-label="Close">${icon('close')}</button>
    </div>
    <div class="drawer-body">
      <section class="dsec"><h3 class="section-title">Verdict</h3>${verdictSummary(f)}</section>
      <section class="dsec"><h3 class="section-title">Anomaly detectors</h3>${verdicts(f)}</section>
      <section class="dsec"><h3 class="section-title">Attack classifier</h3>${classifier(f)}</section>
      <section class="dsec"><h3 class="section-title">Why it stands out</h3>${whyList(f)}</section>
      <section class="dsec"><h3 class="section-title">MITRE ATT&amp;CK</h3>${mitreList(f)}</section>
      <section class="dsec"><h3 class="section-title">Recommended actions</h3>${actionList(f)}</section>
      ${responseSection(f)}
      ${f.category == null ? '' : html`<section class="dsec"><h3 class="section-title">Ground truth</h3>${groundTruth(f)}</section>`}
      <section class="dsec"><h3 class="section-title">Flow</h3>${flowMeta(f)}</section>
      <section class="dsec">${statusSelect(f, 'drawer-status')}${noteField(f, 'drawer-note')}</section>
    </div>
    <div class="drawer-foot">
      <button class="btn btn-primary" data-open-explorer="${f.id}">${icon('explorer')}Open in Event Explorer</button>
      <button class="btn btn-ghost" data-close>Close</button>
    </div>`, { label: `Flow ${f.id}`, onClose: () => onChange?.() });
  bindStatus(el);
  bindBlock(el);
  on(el, 'click', '[data-open-explorer]', (_e, b) => { el.querySelector('[data-close]').click(); go('explorer', b.dataset.openExplorer); });
}
