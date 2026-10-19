// Building blocks for inspecting one flow: the quick-look drawer used by the alert queue,
// the alert queue and the overview. Everything shown is engine output for that flow.
import { html } from '../core/dom.js';
import { fmtInt, fmtBytes, fmtDurationUs, fmtFeature, fmtScore, fmtPct, fmtTime } from '../core/format.js';
import { icon } from './icons.js';
import { sevBadge, modelStrip, ipText, scoreBar, modeTag, riskCell } from './security.js';
import { openDrawer } from './overlays.js';
import { MODELS } from '../data/model-registry.js';
import { flowById, apiKnown, liveState } from '../data/index.js';
import { blockControl, bindBlock } from './block.js';

export const flowHeadline = (f) => html`
  <div class="flow-head">
    <div class="flow-head-top">${sevBadge(f.severity, { pulse: true })}<span class="mono flow-id">${f.id}</span></div>
    <div class="flow-route">${ipText(f.src?.ip ?? null, f.src?.port ?? null)}<span class="route-arrow">${icon('arrowRight')}</span>${ipText(f.dst.ip, f.dst.port)}</div>
    <div class="flow-sub"><span>${f.service || 'unknown service'}</span><span>·</span><span class="mono">${f.file || 'sensor'}</span>${f.ts ? html`<span>·</span><span class="mono">${fmtTime(f.ts, { date: false })}</span>` : ''}</div>
  </div>`;

export const flowMeta = (f) => html`
  <dl class="kv">
    <dt>Sensor</dt><dd class="mono">${f.file || 'n/a'}</dd>
    <dt>Destination</dt><dd>port <span class="mono">${f.dst.port}</span> · ${f.service || 'unknown'}</dd>
    <dt>Duration</dt><dd class="mono">${fmtDurationUs(f.durationUs)}</dd>
    <dt>Packets</dt><dd class="mono">${fmtInt(f.packets)}</dd>
    <dt>Bytes</dt><dd class="mono">${fmtBytes(f.bytes)}</dd>
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

export const mitreList = (f) => (f.mitre?.length
  ? html`<div class="chips-inline">${f.mitre.map((m) => html`<span class="tag-plain" title="${m.technique}">${m.tactic} · ${m.technique}</span>`)}</div>`
  : html`<p class="panel-meta">No ATT&amp;CK mapping for this verdict.</p>`);

export const actionList = (f) => (f.actions?.length
  ? html`<ol class="prose" style="margin:0;padding-left:18px">${f.actions.map((a) => html`<li>${a}</li>`)}</ol>`
  : html`<p class="panel-meta">No recommended actions: the flow is not alerted.</p>`);

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
      ${blocked ? html`<p class="panel-meta"><span class="mono">${ip}</span> already has an active block. Manage it in Hosts.</p>` : blockControl(ip, f.family, f.id)}</section>` : ''}`;
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
      <section class="dsec"><h3 class="section-title">Flow</h3>${flowMeta(f)}</section>
    </div>
    <div class="drawer-foot">
      <button class="btn btn-ghost" data-close>Close</button>
    </div>`, { label: `Flow ${f.id}`, onClose: () => onChange?.() });
  bindBlock(el);
}
