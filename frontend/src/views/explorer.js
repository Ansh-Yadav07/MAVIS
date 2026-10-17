// Event Explorer: one flow in depth. What was detected, by which detector, how far past the
// cut-off, which features stand out, and what else the same source did.
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { go } from '../core/router.js';
import { fmtInt, fmtTime } from '../core/format.js';
import { icon } from '../components/icons.js';
import { bindChart, histogram } from '../components/charts.js';
import { tip, toast } from '../components/overlays.js';
import { sevBadge, ipText, modelStrip, tagSample, sampleCallout, SCORE_RANGE, cutoffFor } from '../components/security.js';
import { flowHeadline, flowMeta, verdicts, evidence, explanation, statusSelect, bindStatus } from '../components/flow-detail.js';
import { emptyState } from '../components/states.js';
import { flows, flowById } from '../data/index.js';
import { MODELS } from '../data/model-registry.js';
import { pageHead, panel, remount, SEV_COLOR } from './common.js';

const RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };

function queue() {
  return flows().filter((f) => f.agree > 0).sort((a, b) => RANK[b.severity] - RANK[a.severity] || b.ts.localeCompare(a.ts));
}

function sourceTimeline(f) {
  const same = flows().filter((x) => x.src.ip === f.src.ip && x.day === f.day).sort((a, b) => a.ts.localeCompare(b.ts));
  const t = (x) => { const d = new Date(x.ts); return d.getUTCHours() + d.getUTCMinutes() / 60 + d.getUTCSeconds() / 3600; };
  const lo = 8, hi = 18;
  return html`
    <div class="timeline" role="list" aria-label="Flows from ${f.src.ip} on the same day">
      <div class="timeline-axis">${[8, 10, 12, 14, 16, 18].map((h) => html`<span style="left:${((h - lo) / (hi - lo)) * 100}%">${h}:00</span>`)}</div>
      <div class="timeline-track">
        ${same.map((x) => html`<button role="listitem" class="tl-dot ${x.id === f.id ? 'is-current' : ''}" data-sev="${x.severity}" style="left:${Math.max(0, Math.min(100, ((t(x) - lo) / (hi - lo)) * 100)).toFixed(2)}%"
          data-goto="${x.id}" aria-label="${x.id} at ${fmtTime(x.ts, { date: false })}, ${x.severity === 'none' ? 'not flagged' : x.severity}"
          data-tip='${tip(`${x.id} · ${fmtTime(x.ts, { date: false })} UTC`, [['Destination', `${x.dst.ip}:${x.dst.port}`], ['Detectors', `${x.agree} of 3`]])}'></button>`)}
      </div>
    </div>
    <div class="panel-meta" style="margin-top:8px">${fmtInt(same.length)} flows from ${f.src.ip} on this day. Select a mark to open it.</div>`;
}

export default {
  title: 'Event Explorer',
  crumb: (param) => param || null,
  render(root, param) {
    const q = queue();
    const f = param ? flowById(param) : q[0];
    if (!f) {
      mount(root, html`${pageHead({ title: 'Event Explorer' })}${emptyState({ title: `No flow called ${param}`, text: 'It may have been a link to an older sample. Pick a flow from the threat queue instead.', icon: 'explorer', action: html`<a class="btn" href="#threats">Open Threat Detection</a>` })}`);
      return;
    }
    const pos = q.findIndex((x) => x.id === f.id);
    const prev = pos > 0 ? q[pos - 1] : null;
    const next = pos >= 0 && pos < q.length - 1 ? q[pos + 1] : null;
    const note = store.edit(f.id).note || '';
    const all = flows();

    mount(root, html`
      ${pageHead({
        title: 'Event Explorer',
        sub: 'Everything MAVIS can show about one flow, from detector scores to the features behind them.',
        actions: html`
          <label class="visually-hidden" for="ex-jump">Jump to flow</label>
          <select class="select" id="ex-jump" style="width:auto;max-width:260px">
            ${q.slice(0, 120).map((x) => html`<option value="${x.id}" ${x.id === f.id ? html`selected` : ''}>${x.id} · ${x.severity} · ${x.src.ip}</option>`)}
          </select>
          <button class="btn" data-goto="${prev?.id || ''}" ${prev ? '' : html`disabled`} aria-label="Previous flow in queue">${icon('chevron', { cls: 'flip' })}Previous</button>
          <button class="btn" data-goto="${next?.id || ''}" ${next ? '' : html`disabled`} aria-label="Next flow in queue">Next${icon('chevron')}</button>`,
      })}

      <div class="ex-grid">
        <div class="ex-main">
          <section class="panel ex-hero" aria-label="Flow summary">
            <div class="panel-body">
              ${flowHeadline(f)}
              <div class="ex-hero-verdicts">${verdicts(f)}</div>
            </div>
          </section>

          ${panel({ title: 'Why it stands out', tag: html`<span class="tag tag-sample">Illustrative</span>`, body: html`
            <div class="prose">${explanation(f)}</div>
            <p class="panel-meta" style="margin-top:12px">Written in the browser from sample scores and features. MAVIS has no explanation module yet, so this is a preview of the format, not a model explanation.</p>` })}

          ${panel({ title: 'Where this flow sits in each score distribution', tag: tagSample(), body: html`
            <div class="dist-grid">${MODELS.map((m) => html`
              <figure class="dist">
                <figcaption><span class="mdot" data-m="${m.id}"></span>${m.name}<span class="panel-meta mono">${f.scores[m.id].toFixed(3)}</span></figcaption>
                <div class="chart" id="ex-h-${m.id}"></div>
              </figure>`)}</div>
            <div class="legend" style="margin-top:6px"><span class="legend-item"><i class="swatch" style="background:var(--benign)"></i>Benign-labelled sample flows</span><span class="legend-item"><i class="swatch" style="background:var(--ink-2)"></i>Attack-labelled</span><span class="legend-item"><i class="swatch" style="background:var(--accent)"></i>This flow</span></div>` })}

          ${panel({ title: 'Feature evidence', tag: tagSample(), meta: 'CIC-IDS2017 flow features', body: evidence(f, { limit: 10 }) })}

          ${panel({ title: `Activity from ${f.src.ip}`, tag: tagSample(), body: sourceTimeline(f) })}
        </div>

        <aside class="ex-side">
          ${panel({ title: 'Flow metadata', body: flowMeta(f) })}
          ${panel({ title: 'Risk assessment', tag: tagSample(), body: html`
            <div class="risk">
              <div class="risk-sev">${sevBadge(f.severity)}</div>
              <dl class="kv">
                <dt>Agreement</dt><dd>${modelStrip(f.flags)} <span class="panel-meta">${f.agree} of 3</span></dd>
                <dt>Combined score</dt><dd><span class="tag tag-planned">Not built</span></dd>
              </dl>
              <p class="panel-meta">The planned MAVIS fusion engine will produce a combined score. Until then severity uses a sample rule based on agreement and distance past each cut-off.</p>
            </div>` })}
          ${panel({ title: 'Investigation', body: html`
            ${statusSelect(f, 'ex-status')}
            <div class="field" style="margin-top:14px">
              <label class="field-label" for="ex-note">Analyst notes</label>
              <textarea class="textarea" id="ex-note" placeholder="What did you check? What should happen next?" maxlength="2000">${note}</textarea>
              <span class="field-hint" id="ex-note-hint">Saved in this browser only.</span>
            </div>
            <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
              <button class="btn btn-primary btn-sm" data-action="save-note">${icon('note')}Save note</button>
              <button class="btn btn-ghost btn-sm" data-action="copy-id">${icon('copy')}Copy flow summary</button>
            </div>` })}
        </aside>
      </div>`);

    // Score distributions with this flow marked
    MODELS.forEach((m) => {
      const el = $(`#ex-h-${m.id}`, root);
      bindChart(el, (w) => {
        const svg = histogram(w, 120, {
          values: all.map((x) => ({ value: x.scores[m.id], group: x.label === 'BENIGN' ? 'benign' : 'attack' })),
          groups: [{ key: 'benign', name: 'Benign-labelled' }, { key: 'attack', name: 'Attack-labelled' }],
          range: SCORE_RANGE[m.id], bins: 22, cutoff: cutoffFor(m.id), cutoffLabel: 'cut-off',
          color: 'var(--ink-2)', label: `${m.name} score distribution`, fmt: (v) => v.toFixed(2),
        });
        const [lo, hi] = SCORE_RANGE[m.id];
        const x = 34 + Math.max(0, Math.min(1, (f.scores[m.id] - lo) / (hi - lo))) * (w - 42);
        return svg.replace('</svg>', `<line x1="${x}" x2="${x}" y1="10" y2="94" stroke="var(--accent)" stroke-width="2"/><circle cx="${x}" cy="10" r="4" fill="var(--accent)"/></svg>`);
      });
    });

    bindStatus(root, () => remount(this, root, f.id));
    on(root, 'click', '[data-goto]', (_e, b) => { if (b.dataset.goto) go('explorer', b.dataset.goto); });
    on(root, 'change', '#ex-jump', (_e, s) => go('explorer', s.value));
    on(root, 'click', '[data-action="save-note"]', () => {
      store.setEdit(f.id, { note: $('#ex-note', root).value.trim() });
      $('#ex-note-hint', root).textContent = `Saved ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}, in this browser only.`;
      toast(`Note saved on ${f.id}`);
    });
    on(root, 'click', '[data-action="copy-id"]', async () => {
      const text = `${f.id} (${f.severity}) ${f.src.ip}:${f.src.port} -> ${f.dst.ip}:${f.dst.port} ${f.proto} at ${f.ts}\nIF ${f.scores.if} | LOF ${f.scores.lof} | AE ${f.scores.ae} | agreement ${f.agree}/3\n[MAVIS sample data]`;
      try { await navigator.clipboard.writeText(text); toast('Flow summary copied'); }
      catch { toast('Copy is blocked here. Select the flow ID in the header instead.', { tone: 'warn' }); }
    });
  },
};
