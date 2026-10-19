// Incidents: attack episodes with a response timeline (detected, actions, contained, resolved),
// plus insider and lateral-movement alerts.
import { html, mount, on } from '../core/dom.js';
import { fmtInt, fmtTime } from '../core/format.js';
import { toast } from '../components/overlays.js';
import { sevBadge } from '../components/security.js';
import { openFlowDrawer } from '../components/flow-detail.js';
import { subscribeLive, resolveEpisode } from '../data/index.js';
import { pageHead, panel, regions, insiderItem } from './common.js';

const STATE_LABEL = { active: 'Active', contained: 'Contained', resolved: 'Resolved' };
const ACTION_LABEL = { logged: 'Logged', notified: 'Notified', blocked: 'Blocked', 'upstream-protection': 'Upstream protection', isolated: 'Host isolated' };
const time = (ts) => (ts ? fmtTime(ts, { date: false }) : '');

function steps(e) {
  const out = [{ ts: e.firstSeen, label: 'Detected', detail: `${e.title}, ${e.severity} severity`, kind: 'detected' }];
  [...(e.actions || [])].sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts)).forEach((a) => out.push({
    ts: a.ts, label: ACTION_LABEL[a.kind] || a.kind, kind: 'action',
    detail: [a.detail, a.backend ? `(${a.backend})` : ''].filter(Boolean).join(' '),
  }));
  if (e.state === 'contained') out.push({ ts: e.stateSince, label: 'Contained', detail: 'Alert rate fell or all sources are blocked.', kind: 'contained' });
  else if (e.state === 'resolved') out.push({ ts: e.stateSince, label: 'Resolved', detail: 'No new alerts, or marked resolved by an analyst.', kind: 'resolved' });
  else out.push({ ts: null, label: 'Containment pending', detail: 'Waiting for the alert rate to fall.', kind: 'pending' });
  return out;
}

const mitre = (m) => (typeof m === 'string' ? m : [m.tactic, m.technique].filter(Boolean).join(' · '));

const card = (e) => html`<article class="ep-card" data-state="${e.state}" data-sev="${e.severity}" aria-label="${e.title}">
  <header class="ep-head">${sevBadge(e.severity)}<h3 class="ep-title">${e.title}</h3><span class="ep-state" data-state="${e.state}">${STATE_LABEL[e.state] || e.state}</span>
    <span class="spacer"></span>${e.state !== 'resolved' ? html`<button class="btn btn-sm" data-resolve="${e.id}">Mark resolved</button>` : ''}</header>
  <dl class="ep-facts">
    <div><dt>Target</dt><dd class="mono">${e.target || 'n/a'}</dd></div>
    <div><dt>Sources</dt><dd class="mono">${fmtInt(e.sources || 0)}</dd></div>
    <div><dt>Flows</dt><dd class="mono">${fmtInt(e.flows || 0)}</dd></div>
    <div><dt>Flows/s</dt><dd class="mono">${fmtInt(e.flowsPerSec || 0)}</dd></div>
    <div><dt>First seen</dt><dd class="mono">${time(e.firstSeen)}</dd></div>
  </dl>
  ${(e.topSources || []).length ? html`<p class="panel-meta">Top sources: <span class="mono">${e.topSources.slice(0, 5).join(', ')}</span>${e.sources > 5 ? ` and ${fmtInt(e.sources - 5)} more` : ''}</p>` : ''}
  ${(e.mitre || []).length ? html`<div class="chips-inline">${e.mitre.map((m) => html`<span class="tag-plain">${mitre(m)}</span>`)}</div>` : ''}
  <ol class="timeline" aria-label="Response timeline">${steps(e).map((st) => html`<li data-kind="${st.kind}"><span class="tl-dot" aria-hidden="true"></span>
    <span class="tl-time mono">${time(st.ts) || '...'}</span><span class="tl-body"><b>${st.label}</b>${st.detail ? html` <span class="panel-meta">${st.detail}</span>` : ''}</span></li>`)}</ol>
</article>`;

export default {
  title: 'Incidents',
  render(root) {
    mount(root, html`
      ${pageHead({ title: 'Incidents', sub: 'Alerts grouped into attack episodes, with the automatic response shown step by step.' })}
      <div class="ep-list" id="ep-list"></div>
      ${panel({ title: 'Insider and lateral-movement alerts', bodyCls: 'flush', body: html`<ul class="ins-list" id="ep-insider"></ul>` })}`);
    const region = regions(root);
    on(root, 'click', '[data-resolve]', async (_e, b) => {
      b.disabled = true;
      try { await resolveEpisode(b.dataset.resolve); toast('Incident marked resolved'); } catch (e) { toast(e.message, { tone: 'error' }); b.disabled = false; }
    });
    on(root, 'click', '[data-open]', (_e, b) => openFlowDrawer(b.dataset.open));
    return subscribeLive((s) => {
      if (!root.isConnected) return;
      const eps = s.episodes || [];
      region('ep-list', JSON.stringify(eps), () => eps.length ? eps.map(card) : html`<div class="empty"><div class="empty-title">No incidents</div><p>Incidents appear when alerts group into an attack on one target. Run <code>.venv/bin/python scripts/simulate.py story</code> to see one.</p></div>`);
      const ins = [...(s.insider || [])].reverse().slice(0, 30);
      region('ep-insider', ins.map((a) => a.id).join(), () => ins.length ? ins.map(insiderItem) : html`<li class="panel-body panel-meta">None. Hosts stay quiet while they warm up (first 10 minutes) unless you applied a learning window.</li>`);
    });
  },
};
