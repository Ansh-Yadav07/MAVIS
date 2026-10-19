// App shell: navigation rail, top bar (search, capture-day filter, alert budget, notifications)
// and the provenance strip. Everything shown comes from data/index.js.
import { html, mount, on, $, esc } from '../core/dom.js';
import { store } from '../core/store.js';
import { go } from '../core/router.js';
import { icon } from './icons.js';
import { logoMark } from './logo.js';
import { togglePopover, closePopover, openDialog, toast } from './overlays.js';
import { sevBadge } from './security.js';
import { flows, flagged, DAYS, budgets, currentBudget, insights, drift, snapshot, captures, apiAvailable, engine } from '../data/index.js';

export const NAV = [
  { group: 'Operate', items: [
    { id: 'overview', label: 'Overview', icon: 'overview' },
    { id: 'live', label: 'Live Monitor', icon: 'live' },
    { id: 'threats', label: 'Threat Detection', icon: 'threat', count: 'open' },
    { id: 'investigations', label: 'Investigations', icon: 'investigations' },
    { id: 'network', label: 'Network Traffic', icon: 'network' },
    { id: 'explorer', label: 'Event Explorer', icon: 'explorer' },
  ] },
  { group: 'Engine', items: [
    { id: 'models', label: 'ML Models', icon: 'models' },
    { id: 'dataset', label: 'Dataset Analysis', icon: 'dataset' },
  ] },
  { group: 'Output', items: [
    { id: 'reports', label: 'Reports', icon: 'reports' },
    { id: 'analyze', label: 'Analyze capture', icon: 'analyze' },
    { id: 'settings', label: 'Settings', icon: 'settings' },
  ] },
];

export const navLabel = (id) => NAV.flatMap((g) => g.items).find((i) => i.id === id)?.label || 'Overview';
export const fmtBudget = (b) => `${parseFloat((b * 100).toFixed(2))}%`;

const day = () => store.session.day || undefined;
const openCount = () => flagged({ day: day() }).filter((f) => (f.severity === 'critical' || f.severity === 'high') && (f.status === 'New' || f.status === 'Triaging')).length;

let apiOk = null;
const railFoot = () => html`
  <div class="rail-source">
    <div class="rail-source-row" title="Alerts use the engine's calibrated thresholds for this false-positive budget"><span class="live-dot" data-state="real"></span><span class="rail-source-text"><b>MAVIS engine</b> · ${fmtBudget(currentBudget())} alert budget</span></div>
    <div class="rail-source-row" title="${apiOk ? 'Local API reachable: you can analyse your own captures' : 'Run python scripts/serve.py to enable live analysis of uploaded captures'}"><span class="live-dot" data-state="${apiOk ? 'real' : 'off'}"></span><span class="rail-source-text">${apiOk ? 'Local API connected' : 'Static snapshot'}</span></div>
  </div>`;

export function renderRail(active) {
  const rail = $('#rail');
  mount(rail, html`
    <a class="brand" href="#overview" aria-label="MAVIS home">
      ${logoMark()}
      <span class="brand-text"><span class="brand-name">MAVIS</span><span class="brand-sub">Multi-Attack Vector Intelligence</span></span>
    </a>
    <nav class="nav" aria-label="Sections">
      ${NAV.map((g) => html`
        <div class="nav-group-label">${g.group}</div>
        ${g.items.map((it) => html`
          <a class="nav-link" href="#${it.id}" ${active === it.id ? html`aria-current="page"` : ''} title="${it.label}">
            ${icon(it.icon)}<span class="nav-label">${it.label}</span>
            ${it.count === 'open' ? html`<span class="nav-count" data-tone="critical" title="Open critical and high alerts (new or triaging)">${openCount()}</span>` : ''}
          </a>`)}`)}
    </nav>
    <div class="rail-foot" id="rail-foot">${railFoot()}</div>`);
  apiAvailable().then((v) => {
    if (apiOk === v) return;
    apiOk = v;
    const foot = $('#rail-foot');
    if (foot) mount(foot, railFoot());
  });
}

export function renderTopbar(active, crumb) {
  const unread = notifications().filter((n) => !store.isRead(n.id)).length;
  const cur = currentBudget();
  mount($('#topbar'), html`
    <button class="icon-btn menu-btn" data-action="open-nav" aria-label="Open navigation" aria-controls="rail">${icon('menu')}</button>
    <button class="icon-btn collapse-btn" data-action="toggle-rail" aria-label="${store.prefs.rail === 'collapsed' ? 'Expand' : 'Collapse'} sidebar" title="Toggle sidebar">${icon('collapse')}</button>
    <nav class="crumbs" aria-label="Breadcrumb">
      <span class="crumb-root">MAVIS</span><span class="crumb-sep" aria-hidden="true">/</span>
      <span ${crumb ? '' : html`aria-current="page"`}>${navLabel(active)}</span>
      ${crumb ? html`<span aria-hidden="true">/</span><span aria-current="page" class="mono">${crumb}</span>` : ''}
    </nav>
    <div class="topbar-spacer"></div>
    <div class="search global-search" style="flex:0 1 280px">
      ${icon('search')}
      <input class="input" id="global-search" type="search" placeholder="Search id, port, service, label" aria-label="Search flows by id, port, service, label, family or verdict. Enter opens the Event Explorer." autocomplete="off" role="combobox" aria-expanded="false" aria-controls="search-results">
      <kbd aria-hidden="true">/</kbd>
    </div>
    <label class="tb-ctl tb-day"><span class="visually-hidden">Capture day</span>
      <select class="select" id="tb-day" title="Capture day">
        <option value="">All days</option>
        ${DAYS.map((d) => html`<option value="${d.id}" ${store.session.day === d.id ? html`selected` : ''}>${d.label}</option>`)}
      </select></label>
    <label class="tb-ctl tb-budget" title="Share of benign traffic the engine may flag. Thresholds were calibrated on held-out benign flows."><span>Alert budget</span>
      <select class="select" id="tb-budget" aria-label="Alert budget">
        ${budgets().map((b) => html`<option value="${b}" ${b === cur ? html`selected` : ''}>${fmtBudget(b)}</option>`)}
      </select></label>
    <div class="topbar-actions">
      <button class="icon-btn" data-action="notifications" aria-haspopup="true" aria-expanded="false" aria-label="Notifications, ${unread} unread">${icon('bell')}${unread ? html`<span class="badge-dot">${unread}</span>` : ''}</button>
      <button class="btn btn-ghost btn-sm" data-action="profile" aria-haspopup="menu" aria-expanded="false">Analyst</button>
    </div>`);
}

export function renderProvenance() {
  const snap = snapshot();
  const ups = captures().filter((c) => c.upload).length;
  const gen = snap?.generated ? String(snap.generated).slice(0, 10) : 'unknown';
  mount($('#provenance'), html`
    <span class="prov-item"><span class="live-dot" data-state="real"></span><b>Real engine output</b> · CIC-IDS2017 week · snapshot ${gen}${ups ? html` · + ${ups} uploaded capture${ups > 1 ? 's' : ''}` : ''}</span>
    <span class="prov-item prov-optional">No IPs or timestamps in this dataset: ports, services and capture order are shown instead</span>`);
}

/* ---------- Notifications: engine insights and drift warnings ---------- */
function notifications() {
  const d = day();
  const ins = insights(d).map((n) => ({ id: n.id, kind: 'insight', text: n.text, where: n.file }));
  const dr = drift(d).filter((x) => x.status && x.status !== 'stable' && x.status !== 'insufficient-data')
    .map((x) => ({ id: `drift:${x.file}`, kind: 'drift', text: `Drift ${x.status}: ${x.features_drifted ?? 0} features shifted${x.top?.length ? ` (largest: ${x.top[0].feature})` : ''}.`, where: x.file }));
  return [...dr, ...ins].filter((n) => n.text && !/^No significant threats/.test(n.text)).slice(0, 12);
}

function notificationsPanel() {
  const list = notifications();
  return html`
    <div class="menu-head" style="display:flex;justify-content:space-between;align-items:center;gap:8px">
      <span>Engine notes</span>
      ${list.length ? html`<button class="btn btn-ghost btn-sm" data-action="mark-read">Mark all read</button>` : ''}
    </div>
    ${list.length ? list.map((n) => html`
      <button class="menu-item notif ${store.isRead(n.id) ? 'is-read' : ''}" data-note="${n.id}" style="align-items:flex-start;${store.isRead(n.id) ? 'opacity:.6' : ''}">
        <span style="display:grid;gap:2px;min-width:0;flex:1">
          <span class="panel-meta">${n.kind === 'drift' ? 'Model drift' : 'Insight'} · ${n.where}</span>
          <span style="font-size:12.5px;color:var(--ink-1);white-space:normal;line-height:1.4">${n.text}</span>
        </span>
      </button>`) : html`<div class="empty" style="padding:20px">${icon('check')}<div class="empty-title">Nothing to report</div><p>Insights and drift warnings from the engine appear here.</p></div>`}
    <div class="menu-sep"></div>
    <button class="menu-item" data-go="settings">${icon('settings')}Settings</button>`;
}

/* ---------- Global search ---------- */
function searchResults(q) {
  const s = q.trim().toLowerCase();
  if (!s) return [];
  const pages = NAV.flatMap((g) => g.items).filter((i) => i.label.toLowerCase().includes(s)).map((i) => ({ kind: 'page', id: i.id, label: i.label }));
  const hits = flows({ day: day() }).filter((f) =>
    f.id.toLowerCase().includes(s) || String(f.dst.port) === s || (f.service || '').toLowerCase() === s
    || (f.label || '').toLowerCase().includes(s) || (f.family || '').toLowerCase().includes(s) || f.verdict === s)
    .sort((a, b) => b.risk - a.risk)
    .slice(0, 7)
    .map((f) => ({ kind: 'flow', id: f.id, label: `${f.id} · ${f.family || 'normal'} · port ${f.dst.port}`, flow: f }));
  return [...pages, ...hits];
}

export function bindShell(onPrefChange) {
  const app = $('#app');

  on(document, 'click', '[data-action="open-nav"]', () => { app.dataset.mobileNav = 'open'; $('#rail .nav-link')?.focus(); });
  on(document, 'click', '[data-action="close-nav"]', () => { delete app.dataset.mobileNav; });
  on($('#rail'), 'click', '.nav-link', () => { delete app.dataset.mobileNav; });
  on(document, 'click', '[data-action="toggle-rail"]', () => {
    store.setPref('rail', store.prefs.rail === 'collapsed' ? 'expanded' : 'collapsed');
    onPrefChange();
  });

  on(document, 'click', '[data-action="notifications"]', (_e, btn) => {
    togglePopover(btn, notificationsPanel(), { width: 380, role: 'dialog', onMount: (el) => {
      on(el, 'click', '[data-note]', (_ev, b) => { store.markRead([b.dataset.note]); b.style.opacity = '.6'; });
      on(el, 'click', '[data-action="mark-read"]', () => { store.markRead(notifications().map((n) => n.id)); closePopover(); toast('Notifications marked as read'); });
      on(el, 'click', '[data-go]', (_ev, b) => { closePopover(); go(b.dataset.go); });
    } });
  });

  on(document, 'change', '#tb-day', (_e, sel) => store.setSession('day', sel.value || null));
  on(document, 'change', '#tb-budget', (_e, sel) => store.setPref('alertBudget', Number(sel.value)));

  on(document, 'click', '[data-action="profile"]', (_e, btn) => {
    togglePopover(btn, html`
      <div class="menu-head"><div style="color:var(--ink-1);font-weight:600;font-size:var(--fs-sm)">Analyst</div>Local console, no sign-in. Edits stay in this browser.</div>
      <div class="menu-sep"></div>
      <button class="menu-item" role="menuitem" data-go="settings">${icon('settings')}Settings</button>
      <button class="menu-item" role="menuitem" data-action="appearance-toggle">${icon('layers')}Switch to ${document.documentElement.dataset.appearance === 'light' ? 'dark' : 'light'} appearance</button>
      <button class="menu-item" role="menuitem" data-action="shortcuts">${icon('keyboard')}Keyboard shortcuts</button>
      <div class="menu-sep"></div>
      <a class="menu-item" role="menuitem" href="https://github.com/Ansh-Yadav07/MAVIS" target="_blank" rel="noopener">${icon('external')}Project repository</a>`,
    { width: 260, onMount: (el) => {
      on(el, 'click', '[data-go]', (_ev, b) => { closePopover(); go(b.dataset.go); });
      on(el, 'click', '[data-action="appearance-toggle"]', () => {
        store.setPref('appearance', document.documentElement.dataset.appearance === 'light' ? 'dark' : 'light');
        closePopover(); onPrefChange();
      });
      on(el, 'click', '[data-action="shortcuts"]', () => { closePopover(); shortcutsDialog(); });
    } });
  });

  // Search combobox
  let resultsEl = null, activeIdx = -1, results = [];
  const closeResults = () => { resultsEl?.remove(); resultsEl = null; activeIdx = -1; $('#global-search')?.setAttribute('aria-expanded', 'false'); };
  const choose = (r) => {
    closeResults();
    const input = $('#global-search'); if (input) { input.value = ''; input.blur(); }
    if (r.kind === 'page') go(r.id); else go('explorer', r.id);
  };
  const paint = (input) => {
    results = searchResults(input.value);
    if (!input.value.trim()) { closeResults(); return; }
    if (!resultsEl) {
      resultsEl = document.createElement('div');
      resultsEl.className = 'popover search-pop';
      resultsEl.id = 'search-results';
      resultsEl.setAttribute('role', 'listbox');
      document.body.appendChild(resultsEl);
    }
    const r = input.getBoundingClientRect();
    resultsEl.style.width = `${Math.max(r.width, Math.min(380, window.innerWidth - 24))}px`;
    resultsEl.style.left = `${Math.max(12, Math.min(window.innerWidth - resultsEl.offsetWidth - 12, r.left))}px`;
    resultsEl.style.top = `${r.bottom + 6 + window.scrollY}px`;
    mount(resultsEl, results.length ? html`${results.map((res, i) => html`
      <div class="menu-item" role="option" id="sr-${i}" aria-selected="${i === activeIdx}" data-idx="${i}" style="${i === activeIdx ? 'background:var(--surface-hover)' : ''}">
        ${icon(res.kind === 'page' ? 'arrowRight' : 'explorer')}
        <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" class="${res.kind === 'flow' ? 'mono' : ''}">${res.label}</span>
        ${res.kind === 'flow' ? sevBadge(res.flow.severity) : html`<span class="panel-meta">Section</span>`}
      </div>`)}<div class="menu-head" style="border-top:1px solid var(--line);margin-top:4px">Enter opens all matches in the Event Explorer</div>`
      : html`<div class="menu-head">No flows match “${esc(input.value)}”. Try a port such as 443, a service such as http, or a label such as PortScan.</div>`);
    input.setAttribute('aria-expanded', 'true');
    input.setAttribute('aria-activedescendant', activeIdx >= 0 ? `sr-${activeIdx}` : '');
  };
  on(document, 'input', '#global-search', (_e, input) => { activeIdx = -1; paint(input); });
  on(document, 'keydown', '#global-search', (ev, input) => {
    if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
      if (!results.length) return;
      activeIdx = ev.key === 'ArrowDown' ? (activeIdx + 1) % results.length : (activeIdx - 1 + results.length) % results.length;
      paint(input); ev.preventDefault();
    } else if (ev.key === 'Enter') {
      if (activeIdx >= 0 && results[activeIdx]) { choose(results[activeIdx]); return; }
      const q = input.value.trim();
      if (!q) return;
      closeResults(); input.blur();
      store.setSession('query', q);
      go('explorer');
    } else if (ev.key === 'Escape') { closeResults(); input.blur(); }
  });
  document.addEventListener('pointerdown', (ev) => {
    const opt = ev.target.closest('#search-results [data-idx]');
    if (opt) { ev.preventDefault(); choose(results[+opt.dataset.idx]); return; }
    if (resultsEl && !ev.target.closest('#search-results') && ev.target.id !== 'global-search') closeResults();
  });

  // "/" focuses search unless typing in a field. Escape closes the mobile nav.
  document.addEventListener('keydown', (ev) => {
    const typing = ev.target.closest('input, textarea, select, [contenteditable]');
    if (ev.key === '/' && !typing && !ev.metaKey && !ev.ctrlKey) { ev.preventDefault(); $('#global-search')?.focus(); }
    if (ev.key === 'Escape' && app.dataset.mobileNav) delete app.dataset.mobileNav;
  });
}

export function shortcutsDialog() {
  openDialog(() => html`
    <div class="dialog-head"><h2 class="panel-title" style="font-size:var(--fs-lg)">Keyboard shortcuts</h2></div>
    <div class="dialog-body">
      <dl class="kv">
        <dt><kbd class="mono">/</kbd></dt><dd>Search flows by id, port, service, label, family or verdict</dd>
        <dt><kbd class="mono">↑ ↓</kbd> then <kbd class="mono">Enter</kbd></dt><dd>Pick a search result; Enter alone opens all matches</dd>
        <dt><kbd class="mono">Enter</kbd> on a row</dt><dd>Open the flow</dd>
        <dt><kbd class="mono">Esc</kbd></dt><dd>Close menus, drawers and dialogs</dd>
      </dl>
    </div>
    <div class="dialog-foot"><button class="btn btn-primary" data-close data-autofocus>Done</button></div>`, { label: 'Keyboard shortcuts' });
}
