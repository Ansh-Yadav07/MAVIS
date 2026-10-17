// App shell: navigation rail, top bar (search, notifications, profile) and the provenance strip.
import { html, mount, on, $, esc } from '../core/dom.js';
import { store } from '../core/store.js';
import { go } from '../core/router.js';
import { fmtTime } from '../core/format.js';
import { icon } from './icons.js';
import { logoMark } from './logo.js';
import { togglePopover, closePopover, openDialog, toast } from './overlays.js';
import { sevBadge } from './security.js';
import { flows, flagged } from '../data/index.js';

export const NAV = [
  { group: 'Analyse', items: [
    { id: 'overview', label: 'Overview', icon: 'overview' },
    { id: 'network', label: 'Network Traffic', icon: 'network' },
    { id: 'threats', label: 'Threat Detection', icon: 'threat', count: 'open' },
    { id: 'explorer', label: 'Event Explorer', icon: 'explorer' },
  ] },
  { group: 'Intelligence', items: [
    { id: 'models', label: 'ML Models', icon: 'models' },
    { id: 'dataset', label: 'Dataset Analysis', icon: 'dataset' },
  ] },
  { group: 'Output', items: [
    { id: 'reports', label: 'Reports', icon: 'reports' },
    { id: 'settings', label: 'Settings', icon: 'settings' },
  ] },
];

export const navLabel = (id) => NAV.flatMap((g) => g.items).find((i) => i.id === id)?.label || 'Overview';

const openCount = () => flagged().filter((f) => (f.severity === 'critical' || f.severity === 'high') && (f.status === 'New' || f.status === 'Triaging')).length;

export function renderRail(active) {
  const rail = $('#rail');
  mount(rail, html`
    <a class="brand" href="#overview" aria-label="MAVIS home">
      ${logoMark()}
      <span class="brand-text"><span class="brand-name">MAVIS</span><span class="brand-sub">Multi-Attack Vector Intelligence</span></span>
    </a>
    <nav class="nav">
      ${NAV.map((g) => html`
        <div class="nav-group-label">${g.group}</div>
        ${g.items.map((it) => html`
          <a class="nav-link" href="#${it.id}" ${active === it.id ? html`aria-current="page"` : ''} title="${it.label}">
            ${icon(it.icon)}<span class="nav-label">${it.label}</span>
            ${it.count === 'open' ? html`<span class="nav-count" data-tone="critical" title="Open high and critical sample events">${openCount()}</span>` : ''}
          </a>`)}`)}
    </nav>
    <div class="rail-foot">
      <div class="rail-source">
        <div class="rail-source-row" title="Dataset profile: measured"><span class="live-dot" data-state="real"></span><span class="rail-source-text">Dataset profile · measured</span></div>
        <div class="rail-source-row" title="Detections: sample data"><span class="live-dot" data-state="sample"></span><span class="rail-source-text">Detections · sample data</span></div>
        <div class="rail-source-row" title="Live capture: not connected"><span class="live-dot" data-state="off"></span><span class="rail-source-text">Live capture · not connected</span></div>
      </div>
    </div>`);
}

export function renderTopbar(active, crumb) {
  const unread = notifications().filter((n) => !store.isRead(n.id)).length;
  mount($('#topbar'), html`
    <button class="icon-btn menu-btn" data-action="open-nav" aria-label="Open navigation" aria-controls="rail">${icon('menu')}</button>
    <button class="icon-btn collapse-btn" data-action="toggle-rail" aria-label="${store.prefs.rail === 'collapsed' ? 'Expand' : 'Collapse'} sidebar" title="Toggle sidebar">${icon('collapse')}</button>
    <nav class="crumbs" aria-label="Breadcrumb">
      <span class="crumb-root">MAVIS</span><span class="crumb-sep" aria-hidden="true">/</span>
      <span ${crumb ? '' : html`aria-current="page"`}>${navLabel(active)}</span>
      ${crumb ? html`<span aria-hidden="true">/</span><span aria-current="page" class="mono">${crumb}</span>` : ''}
    </nav>
    <div class="topbar-spacer"></div>
    <div class="search global-search" style="flex:0 1 300px">
      ${icon('search')}
      <input class="input" id="global-search" type="search" placeholder="Search flows, IPs, labels" aria-label="Search flows, IP addresses and labels" autocomplete="off" role="combobox" aria-expanded="false" aria-controls="search-results">
      <kbd aria-hidden="true">/</kbd>
    </div>
    <div class="topbar-actions">
      <button class="icon-btn" data-action="notifications" aria-haspopup="true" aria-expanded="false" aria-label="Notifications, ${unread} unread">${icon('bell')}${unread ? html`<span class="badge-dot">${unread}</span>` : ''}</button>
      <button class="icon-btn" data-action="profile" aria-haspopup="menu" aria-expanded="false" aria-label="Profile menu">${icon('user')}</button>
    </div>`);
}

export function renderProvenance() {
  mount($('#provenance'), html`
    <span class="prov-item"><span class="prov-key">Mode</span><b>Dataset analysis</b></span>
    <span class="prov-item"><span class="live-dot" data-state="real"></span>CIC-IDS2017 profile <span class="prov-optional">· 8 files measured</span></span>
    <span class="prov-item"><span class="live-dot" data-state="sample"></span>Detection results are <b>sample data</b></span>
    <span class="prov-item prov-optional"><span class="live-dot" data-state="off"></span>Live capture not connected</span>`);
}

/* ---------- Notifications: sample high/critical events awaiting triage ---------- */
function notifications() {
  return flagged()
    .filter((f) => (f.severity === 'critical' || (store.prefs.notifyHigh && f.severity === 'high')) && f.status === 'New')
    .filter((f) => store.prefs.notifyCritical || f.severity !== 'critical')
    .sort((a, b) => b.ts.localeCompare(a.ts))
    .slice(0, 8);
}

function notificationsPanel() {
  const list = notifications();
  return html`
    <div class="menu-head" style="display:flex;justify-content:space-between;align-items:center;gap:8px">
      <span>Awaiting triage <span class="tag tag-sample" style="margin-left:6px">Sample</span></span>
      ${list.length ? html`<button class="btn btn-ghost btn-sm" data-action="mark-read">Mark all read</button>` : ''}
    </div>
    ${list.length ? list.map((f) => html`
      <button class="menu-item notif ${store.isRead(f.id) ? 'is-read' : ''}" data-open-flow="${f.id}">
        <span style="display:grid;gap:2px;min-width:0;flex:1">
          <span style="display:flex;gap:8px;align-items:center;justify-content:space-between">${sevBadge(f.severity)}<span class="mono" style="font-size:11px;color:var(--ink-3)">${fmtTime(f.ts)}</span></span>
          <span style="font-size:12.5px;color:var(--ink-2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${f.id} · ${f.src.ip} → ${f.dst.ip}:${f.dst.port}</span>
        </span>
      </button>`) : html`<div class="empty" style="padding:20px">${icon('check')}<div class="empty-title">Nothing waiting</div><p>New critical and high events will be listed here.</p></div>`}
    <div class="menu-sep"></div>
    <button class="menu-item" data-go="settings">${icon('settings')}Notification preferences</button>`;
}

/* ---------- Global search ---------- */
function searchResults(q) {
  const s = q.trim().toLowerCase();
  if (!s) return [];
  const pages = NAV.flatMap((g) => g.items).filter((i) => i.label.toLowerCase().includes(s)).map((i) => ({ kind: 'page', id: i.id, label: i.label }));
  const hits = flows().filter((f) =>
    f.id.toLowerCase().includes(s) || f.src.ip.includes(s) || f.dst.ip.includes(s) || f.label.toLowerCase().includes(s) || f.service.toLowerCase() === s)
    .sort((a, b) => b.agree - a.agree)
    .slice(0, 7)
    .map((f) => ({ kind: 'flow', id: f.id, label: `${f.id} · ${f.src.ip} → ${f.dst.ip}:${f.dst.port}`, flow: f }));
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
    togglePopover(btn, notificationsPanel(), { width: 360, role: 'dialog', onMount: (el) => {
      on(el, 'click', '[data-open-flow]', (_ev, b) => { store.markRead([b.dataset.openFlow]); closePopover(); go('explorer', b.dataset.openFlow); });
      on(el, 'click', '[data-action="mark-read"]', () => { store.markRead(notifications().map((n) => n.id)); closePopover(); toast('Notifications marked as read'); });
      on(el, 'click', '[data-go]', (_ev, b) => { closePopover(); go(b.dataset.go); });
    } });
  });

  on(document, 'click', '[data-action="profile"]', (_e, btn) => {
    togglePopover(btn, html`
      <div class="menu-head"><div style="color:var(--ink-1);font-weight:600;font-size:var(--fs-sm)">Local analyst</div>No sign-in. This is a frontend preview.</div>
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
      </div>`)}<div class="menu-head" style="border-top:1px solid var(--line);margin-top:4px">Searching sample flows by ID, IP address, label or service</div>`
      : html`<div class="menu-head">No flows match “${esc(input.value)}”. Try an IP such as 203.0.113.73 or a label such as PortScan.</div>`);
    input.setAttribute('aria-expanded', 'true');
    input.setAttribute('aria-activedescendant', activeIdx >= 0 ? `sr-${activeIdx}` : '');
  };
  on(document, 'input', '#global-search', (_e, input) => { activeIdx = -1; paint(input); });
  on(document, 'keydown', '#global-search', (ev, input) => {
    if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
      if (!results.length) return;
      activeIdx = ev.key === 'ArrowDown' ? (activeIdx + 1) % results.length : (activeIdx - 1 + results.length) % results.length;
      paint(input); ev.preventDefault();
    } else if (ev.key === 'Enter' && results.length) {
      choose(results[Math.max(0, activeIdx)]);
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
        <dt><kbd class="mono">/</kbd></dt><dd>Search flows, IPs and labels</dd>
        <dt><kbd class="mono">↑ ↓</kbd> then <kbd class="mono">Enter</kbd></dt><dd>Pick a search result or menu item</dd>
        <dt><kbd class="mono">Enter</kbd> on a row</dt><dd>Open the flow</dd>
        <dt><kbd class="mono">Esc</kbd></dt><dd>Close menus, drawers and dialogs</dd>
      </dl>
    </div>
    <div class="dialog-foot"><button class="btn btn-primary" data-close data-autofocus>Done</button></div>`, { label: 'Keyboard shortcuts' });
}
