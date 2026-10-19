// App shell: navigation rail and top bar (breadcrumb, connection, sound toggle).
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { icon } from './icons.js';
import { logoMark } from './logo.js';
import { enableSound, beep } from './alarm.js';
import { toast } from './overlays.js';

export const NAV = [
  { id: 'overview', label: 'Overview', icon: 'overview' },
  { id: 'graph', label: 'Attack Graph', icon: 'graph', live: true },
  { id: 'alerts', label: 'Alerts', icon: 'threat', live: true },
  { id: 'incidents', label: 'Incidents', icon: 'investigations', live: true, count: 'incidents' },
  { id: 'hosts', label: 'Hosts', icon: 'hosts', live: true },
  { id: 'models', label: 'Models', icon: 'models' },
  { id: 'settings', label: 'Settings', icon: 'settings', live: true },
];

export const navLabel = (id) => NAV.find((i) => i.id === id)?.label || 'Overview';

let apiUp = false;
export const setApiUp = (v) => { apiUp = v; };

const items = () => NAV.filter((i) => apiUp || !i.live);

export function renderRail(active) {
  mount($('#rail'), html`
    <a class="brand" href="#overview" aria-label="MAVIS home">
      ${logoMark()}
      <span class="brand-text"><span class="brand-name">MAVIS</span><span class="brand-sub">Multi-Attack Vector Intelligence</span></span>
    </a>
    <nav class="nav" aria-label="Sections">
      ${items().map((it) => html`
        <a class="nav-link" href="#${it.id}" ${active === it.id ? html`aria-current="page"` : ''} title="${it.label}">
          ${icon(it.icon)}<span class="nav-label">${it.label}</span>
          ${it.count ? html`<span class="nav-count" data-count="${it.count}" data-tone="critical" hidden>0</span>` : ''}
        </a>`)}
    </nav>
    <div class="rail-foot" id="rail-foot"></div>`);
}

// Live bits of the chrome: incident badge, rail footer, top-bar connection pill.
let chromeSig = '';
let lastS = null;
export function refreshChrome(s) {
  lastS = s;
  const active = (s.episodes || []).filter((e) => e.state === 'active').length;
  const conn = apiUp && s.available;
  const sig = JSON.stringify([active, conn, s.sensor?.connected, (s.sensors || []).length, store.prefs.sound]);
  if (sig === chromeSig) return;
  chromeSig = sig;
  const badge = $('.nav-count[data-count="incidents"]');
  if (badge) { badge.textContent = active; badge.hidden = !active; }
  const sensors = (s.sensors || []).filter((x) => x.connected).length;
  const foot = $('#rail-foot');
  if (foot) mount(foot, html`<div class="rail-source">
    <div class="rail-source-row"><span class="live-dot" data-state="${conn ? 'real' : 'off'}"></span><span class="rail-source-text">${conn ? 'Local API connected' : apiUp ? 'API not reachable' : 'Static site, no API'}</span></div>
    ${apiUp ? html`<div class="rail-source-row"><span class="live-dot" data-state="${sensors ? 'real' : 'off'}"></span><span class="rail-source-text">${sensors} sensor${sensors === 1 ? '' : 's'} connected</span></div>` : ''}</div>`);
  const snd = $('#sound-btn');
  if (snd) { snd.setAttribute('aria-pressed', String(!!store.prefs.sound)); snd.innerHTML = soundInner(); }
}

const soundInner = () => `${icon(store.prefs.sound ? 'volume' : 'volumeOff').toString()}<span class="snd-label">${store.prefs.sound ? 'Sound on' : 'Sound off'}</span>`;

export function renderTopbar(active) {
  chromeSig = '';
  mount($('#topbar'), html`
    <button class="icon-btn menu-btn" data-action="open-nav" aria-label="Open navigation" aria-controls="rail">${icon('menu')}</button>
    <button class="icon-btn collapse-btn" data-action="toggle-rail" aria-label="${store.prefs.rail === 'collapsed' ? 'Expand' : 'Collapse'} sidebar" title="Toggle sidebar">${icon('collapse')}</button>
    <nav class="crumbs" aria-label="Breadcrumb"><span class="crumb-root">MAVIS</span><span class="crumb-sep" aria-hidden="true">/</span><span aria-current="page">${navLabel(active)}</span></nav>
    <div class="topbar-spacer"></div>
    ${apiUp ? html`<button class="btn btn-sm snd-btn" id="sound-btn" data-action="sound" aria-pressed="${!!store.prefs.sound}" title="Alarm beep while an attack is active">${icon(store.prefs.sound ? 'volume' : 'volumeOff')}<span class="snd-label">${store.prefs.sound ? 'Sound on' : 'Sound off'}</span></button>` : ''}`);
  if (lastS) queueMicrotask(() => refreshChrome(lastS));
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
  // The audio context must be created inside this click handler (browser autoplay rule).
  on(document, 'click', '[data-action="sound"]', () => {
    const next = !store.prefs.sound;
    if (next && !enableSound()) { toast('This browser blocked audio', { tone: 'error' }); return; }
    store.setPref('sound', next);
    if (next) beep();
    chromeSig = '';
    const btn = $('#sound-btn');
    if (btn) { btn.setAttribute('aria-pressed', String(next)); btn.innerHTML = soundInner(); }
  });
  // A remembered "sound on" still needs one gesture per page load before audio may start.
  document.addEventListener('pointerdown', () => { if (store.prefs.sound) enableSound(); }, { once: true });
  document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape' && app.dataset.mobileNav) delete app.dataset.mobileNav; });
}
