// MAVIS frontend entry: applies preferences, renders the shell, routes between views.
import { $, html, mount } from './core/dom.js';
import { store } from './core/store.js';
import { defineRoute, startRouter, currentRoute, getRoutes } from './core/router.js';
import { renderRail, renderTopbar, bindShell, refreshChrome, setApiUp, NAV } from './components/shell.js';
import { initAlarm, setBaseTitle } from './components/alarm.js';
import { installTooltips } from './components/overlays.js';
import { errorState } from './components/states.js';
import { loadData, subscribeLive } from './data/index.js';

import overview from './views/overview.js';
import landing from './views/landing.js';
import graph from './views/graph.js';
import alerts from './views/alerts.js';
import incidents from './views/incidents.js';
import hosts from './views/hosts.js';
import models from './views/models.js';
import settings from './views/settings.js';

const VIEWS = { overview, graph, alerts, incidents, hosts, models, settings };
Object.entries(VIEWS).forEach(([id, v]) => defineRoute(id, v));

let apiUp = false;
const media = window.matchMedia('(prefers-color-scheme: light)');

function applyPrefs() {
  const p = store.prefs;
  const root = document.documentElement;
  root.dataset.appearance = p.appearance === 'system' ? (media.matches ? 'light' : 'dark') : p.appearance;
  root.dataset.density = p.density;
  if (p.motion === 'reduced') root.dataset.motion = 'reduced'; else delete root.dataset.motion;
  $('#app').dataset.rail = p.rail;
}
media.addEventListener?.('change', () => { if (store.prefs.appearance === 'system') applyPrefs(); });

let cleanup = null;

function show(route) {
  const live = NAV.find((i) => i.id === route.id)?.live;
  if (!apiUp && live) { location.hash = 'overview'; return; }   // no API: only the landing page and Models
  const view = route.id === 'overview' && !apiUp ? landing : getRoutes().get(route.id);
  cleanup?.();
  cleanup = null;
  const main = $('#main');
  renderRail(route.id);
  renderTopbar(route.id);
  setBaseTitle(route.id === 'overview' ? 'MAVIS' : `${view.title} · MAVIS`);
  main.classList.remove('view-enter');
  void main.offsetWidth;
  main.classList.add('view-enter');
  const host = document.createElement('div');
  host.className = 'view-host';
  main.replaceChildren(host);
  try {
    cleanup = view.render(host) || null;
  } catch (err) {
    console.error(err);
    mount(main, errorState({ text: `${err.message}. Reload the page; if it keeps happening, check the browser console.` }));
  }
  window.scrollTo({ top: 0, behavior: 'instant' in window ? 'instant' : 'auto' });
  if (document.activeElement && document.activeElement !== document.body && !main.contains(document.activeElement)) main.focus({ preventScroll: true });
}

async function boot() {
  applyPrefs();
  installTooltips(document.body);
  mount($('#main'), html`<div class="view-loading" role="status">Connecting...</div>`);
  try {
    apiUp = (await loadData()).api;
  } catch (err) {
    console.error(err);
    mount($('#main'), errorState({ title: 'Could not start the console', text: err.message }));
    return;
  }
  setApiUp(apiUp);
  bindShell(() => { applyPrefs(); renderTopbar(currentRoute().id); });
  store.subscribe((ev) => { if (ev.type === 'pref') applyPrefs(); });
  if (apiUp) {
    initAlarm();                                    // the alarm watches the live state on every page
    subscribeLive((s) => refreshChrome(s));
  }
  startRouter(show);
}

boot();
