// MAVIS frontend entry: applies preferences, renders the shell, routes between views.
import { $, mount, prefersReducedMotion } from './core/dom.js';
import { store } from './core/store.js';
import { defineRoute, startRouter, currentRoute, render as rerender } from './core/router.js';
import { fmtInt } from './core/format.js';
import { renderRail, renderTopbar, renderProvenance, bindShell } from './components/shell.js';
import { installTooltips, closePopover } from './components/overlays.js';
import { errorState } from './components/states.js';

import overview from './views/overview.js';
import network from './views/network.js';
import threats from './views/threats.js';
import explorer from './views/explorer.js';
import models from './views/models.js';
import dataset from './views/dataset.js';
import reports from './views/reports.js';
import settings from './views/settings.js';

const VIEWS = { overview, network, threats, explorer, models, dataset, reports, settings };
Object.entries(VIEWS).forEach(([id, v]) => defineRoute(id, v));

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

// Count metrics up from zero on first paint. The final value is already in the DOM,
// so the page reads correctly even if this never runs.
function animateCounts(root) {
  if (prefersReducedMotion()) return;
  root.querySelectorAll('[data-count-to]').forEach((el) => {
    const target = +el.dataset.countTo;
    const textNode = el.firstChild;
    if (!textNode || textNode.nodeType !== 3 || !isFinite(target)) return;
    const final = textNode.textContent;
    const t0 = performance.now(), dur = 700;
    const step = (t) => {
      const k = Math.min(1, (t - t0) / dur);
      const e = 1 - Math.pow(1 - k, 3);
      textNode.textContent = k < 1 ? fmtInt(target * e) : final;
      if (k < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  });
}

let cleanup = null;

function show(route, view) {
  closePopover();
  cleanup?.();
  cleanup = null;
  const main = $('#main');
  renderRail(route.id);
  renderTopbar(route.id, view.crumb?.(route.param));
  document.title = route.id === 'overview' ? 'MAVIS' : `${view.title} · MAVIS`;
  main.classList.remove('view-enter');
  void main.offsetWidth;
  main.classList.add('view-enter');
  const host = document.createElement('div');
  host.className = 'view-host';
  main.replaceChildren(host);
  try {
    cleanup = view.render(host, route.param) || null;
  } catch (err) {
    console.error(err);
    mount(main, errorState({ text: `${err.message}. Reload the page; if it keeps happening, the sample data module may have failed to load.` }));
  }
  animateCounts(main);
  window.scrollTo({ top: 0, behavior: 'instant' in window ? 'instant' : 'auto' });
  if (document.activeElement && document.activeElement !== document.body && !main.contains(document.activeElement)) {
    main.focus({ preventScroll: true });
  }
}

applyPrefs();
renderProvenance();
installTooltips(document.body);
bindShell(() => { applyPrefs(); renderTopbar(currentRoute().id, VIEWS[currentRoute().id].crumb?.(currentRoute().param)); });

// Re-render the current view when analyst edits or prefs change something it shows.
store.subscribe((ev) => {
  if (ev.type === 'pref') applyPrefs();
  if (ev.type === 'edit' || ev.type === 'notes') {
    const r = currentRoute();
    renderRail(r.id);
    renderTopbar(r.id, VIEWS[r.id].crumb?.(r.param));
  }
});

startRouter(show);
export { rerender };
