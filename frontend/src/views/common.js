// Small shared pieces for views: page header, provenance-aware panel, selectors over sample flows.
import { html } from '../core/dom.js';
import { DAYS } from '../data/index.js';
import { SEV_ORDER, SEV_LABEL } from '../components/security.js';

export const pageHead = ({ title, sub, actions = '' }) => html`
  <header class="page-head">
    <div class="page-head-text"><h1 class="page-title">${title}</h1>${sub ? html`<p class="page-sub">${sub}</p>` : ''}</div>
    ${actions ? html`<div class="page-actions">${actions}</div>` : ''}
  </header>`;

export const panel = ({ title, meta = '', tag = '', actions = '', body, cls = '', bodyCls = '', foot = '', id = '' }) => html`
  <section class="panel ${cls}" ${id ? html`id="${id}"` : ''} aria-label="${title}">
    <div class="panel-head"><h2 class="panel-title">${title}</h2>${tag}${meta ? html`<span class="panel-meta">${meta}</span>` : ''}<span class="spacer"></span>${actions}</div>
    <div class="panel-body ${bodyCls}">${body}</div>
    ${foot ? html`<div class="panel-foot">${foot}</div>` : ''}
  </section>`;

export const SEV_COLOR = {
  critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)', none: 'var(--sev-none)',
};

export function severityCounts(list) {
  const c = Object.fromEntries(SEV_ORDER.map((s) => [s, 0]));
  list.forEach((f) => { c[f.severity]++; });
  return c;
}

export const severityRows = (list, { includeNone = false } = {}) => {
  const c = severityCounts(list);
  return SEV_ORDER.filter((s) => includeNone || s !== 'none').map((s) => ({ label: SEV_LABEL[s], value: c[s], color: SEV_COLOR[s] }));
};

// Buckets for the activity chart: hourly across the week, or 20-minute slots for one day.
export function activityBuckets(list, dayId = null) {
  const out = [];
  const days = dayId ? DAYS.filter((d) => d.id === dayId) : DAYS;
  const slot = dayId ? 1 / 3 : 1;
  const xLabels = [];
  days.forEach((d) => {
    xLabels.push({ index: out.length, text: dayId ? '08:00' : d.label });
    for (let h = 8; h < 18; h += slot) {
      const hh = Math.floor(h), mm = Math.round((h - hh) * 60);
      out.push({ day: d.id, h0: h, h1: h + slot, total: 0, flagged: 0,
        title: `${d.label} · ${String(hh).padStart(2, '0')}:${String(mm).padStart(2, '0')}–${String(Math.floor(h + slot)).padStart(2, '0')}:${String(Math.round(((h + slot) % 1) * 60)).padStart(2, '0')} UTC` });
    }
  });
  if (dayId) [10, 12, 14, 16].forEach((h) => xLabels.push({ index: (h - 8) * 3, text: `${h}:00` }));
  list.forEach((f) => {
    const t = new Date(f.ts);
    const hour = t.getUTCHours() + t.getUTCMinutes() / 60;
    const b = out.find((x) => x.day === f.day && hour >= x.h0 && hour < x.h1);
    if (!b) return;
    b.total++;
    if (f.agree > 0) b.flagged++;
  });
  return { buckets: out, xLabels };
}

export function agreementCombos(list) {
  const sets = [['if', 'lof', 'ae'], ['if', 'lof'], ['if', 'ae'], ['lof', 'ae'], ['if'], ['lof'], ['ae']];
  return sets.map((set) => ({
    set,
    count: list.filter((f) => ['if', 'lof', 'ae'].every((m) => f.flags[m] === set.includes(m))).length,
  }));
}

// Re-render a view into a fresh element so delegated listeners never stack up.
export function remount(view, root, param) {
  const fresh = document.createElement('div');
  fresh.className = root.className;
  root.replaceWith(fresh);
  view.render(fresh, param);
  return fresh;
}
