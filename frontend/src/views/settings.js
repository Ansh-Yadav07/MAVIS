// Settings: viewer preferences only. They are stored in this browser.
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { toast, confirmDialog } from '../components/overlays.js';
import { fmtPct, fmtInt } from '../core/format.js';
import { snapshot, engine, budgets, currentBudget, captures } from '../data/index.js';
import { pageHead, remount } from './common.js';

const group = (title, desc, body) => html`
  <section class="set-group" aria-labelledby="sg-${title.replace(/\W/g, '')}">
    <div class="set-intro"><h2 class="panel-title" id="sg-${title.replace(/\W/g, '')}">${title}</h2><p class="panel-meta">${desc}</p></div>
    <div class="set-body">${body}</div>
  </section>`;

const radios = (name, label, value, options) => html`
  <fieldset class="set-field"><legend class="field-label">${label}</legend>
    <div class="radio-cards">${options.map(([v, l, d]) => html`
      <label class="radio-card"><input type="radio" name="${name}" value="${v}" ${value === v ? html`checked` : ''} data-pref="${name}"><span><b>${l}</b>${d ? html`<span>${d}</span>` : ''}</span></label>`)}</div>
  </fieldset>`;

const toggle = (key, label, desc, on_) => html`
  <label class="switch-row" for="pref-${key}">
    <span><b>${label}</b><span class="panel-meta">${desc}</span></span>
    <input class="switch" type="checkbox" role="switch" id="pref-${key}" data-pref-bool="${key}" ${on_ ? html`checked` : ''}>
  </label>`;

function about() {
  const snap = snapshot(), e = engine();
  const gen = snap?.generated ? new Date(snap.generated).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : 'unknown';
  const uploads = captures().filter((c) => c.upload).length;
  return html`
    <dl class="kv">
      <dt>Alert budget (default)</dt><dd class="mono">${fmtPct(e.alertBudgetFpr, 2)} <span class="muted">false alerts on benign calibration flows</span></dd>
      <dt>Known-attack threshold</dt><dd class="mono">attack probability ≥ ${e.thresholds.known.toFixed(3)}</dd>
      <dt>Novel threshold</dt><dd class="mono">anomaly percentile ≥ ${e.thresholds.novel.toFixed(5)}</dd>
      <dt>Detector vote</dt><dd class="mono">above the ${fmtPct(e.votePercentile, 0)} benign percentile</dd>
      <dt>Features</dt><dd class="mono">${fmtInt(e.features.length)}</dd>
      <dt>Attack classes</dt><dd>${e.classes.filter((c) => c !== 'Benign').join(', ')}</dd>
      <dt>Snapshot date</dt><dd class="mono">${gen}</dd>
      <dt>Source</dt><dd>${snap?.source || 'n/a'}</dd>
      <dt>Captures loaded</dt><dd class="mono">${captures().length - uploads} files${uploads ? ` + ${uploads} upload${uploads === 1 ? '' : 's'} (this session only)` : ''}</dd>
      <dt>Regenerate</dt><dd><code>python scripts/export_frontend.py</code> <span class="muted">after <code>python scripts/build_engine.py</code>; writes <code>frontend/data/mavis.json</code></span></dd>
      <dt>Live analysis</dt><dd><code>python scripts/serve.py</code> <span class="muted">then open http://localhost:8000</span></dd>
    </dl>`;
}

export default {
  title: 'Settings',
  render(root) {
    const p = store.prefs;
    mount(root, html`
      ${pageHead({ title: 'Settings', sub: 'Preferences are stored in this browser only. MAVIS has no accounts, so nothing here is shared.' })}
      <div class="settings">
        ${group('Appearance', 'How the console looks.', html`
          ${radios('appearance', 'Theme', p.appearance, [['light', 'Light', 'Paper surfaces, the default'], ['dark', 'Dark', 'Low light and night shifts'], ['system', 'System', 'Follow the device setting']])}
          ${radios('motion', 'Motion', p.motion, [['system', 'Follow device', 'Respects reduced-motion'], ['reduced', 'Reduced', 'Turn off animation']])}`)}
        ${group('Tables', 'Density and paging for event tables.', html`
          ${radios('density', 'Row density', p.density, [['comfortable', 'Comfortable', '40px rows'], ['compact', 'Compact', '32px rows']])}
          <div class="field set-field" style="max-width:220px"><label class="field-label" for="pref-page">Rows per page</label>
            <select class="select" id="pref-page" data-pref-num="pageSize">${[10, 25, 50, 100].map((n) => html`<option value="${n}" ${p.pageSize === n ? html`selected` : ''}>${n}</option>`)}</select></div>`)}
        ${group('Alert budget', 'How many false alerts you accept on benign traffic.', html`
          <div class="field set-field" style="max-width:320px"><label class="field-label" for="pref-budget">False-positive budget</label>
            <select class="select" id="pref-budget">${budgets().map((b) => html`<option value="${b}" ${currentBudget() === b ? html`selected` : ''}>${fmtPct(b, b < 0.01 ? 2 : 1)}${b === engine().alertBudgetFpr ? ' (engine default)' : ''}</option>`)}</select>
            <span class="field-hint">Same setting as the top bar. A lower budget means fewer alerts and more missed attacks. The engine’s calibrated thresholds for each budget are re-applied to the exported flows; no model is re-run. Full-capture totals stay at the default budget.</span></div>`)}
        ${group('Charts', 'Chart display.', toggle('chartGrid', 'Grid lines', 'Faint horizontal guides behind charts', p.chartGrid))}
        ${group('Notifications', 'Which alerts appear in the bell menu.', html`
          ${toggle('notifyCritical', 'Critical events', 'Critical alerts from the exported sample', p.notifyCritical)}
          ${toggle('notifyHigh', 'High events', 'High alerts from the exported sample', p.notifyHigh)}
          <p class="panel-meta">Notifications are in-app only. MAVIS does not send email or push messages.</p>`)}
        ${group('About this engine', 'What produced the numbers in this console.', about())}
        ${group('Reset', 'Return every preference to its default.', html`<div><button class="btn" data-action="reset">Reset preferences</button></div>`)}
      </div>`);

    const saved = (label) => toast(`${label} saved`);
    on(root, 'change', '[data-pref]', (_e, i) => { store.setPref(i.name, i.value); saved('Preference'); });
    on(root, 'change', '[data-pref-bool]', (_e, i) => { store.setPref(i.dataset.prefBool, i.checked); saved(i.closest('label').querySelector('b').textContent); });
    on(root, 'change', '#pref-budget', (_e, sel) => { store.setPref('alertBudget', +sel.value === engine().alertBudgetFpr ? null : +sel.value); saved('Alert budget'); });
    on(root, 'change', '[data-pref-num]', (_e, s) => { store.setPref(s.dataset.prefNum, +s.value); saved('Rows per page'); });
    on(root, 'click', '[data-action="reset"]', async () => {
      const ok = await confirmDialog({ title: 'Reset all preferences?', body: 'Theme, motion, density, alert budget, charts and notification choices go back to their defaults. Your notes and event statuses are kept.', confirmLabel: 'Reset preferences' });
      if (!ok) return;
      store.resetPrefs();
      toast('Preferences reset');
      remount(this, root);
    });
    return store.subscribe((ev) => {
      if (ev.type === 'pref' && (ev.key === 'alertBudget' || ev.key === '*')) { const sel = $('#pref-budget', root); if (sel) sel.value = String(currentBudget()); }
    });
  },
};
