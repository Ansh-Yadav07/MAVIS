// Settings: viewer preferences only. They are stored in this browser.
import { html, mount, on } from '../core/dom.js';
import { store } from '../core/store.js';
import { toast, confirmDialog } from '../components/overlays.js';
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

export default {
  title: 'Settings',
  render(root) {
    const p = store.prefs;
    mount(root, html`
      ${pageHead({ title: 'Settings', sub: 'Display preferences for this browser. MAVIS has no accounts yet, so nothing here is shared.' })}
      <div class="settings">
        ${group('Appearance', 'How the console looks.', html`
          ${radios('appearance', 'Theme', p.appearance, [['dark', 'Dark', 'Default for analyst work'], ['light', 'Light', 'Bright rooms and review'], ['system', 'System', 'Follow the device setting']])}
          ${radios('motion', 'Motion', p.motion, [['system', 'Follow device', 'Respects reduced-motion'], ['reduced', 'Reduced', 'Turn off animation']])}`)}
        ${group('Tables', 'Density and paging for event tables.', html`
          ${radios('density', 'Row density', p.density, [['comfortable', 'Comfortable', '40px rows'], ['compact', 'Compact', '32px rows']])}
          <div class="field set-field" style="max-width:220px"><label class="field-label" for="pref-page">Rows per page</label>
            <select class="select" id="pref-page" data-pref-num="pageSize">${[10, 25, 50, 100].map((n) => html`<option value="${n}" ${p.pageSize === n ? html`selected` : ''}>${n}</option>`)}</select></div>`)}
        ${group('Charts', 'Chart display.', toggle('chartGrid', 'Grid lines', 'Faint horizontal guides behind charts', p.chartGrid))}
        ${group('Notifications', 'Which sample events appear in the bell menu.', html`
          ${toggle('notifyCritical', 'Critical events', 'All three detectors far past their cut-offs', p.notifyCritical)}
          ${toggle('notifyHigh', 'High events', 'Strong agreement between detectors', p.notifyHigh)}
          <p class="panel-meta">Notifications are in-app only. MAVIS does not send email or push messages.</p>`)}
        ${group('Reset', 'Return every preference to its default.', html`<div><button class="btn" data-action="reset">Reset preferences</button></div>`)}
      </div>`);

    const saved = (label) => toast(`${label} saved`);
    on(root, 'change', '[data-pref]', (_e, i) => { store.setPref(i.name, i.value); saved('Preference'); });
    on(root, 'change', '[data-pref-bool]', (_e, i) => { store.setPref(i.dataset.prefBool, i.checked); saved(i.closest('label').querySelector('b').textContent); });
    on(root, 'change', '[data-pref-num]', (_e, s) => { store.setPref(s.dataset.prefNum, +s.value); saved('Rows per page'); });
    on(root, 'click', '[data-action="reset"]', async () => {
      const ok = await confirmDialog({ title: 'Reset all preferences?', body: 'Theme, motion, table density, charts and notification choices go back to their defaults. Your notes and event statuses are kept.', confirmLabel: 'Reset preferences' });
      if (!ok) return;
      store.resetPrefs();
      toast('Preferences reset');
      remount(this, root);
    });
  },
};
