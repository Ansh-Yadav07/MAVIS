// Settings: viewer preferences only. They are stored in this browser.
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { toast, confirmDialog } from '../components/overlays.js';
import { fmtPct, fmtInt } from '../core/format.js';
import { snapshot, engine, budgets, currentBudget, captures, apiAvailable, responseConfig, updateResponseConfig, responseAudit, blocks, unblockIp } from '../data/index.js';
import { fmtTime } from '../core/format.js';
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

const SEVS = ['critical', 'high', 'medium', 'low'];
const FAMILIES = ['BruteForce', 'PortScan', 'WebAttack', 'DoS', 'Bot', 'Infiltration'];

function responseForm(c) {
  const a = c.autoRules || {};
  return html`
    ${radios('resp-mode', 'Mode', c.mode, [['suggest', 'Suggest', 'Recommend blocks, never act'], ['approve', 'Approve', 'Queue blocks for an analyst'], ['auto', 'Auto', 'Block automatically when auto-rules match']])}
    <div class="field set-field" style="max-width:320px"><label class="field-label" for="resp-backend">Backend</label>
      <select class="select" id="resp-backend">${[['dry-run', 'Dry-run (records only)'], ['pf', 'pf (macOS firewall)'], ['nftables', 'nftables (Linux)'], ['cloudflare', 'Cloudflare IP Access Rules']].map(([v, l]) => html`<option value="${v}" ${c.backend === v ? html`selected` : ''}>${l}</option>`)}</select>
      <div class="resp-warn" id="resp-warn" ${c.backend === 'dry-run' ? 'hidden' : ''}>This backend changes real firewall rules. Check the allowlist first: a wrong block can cut you off from your own network.</div></div>
    <div class="resp-grid">
      <div class="field"><label class="field-label" for="resp-ttl">Block duration (minutes)</label><input class="input" id="resp-ttl" type="number" min="1" max="10080" value="${c.ttlMinutes}"></div>
      <div class="field"><label class="field-label" for="resp-max">Max blocks per minute</label><input class="input" id="resp-max" type="number" min="1" max="100" value="${c.maxBlocksPerMinute}"></div>
      <div class="field"><label class="field-label" for="resp-sev">Auto: minimum severity</label><select class="select" id="resp-sev">${SEVS.map((v) => html`<option ${a.minSeverity === v ? html`selected` : ''}>${v}</option>`)}</select></div>
      <div class="field"><label class="field-label" for="resp-conf">Auto: minimum confidence</label><select class="select" id="resp-conf">${['high', 'medium', 'low'].map((v) => html`<option ${a.minConfidence === v ? html`selected` : ''}>${v}</option>`)}</select></div>
      <div class="field"><label class="field-label" for="resp-votes">Auto: minimum detector votes</label><input class="input" id="resp-votes" type="number" min="1" max="4" value="${a.minVotes ?? 2}"></div>
    </div>
    <fieldset class="set-field"><legend class="field-label">Auto-block these attack types</legend>
      <div class="chips-inline">${FAMILIES.map((f) => html`<label class="chip" style="gap:6px"><input type="checkbox" data-resp-family="${f}" ${(a.families || []).includes(f) ? html`checked` : ''}>${f}</label>`)}</div>
      <span class="field-hint">Novel (unrecognised) alerts are never auto-blocked. Distributed attacks are never blocked per IP.</span></fieldset>
    <div class="field"><label class="field-label" for="resp-allow">Allowlist (one address or CIDR per line)</label>
      <textarea class="textarea" id="resp-allow" rows="4" spellcheck="false">${(c.allowlist || []).join('\n')}</textarea>
      <span class="field-hint">Never blocked, whatever the engine says. Loopback and this machine are always protected.</span></div>
    <div><button class="btn btn-primary" data-resp-save>Save response settings</button></div>`;
}

async function loadResponse(root) {
  const box = $('#resp-box', root);
  const audBox = $('#audit-box', root);
  if (!box) return;
  if (!(await apiAvailable())) {
    const msg = html`<p class="panel-meta">Blocking needs the local server: <code>.venv/bin/python scripts/serve.py</code>. The static site cannot change response settings.</p>`;
    mount(box, msg); if (audBox) mount(audBox, msg);
    return;
  }
  try {
    const cfg = await responseConfig();
    mount(box, responseForm(cfg.config || cfg));
  } catch (e) { mount(box, html`<p class="field-error">Could not load response settings: ${e.message}</p>`); }
  await loadBlocks(root);
}

async function loadBlocks(root) {
  const audBox = $('#audit-box', root);
  if (!audBox) return;
  const [b, a] = await Promise.all([blocks(), responseAudit()]);
  const list = [...(b.blocks || []), ...(b.pending || [])];
  const audit = (a.audit || a.entries || []).slice(-60).reverse();
  mount(audBox, html`
    <h3 class="field-label">Active and pending blocks</h3>
    ${list.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>IP</th><th>Reason</th><th>Status</th><th>Expires</th><th></th></tr></thead><tbody>${list.map((x) => html`<tr>
      <td class="mono">${x.ip}</td><td class="muted" style="white-space:normal">${x.reason}</td><td>${x.status}${x.error ? html` <span class="field-error">${x.error}</span>` : ''}</td>
      <td class="mono muted">${x.expiresAt ? fmtTime(x.expiresAt, { date: false }) : ''}</td><td class="r"><button class="btn btn-sm" data-resp-unblock="${x.ip}">Unblock</button></td></tr>`)}</tbody></table></div>` : html`<p class="panel-meta">No blocks.</p>`}
    <h3 class="field-label" style="margin-top:12px">Recent audit entries</h3>
    ${audit.length ? html`<div class="audit-list">${audit.map((e) => html`<div>${typeof e === 'string' ? e : `${e.ts ? fmtTime(e.ts, { date: false }) : ''} ${e.event || e.action || ''} ${e.ip || ''} ${e.detail || e.reason || ''}`}</div>`)}</div>` : html`<p class="panel-meta">No audit entries yet.</p>`}`);
}

function bindResponse(root) {
  on(root, 'change', '#resp-backend', (_e, s) => { $('#resp-warn', root).hidden = s.value === 'dry-run'; });
  on(root, 'click', '[data-resp-save]', async (_e, btn) => {
    const num = (id) => +$(id, root).value;
    const mode = root.querySelector('[name="resp-mode"]:checked')?.value;
    const backend = $('#resp-backend', root).value;
    if (backend !== 'dry-run' && !(await confirmDialog({ title: `Use the ${backend} backend?`, body: 'Blocks will change real firewall rules. Make sure the allowlist covers your gateway and your own addresses.', confirmLabel: 'Save', tone: 'danger' }))) return;
    btn.disabled = true;
    try {
      await updateResponseConfig({
        mode, backend, ttlMinutes: num('#resp-ttl'), maxBlocksPerMinute: num('#resp-max'),
        allowlist: $('#resp-allow', root).value.split('\n').map((x) => x.trim()).filter(Boolean),
        autoRules: { minSeverity: $('#resp-sev', root).value, minConfidence: $('#resp-conf', root).value, minVotes: num('#resp-votes'),
          families: [...root.querySelectorAll('[data-resp-family]:checked')].map((i) => i.dataset.respFamily) },
      });
      toast('Response settings saved');
    } catch (e) { toast(`Not saved: ${e.message}`, { tone: 'error' }); }
    btn.disabled = false;
  });
  on(root, 'click', '[data-resp-unblock]', async (_e, b) => {
    try { await unblockIp(b.dataset.respUnblock); toast(`${b.dataset.respUnblock} unblocked`); await loadBlocks(root); } catch (e) { toast(e.message, { tone: 'error' }); }
  });
}

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
        ${group('Response', 'What MAVIS may do about an attacking address. Applies to live mode and needs the local server.', html`<div id="resp-box"><p class="panel-meta">Loading…</p></div>`)}
        ${group('Blocks & audit', 'Blocks in force and the log of every response decision.', html`<div id="audit-box"></div>`)}
        ${group('About this engine', 'What produced the numbers in this console.', about())}
        ${group('Reset', 'Return every preference to its default.', html`<div><button class="btn" data-action="reset">Reset preferences</button></div>`)}
      </div>`);

    loadResponse(root);
    bindResponse(root);
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
