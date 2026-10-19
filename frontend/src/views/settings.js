// Settings: appearance, density, motion, sound, learning target and the response policy.
// Preferences are stored in this browser; response settings are stored by the local server.
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { toast, confirmDialog } from '../components/overlays.js';
import { enableSound, beep } from '../components/alarm.js';
import { fmtTime } from '../core/format.js';
import { apiAvailable, responseConfig, updateResponseConfig, responseAudit, blocks, unblockIp } from '../data/index.js';
import { pageHead } from './common.js';

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
    ${radios('resp-mode', 'Response mode', c.mode, [['suggest', 'Suggest', 'Recommend actions, never act'], ['approve', 'Approve', 'Queue blocks for an analyst'], ['auto', 'Auto', 'Act automatically by severity']])}
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
  if (!box) return;
  if (!(await apiAvailable())) { mount(box, html`<p class="panel-meta">Needs the local server: <code>.venv/bin/python scripts/serve.py</code>.</p>`); return; }
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
      <td class="mono">${x.ip}</td><td class="muted wrap">${x.reason}</td><td>${x.status}${x.error ? html` <span class="field-error">${x.error}</span>` : ''}</td>
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

function render(root) {
  const p = store.prefs;
  mount(root, html`
    ${pageHead({ title: 'Settings', sub: 'Display preferences stay in this browser. Response settings are stored by the local server.' })}
    <div class="settings">
      ${group('Appearance', 'How the console looks.', html`
        ${radios('appearance', 'Theme', p.appearance, [['light', 'Light', 'Paper surfaces, the default'], ['dark', 'Dark', 'Low light and night shifts'], ['system', 'System', 'Follow the device setting']])}
        ${radios('density', 'Row density', p.density, [['comfortable', 'Comfortable', '40px rows'], ['compact', 'Compact', '32px rows']])}
        ${radios('motion', 'Motion', p.motion, [['system', 'Follow device', 'Respects reduced-motion'], ['reduced', 'Reduced', 'No flashing banner, no moving particles']])}`)}
      ${group('Alarm sound', 'A two-tone beep every 5 seconds while an attack is active and not acknowledged.', html`
        ${toggle('sound', 'Sound', 'Same switch as the top bar. Browsers need one click to start audio.', p.sound)}
        <div><button class="btn btn-sm" data-beep>Test the beep</button></div>`)}
      ${group('Learning', 'How much normal traffic to collect when you press Start learning on the Overview.', html`
        <div class="field set-field" style="max-width:220px"><label class="field-label" for="pref-learn">Target flows</label>
          <input class="input" id="pref-learn" type="number" min="50" max="20000" step="50" value="${p.learnTarget}" data-pref-num="learnTarget">
          <span class="field-hint">Learning applies automatically at this target.</span></div>`)}
      ${group('Response', 'What MAVIS may do about an attacking address. Needs the local server.', html`<div id="resp-box"><p class="panel-meta">Loading...</p></div>`)}
      ${group('Blocks & audit', 'Blocks in force and the log of every response decision.', html`<div id="audit-box"></div>`)}
      ${group('Reset', 'Return every display preference to its default.', html`<div><button class="btn" data-action="reset">Reset preferences</button></div>`)}
    </div>`);
  loadResponse(root);
  bindResponse(root);
  const saved = (label) => toast(`${label} saved`);
  on(root, 'change', '[data-pref]', (_e, i) => { store.setPref(i.name, i.value); saved('Preference'); });
  on(root, 'change', '[data-pref-bool]', (_e, i) => {
    if (i.dataset.prefBool === 'sound' && i.checked && !enableSound()) { i.checked = false; toast('This browser blocked audio', { tone: 'error' }); return; }
    store.setPref(i.dataset.prefBool, i.checked);
    if (i.dataset.prefBool === 'sound' && i.checked) beep();
    saved('Preference');
  });
  on(root, 'change', '[data-pref-num]', (_e, i) => { store.setPref(i.dataset.prefNum, Math.max(50, Math.min(20000, +i.value || 400))); saved('Learning target'); });
  on(root, 'click', '[data-beep]', () => { if (enableSound()) beep(); else toast('This browser blocked audio', { tone: 'error' }); });
  on(root, 'click', '[data-action="reset"]', async () => {
    if (!(await confirmDialog({ title: 'Reset all preferences?', body: 'Theme, density, motion, sound and learning target go back to their defaults.', confirmLabel: 'Reset preferences' }))) return;
    store.resetPrefs();
    toast('Preferences reset');
    const fresh = document.createElement('div');
    fresh.className = root.className;
    root.replaceWith(fresh);   // new element so delegated listeners never stack
    render(fresh);
  });
}

export default { title: 'Settings', render };
