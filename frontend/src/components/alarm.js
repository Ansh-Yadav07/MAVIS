// Alarm system: a flashing banner while the server reports `under-attack`, an amber strip for
// `elevated`, a two-tone beep every 5 s (sound on, not acknowledged) and a title prefix.
// Browsers only allow audio after a user gesture, so the AudioContext is created from the
// "Sound" button click in the top bar (see enableSound).
import { html, mount, on, $ } from '../core/dom.js';
import { store } from '../core/store.js';
import { go } from '../core/router.js';
import { fmtInt } from '../core/format.js';
import { subscribeLive } from '../data/index.js';

let ctx = null;
let beepTimer = null;
let ackKey = null;          // `since` of the attack the analyst acknowledged
let baseTitle = 'MAVIS';
let lastSig = '';

const key = (s) => s.status?.since ?? 'now';
const topEpisode = (s) => [...(s.episodes || [])].filter((e) => e.state === 'active')
  .sort((a, b) => (b.flowsPerSec || 0) - (a.flowsPerSec || 0))[0];

export function enableSound() {
  try {
    ctx ||= new (window.AudioContext || window.webkitAudioContext)();
    ctx.resume?.();
    return true;
  } catch { return false; }
}

function tone(freq, start, dur) {
  const o = ctx.createOscillator(), g = ctx.createGain();
  o.type = 'square'; o.frequency.value = freq;
  g.gain.setValueAtTime(0.0001, ctx.currentTime + start);
  g.gain.exponentialRampToValueAtTime(0.12, ctx.currentTime + start + 0.01);
  g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + start + dur);
  o.connect(g); g.connect(ctx.destination);
  o.start(ctx.currentTime + start); o.stop(ctx.currentTime + start + dur + 0.02);
}
export function beep() {
  if (!ctx || ctx.state === 'closed') return;
  ctx.resume?.();
  tone(880, 0, 0.16); tone(660, 0.24, 0.16);
}

export function setBaseTitle(t) { baseTitle = t; applyTitle(); }
let attackActive = false;
function applyTitle() { document.title = attackActive ? `⚠ UNDER ATTACK · ${baseTitle}` : baseTitle; }

function banner(s) {
  const lvl = s.status?.level;
  if (lvl !== 'under-attack' && lvl !== 'elevated') return '';
  const ep = topEpisode(s);
  const under = lvl === 'under-attack';
  const acked = under && ackKey === key(s);
  const facts = [
    ep?.target ? html`<span>Target <b class="mono">${ep.target}</b></span>` : '',
    ep ? html`<span><b>${fmtInt(ep.sources || 0)}</b> source${ep.sources === 1 ? '' : 's'}</span><span><b>${fmtInt(ep.flowsPerSec || 0)}</b> flows/s</span>` : html`<span><b>${(s.status.alertsPerSec || 0).toFixed(1)}</b> alerts/s</span>`,
  ];
  return html`<div class="alarm" data-level="${lvl}" data-ack="${acked}" role="alert">
    <div class="alarm-main"><b class="alarm-title">${under ? 'UNDER ATTACK' : 'Elevated threat'}</b>
      <span class="alarm-headline">${s.status.headline || ep?.title || ''}</span>
      <span class="alarm-facts">${facts}</span></div>
    <div class="alarm-actions"><button class="btn btn-sm" data-alarm="view">View attack</button>
      ${under && !acked ? html`<button class="btn btn-sm" data-alarm="ack">Acknowledge</button>` : ''}</div>
  </div>`;
}

function update(s) {
  const host = $('#alarm');
  const under = s.status?.level === 'under-attack';
  attackActive = under;
  applyTitle();
  const sig = JSON.stringify([s.status?.level, s.status?.since, s.status?.headline, topEpisode(s)?.sources, Math.round((topEpisode(s)?.flowsPerSec || 0) / 5), ackKey]);
  if (host && sig !== lastSig) { lastSig = sig; mount(host, banner(s)); }
  const shouldBeep = under && ackKey !== key(s) && store.prefs.sound && ctx;
  if (shouldBeep && !beepTimer) { beep(); beepTimer = setInterval(beep, 5000); }
  if (!shouldBeep && beepTimer) { clearInterval(beepTimer); beepTimer = null; }
}

export function initAlarm() {
  const host = $('#alarm');
  let latest = null;
  on(host, 'click', '[data-alarm]', (_e, b) => {
    if (b.dataset.alarm === 'view') go('graph');
    else { ackKey = key(latest); lastSig = ''; update(latest); }
  });
  store.subscribe((ev) => { if (ev.type === 'pref' && latest) update(latest); });
  return subscribeLive((s) => { latest = s; update(s); });
}
