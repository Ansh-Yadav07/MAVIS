// Popover menus, drawer, dialog, toasts and the shared chart tooltip.
// All are keyboard accessible: Escape closes, focus is trapped in modal layers and restored after.
import { html, mount, esc, prefersReducedMotion } from '../core/dom.js';
import { icon } from './icons.js';

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function closeAnimated(el, done) {
  if (!el || !el.isConnected) { done?.(); return; }
  if (prefersReducedMotion()) { el.remove(); done?.(); return; }
  el.dataset.closing = '';
  el.addEventListener('animationend', () => { el.remove(); done?.(); }, { once: true });
  setTimeout(() => { if (el.isConnected) { el.remove(); done?.(); } }, 400);
}

function trapFocus(container, ev) {
  if (ev.key !== 'Tab') return;
  const items = Array.from(container.querySelectorAll(FOCUSABLE)).filter((e) => e.offsetParent !== null);
  if (!items.length) return;
  const first = items[0], last = items[items.length - 1];
  if (ev.shiftKey && document.activeElement === first) { last.focus(); ev.preventDefault(); }
  else if (!ev.shiftKey && document.activeElement === last) { first.focus(); ev.preventDefault(); }
}

/* ---------- Popover (menus, notification list) ---------- */
let openPop = null;

export function closePopover() {
  if (!openPop) return;
  const { el, trigger, cleanup } = openPop;
  openPop = null;
  cleanup();
  trigger.setAttribute('aria-expanded', 'false');
  closeAnimated(el);
}

export function togglePopover(trigger, content, { width, onMount, role = 'menu' } = {}) {
  if (openPop && openPop.trigger === trigger) { closePopover(); return; }
  closePopover();
  const el = document.createElement('div');
  el.className = 'popover';
  el.setAttribute('role', role);
  if (width) el.style.width = `${width}px`;
  mount(el, content);
  document.body.appendChild(el);

  const r = trigger.getBoundingClientRect();
  const w = el.offsetWidth;
  const left = Math.max(12, Math.min(window.innerWidth - w - 12, r.right - w));
  el.style.left = `${left}px`;
  el.style.top = `${r.bottom + 6 + window.scrollY}px`;
  trigger.setAttribute('aria-expanded', 'true');

  const onDoc = (ev) => { if (!el.contains(ev.target) && !trigger.contains(ev.target)) closePopover(); };
  const onKey = (ev) => {
    if (ev.key === 'Escape') { closePopover(); trigger.focus(); }
    if (role === 'menu' && (ev.key === 'ArrowDown' || ev.key === 'ArrowUp')) {
      const items = Array.from(el.querySelectorAll('.menu-item'));
      const i = items.indexOf(document.activeElement);
      const next = ev.key === 'ArrowDown' ? (i + 1) % items.length : (i - 1 + items.length) % items.length;
      items[next]?.focus();
      ev.preventDefault();
    }
  };
  setTimeout(() => document.addEventListener('click', onDoc), 0);
  document.addEventListener('keydown', onKey);
  const onResize = () => closePopover();
  window.addEventListener('resize', onResize);
  openPop = {
    el, trigger,
    cleanup: () => { document.removeEventListener('click', onDoc); document.removeEventListener('keydown', onKey); window.removeEventListener('resize', onResize); },
  };
  onMount?.(el);
  (el.querySelector('.menu-item') || el.querySelector(FOCUSABLE))?.focus({ preventScroll: true });
  return el;
}

/* ---------- Modal layers (drawer + dialog) ---------- */
function openModal(kind, build, { label, onClose } = {}) {
  const returnTo = document.activeElement;
  const scrim = document.createElement('div');
  scrim.className = 'scrim';
  const el = document.createElement(kind === 'drawer' ? 'aside' : 'div');
  el.className = kind;
  el.setAttribute('role', 'dialog');
  el.setAttribute('aria-modal', 'true');
  if (label) el.setAttribute('aria-label', label);

  const close = () => {
    document.removeEventListener('keydown', onKey);
    closeAnimated(scrim);
    closeAnimated(el, () => { onClose?.(); if (returnTo && returnTo.isConnected) returnTo.focus({ preventScroll: true }); });
    document.documentElement.style.overflow = '';
  };
  const onKey = (ev) => {
    if (ev.key === 'Escape') { ev.stopPropagation(); close(); }
    trapFocus(el, ev);
  };

  mount(el, build(close));
  scrim.addEventListener('click', close);
  el.addEventListener('click', (ev) => { if (ev.target.closest('[data-close]')) close(); });
  document.addEventListener('keydown', onKey);
  document.body.append(scrim, el);
  document.documentElement.style.overflow = 'hidden';
  (el.querySelector('[data-autofocus]') || el.querySelector(FOCUSABLE))?.focus({ preventScroll: true });
  return { el, close };
}

export const openDrawer = (build, opts) => openModal('drawer', build, opts);
export const openDialog = (build, opts) => openModal('dialog', build, opts);

// Confirmation built into the page (the viewer blocks native confirm()).
export function confirmDialog({ title, body, confirmLabel = 'Confirm', tone = '' }) {
  return new Promise((resolve) => {
    let result = false;
    openDialog((close) => html`
      <div class="dialog-head"><h2 class="panel-title" style="font-size:var(--fs-lg)">${title}</h2></div>
      <div class="dialog-body">${body}</div>
      <div class="dialog-foot">
        <button class="btn btn-ghost" data-close>Cancel</button>
        <button class="btn ${tone === 'danger' ? 'btn-danger' : 'btn-primary'}" data-confirm data-autofocus>${confirmLabel}</button>
      </div>`, { label: title, onClose: () => resolve(result) }).el
      .querySelector('[data-confirm]').addEventListener('click', (ev) => {
        result = true;
        ev.currentTarget.closest('.dialog').querySelector('[data-close]').click();
      });
  });
}

/* ---------- Toasts ---------- */
export function toast(message, { tone = 'ok', timeout = 3600 } = {}) {
  const region = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = 'toast';
  el.dataset.tone = tone;
  mount(el, html`${icon(tone === 'error' ? 'alert' : tone === 'warn' ? 'info' : 'check')}<div>${message}</div>`);
  region.appendChild(el);
  setTimeout(() => closeAnimated(el), timeout);
}

/* ---------- Tooltip (charts and dense UI) ---------- */
let tipEl = null;
export function showTip(x, y, content) {
  if (!tipEl) tipEl = document.getElementById('tooltip');
  mount(tipEl, content);
  tipEl.hidden = false;
  const w = tipEl.offsetWidth, h = tipEl.offsetHeight;
  let left = x + 14, top = y - h - 10;
  if (left + w > window.innerWidth - 8) left = x - w - 14;
  if (top < 8) top = y + 16;
  tipEl.style.left = `${Math.max(8, left)}px`;
  tipEl.style.top = `${top}px`;
}
export function hideTip() { if (tipEl) tipEl.hidden = true; }

// Charts attach data-tip='<json>' on hit targets; one listener serves the whole app.
export function installTooltips(root) {
  const fromEl = (el) => {
    try {
      const d = JSON.parse(el.dataset.tip);
      return html`<div class="tt-title">${d.t}</div>${(d.r || []).map(([label, value, color]) => html`<div class="tt-row"><span>${color ? html`<i class="swatch" style="background:${color}"></i>` : ''}${label}</span><b>${value}</b></div>`)}${d.n ? html`<div style="margin-top:6px;color:var(--ink-3)">${d.n}</div>` : ''}`;
    } catch { return esc(el.dataset.tip); }
  };
  root.addEventListener('pointermove', (ev) => {
    const el = ev.target.closest('[data-tip]');
    if (!el) { hideTip(); return; }
    showTip(ev.clientX, ev.clientY, fromEl(el));
  });
  root.addEventListener('pointerleave', hideTip);
  root.addEventListener('focusin', (ev) => {
    const el = ev.target.closest('[data-tip]');
    if (!el) return;
    const r = el.getBoundingClientRect();
    showTip(r.left + r.width / 2, r.top, fromEl(el));
  });
  root.addEventListener('focusout', hideTip);
  window.addEventListener('scroll', hideTip, { passive: true });
}

export const tip = (title, rows, note) => JSON.stringify({ t: title, r: rows, n: note });
