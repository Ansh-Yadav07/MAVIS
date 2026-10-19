// Block-source control shared by the flow drawer and the investigation drawer.
// Only rendered when the local API is up (the caller checks apiAvailable()).
import { html, on, $ } from '../core/dom.js';
import { icon } from './icons.js';
import { toast, confirmDialog } from './overlays.js';
import { blockIp, unblockIp } from '../data/index.js';

export const blockControl = (ip, family, alertId) => html`
  <div class="block-ctl" data-block-ip="${ip}" data-alert="${alertId || ''}">
    <div class="field"><label class="field-label">Reason</label>
      <input class="input" data-block-reason maxlength="200" value="${family ? `${family} from ${ip}` : `Analyst block of ${ip}`}"></div>
    <div class="block-row">
      <label class="field-label" for="blk-ttl-${ip}">Block for</label>
      <select class="select" id="blk-ttl-${ip}" data-block-ttl>${[[15, '15 minutes'], [60, '1 hour'], [240, '4 hours']].map(([v, l]) => html`<option value="${v}" ${v === 60 ? html`selected` : ''}>${l}</option>`)}</select>
      <button class="btn btn-sm btn-danger" data-block-go>${icon('threat')}Block source</button>
    </div>
    <p class="field-hint" data-block-msg>The server decides what a block does (dry-run records only). Allowlisted and local addresses are refused.</p>
  </div>`;

export function bindBlock(root) {
  return on(root, 'click', '[data-block-go]', async (_e, btn) => {
    const box = btn.closest('[data-block-ip]');
    const ip = box.dataset.blockIp;
    const ok = await confirmDialog({ title: `Block ${ip}?`, body: 'The response backend applies this block. With a non-dry-run backend it changes real firewall rules.', confirmLabel: 'Block', tone: 'danger' });
    if (!ok) return;
    btn.disabled = true;
    try {
      const b = await blockIp(ip, $('[data-block-reason]', box).value.trim(), +$('[data-block-ttl]', box).value, box.dataset.alert || undefined);
      toast(`${ip} ${b?.status === 'pending' ? 'queued for approval' : 'blocked'}`);
      $('[data-block-msg]', box).textContent = `Recorded (${b?.status || 'active'}${b?.backend ? `, ${b.backend}` : ''}).`;
    } catch (err) {
      toast(`Block failed: ${err.message}`, { tone: 'error' });
      btn.disabled = false;
    }
  });
}

// Block or unblock an address from a table row or side panel (asks first when blocking).
export async function toggleBlock(ip, isBlocked, reason = 'Blocked from the console') {
  try {
    if (isBlocked) { await unblockIp(ip); toast(`${ip} unblocked`); return; }
    const ok = await confirmDialog({ title: `Block ${ip}?`, body: 'The response backend applies this block (dry-run by default). Allowlisted and local addresses are refused.', confirmLabel: 'Block', tone: 'danger' });
    if (!ok) return;
    const b = await blockIp(ip, reason, 60);
    toast(`${ip} ${b?.status === 'pending' ? 'queued for approval' : 'blocked'}`);
  } catch (e) { toast(e.message, { tone: 'error' }); }
}
