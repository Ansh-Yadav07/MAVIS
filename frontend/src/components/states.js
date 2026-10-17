// Empty, error and loading states shared by every view.
import { html } from '../core/dom.js';
import { icon } from './icons.js';

export const emptyState = ({ title, text, icon: ic = 'info', action = '' }) =>
  html`<div class="empty">${icon(ic)}<div class="empty-title">${title}</div><p>${text}</p>${action}</div>`;

export const errorState = ({ title = 'Could not load this section', text, retry = true }) =>
  html`<div class="empty" role="alert">${icon('alert')}<div class="empty-title">${title}</div><p>${text}</p>${retry ? html`<button class="btn btn-sm" data-action="retry">Try again</button>` : ''}</div>`;

export const skeletonRows = (n = 5) =>
  html`<div style="display:grid;gap:10px;padding:16px">${Array.from({ length: n }, (_, i) => html`<div class="skeleton" style="height:14px;width:${92 - (i % 3) * 14}%"></div>`)}</div>`;
