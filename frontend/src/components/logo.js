// MAVIS mark: three detector nodes on an outer ring converge on one fused core.
// The ring is broken into three arcs, one per model.
import { raw } from '../core/dom.js';

export const logoMark = (cls = 'brand-mark') => raw(`
<svg class="${cls}" viewBox="0 0 32 32" fill="none" aria-hidden="true">
  <path d="M16 3.5a12.5 12.5 0 0 1 10.8 6.25" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
  <path d="M27.6 13.3a12.5 12.5 0 0 1-5.4 13.6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" opacity=".7"/>
  <path d="M18.4 28.3A12.5 12.5 0 0 1 3.9 13" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" opacity=".45"/>
  <path d="M16 6.5 16 13M24.2 21 18.6 17.5M7.8 21l5.6-3.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" opacity=".8"/>
  <circle cx="16" cy="6.5" r="2" fill="currentColor"/>
  <circle cx="24.2" cy="21" r="2" fill="currentColor"/>
  <circle cx="7.8" cy="21" r="2" fill="currentColor"/>
  <rect x="13.2" y="13.2" width="5.6" height="5.6" rx="1.2" transform="rotate(45 16 16)" fill="currentColor"/>
</svg>`);
