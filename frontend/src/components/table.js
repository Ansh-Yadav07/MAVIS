// Reusable data table: sortable columns, pagination, optional expandable rows,
// row selection, and a compact card list that replaces the table on phones.
import { html, raw, mount, on } from '../core/dom.js';
import { fmtInt } from '../core/format.js';
import { icon } from './icons.js';
import { emptyState } from './states.js';

export function createTable(container, opts) {
  const o = {
    pageSize: 25, initialSort: null, rowAttrs: () => ({}), onRowClick: null, card: null,
    expandable: null, emptyTitle: 'Nothing matches', emptyText: 'Try clearing a filter.', caption: '', ...opts,
  };
  let rows = o.rows || [];
  let sort = o.initialSort || null; // { key, dir: 'asc'|'desc' }
  let page = 0;
  let expanded = new Set();
  let selected = null;
  let highlight = new Set();

  const col = (key) => o.columns.find((c) => c.key === key);

  function sorted() {
    if (!sort) return rows;
    const c = col(sort.key);
    const get = c.sort || ((r) => r[c.key]);
    const dir = sort.dir === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      const va = get(a), vb = get(b);
      return (va > vb ? 1 : va < vb ? -1 : 0) * dir;
    });
  }

  function render() {
    const all = sorted();
    const pages = Math.max(1, Math.ceil(all.length / o.pageSize));
    page = Math.min(page, pages - 1);
    const slice = all.slice(page * o.pageSize, (page + 1) * o.pageSize);
    const colspan = o.columns.length;

    const head = html`<tr>${o.columns.map((c) => {
      const ariaSort = sort && sort.key === c.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : null;
      return html`<th scope="col" class="${c.align === 'right' ? 'r' : ''}" ${ariaSort ? html`aria-sort="${ariaSort}"` : ''} style="${c.width ? `width:${c.width}` : ''}">${
        c.sortable === false ? c.label : html`<button class="sort-btn" data-sort="${c.key}">${c.label}${icon('sort')}</button>`}</th>`;
    })}</tr>`;

    const body = slice.map((r) => {
      const attrs = o.rowAttrs(r);
      const isExp = expanded.has(r.id);
      const cls = [o.onRowClick || o.expandable ? 'is-clickable' : '', selected === r.id ? 'is-selected' : '', highlight.has(r.id) ? 'is-new' : ''].join(' ');
      const attrStr = Object.entries(attrs).map(([k, v]) => `${k}="${String(v).replace(/"/g, '&quot;')}"`).join(' ');
      return html`<tr class="${cls}" data-row="${r.id}" ${o.onRowClick || o.expandable ? html`tabindex="0"` : ''} ${o.expandable ? html`aria-expanded="${isExp}"` : ''} ${raw(attrStr)}>${
        o.columns.map((c) => html`<td class="${[c.align === 'right' ? 'r' : '', c.className || ''].join(' ')}">${c.render ? c.render(r) : r[c.key]}</td>`)}</tr>${
        isExp ? html`<tr class="expand-row"><td colspan="${colspan}">${o.expandable(r)}</td></tr>` : ''}`;
    });

    const cards = o.card ? slice.map((r) => html`<button class="event-card" data-row="${r.id}">${o.card(r)}</button>`) : '';
    const from = all.length ? page * o.pageSize + 1 : 0;
    const to = Math.min(all.length, (page + 1) * o.pageSize);

    mount(container, all.length ? html`
      <div class="table-wrap">
        <table class="table">${o.caption ? html`<caption class="visually-hidden">${o.caption}</caption>` : ''}<thead>${head}</thead><tbody>${body}</tbody></table>
      </div>
      ${o.card ? html`<div class="event-cards">${cards}</div>` : ''}
      ${pages > 1 || all.length > 10 ? html`<div class="pager">
        <span class="num">${fmtInt(from)}–${fmtInt(to)} of ${fmtInt(all.length)}</span>
        <div class="pager-btns">
          <button class="btn btn-sm" data-page="prev" ${page === 0 ? html`disabled` : ''} aria-label="Previous page">Previous</button>
          <span class="num" style="align-self:center;padding:0 8px">Page ${page + 1} of ${pages}</span>
          <button class="btn btn-sm" data-page="next" ${page >= pages - 1 ? html`disabled` : ''} aria-label="Next page">Next</button>
        </div></div>` : ''}`
      : emptyState({ title: o.emptyTitle, text: o.emptyText, icon: 'filter' }));
    container.classList.toggle('has-cards', !!o.card);
    highlight = new Set();
  }

  const activate = (id) => {
    if (o.expandable) {
      expanded.has(id) ? expanded.delete(id) : expanded.add(id);
      render();
    }
    o.onRowClick?.(rows.find((r) => r.id === id));
  };

  on(container, 'click', '[data-sort]', (_e, el) => {
    const key = el.dataset.sort;
    sort = sort && sort.key === key ? { key, dir: sort.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: col(key).defaultDir || 'desc' };
    page = 0;
    render();
    container.querySelector(`[data-sort="${key}"]`)?.focus();
  });
  on(container, 'click', '[data-page]', (_e, el) => {
    page += el.dataset.page === 'next' ? 1 : -1;
    render();
    container.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  });
  on(container, 'click', '[data-row]', (ev, el) => {
    if (ev.target.closest('a, button:not(.event-card), input, select')) return;
    activate(el.dataset.row);
  });
  on(container, 'keydown', 'tr[data-row]', (ev, el) => {
    if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); activate(el.dataset.row); }
  });

  render();
  return {
    setRows(next, { resetPage = true, flash = [] } = {}) { rows = next; if (resetPage) page = 0; highlight = new Set(flash); render(); },
    select(id) { selected = id; render(); },
    render,
    get rows() { return rows; },
  };
}

