// Hash router. Only bare tokens are used (#threats, #event-FL-0123) because the artifact
// viewer passes nothing else through.

const routes = new Map();
let current = null;
let onChange = () => {};

export function defineRoute(id, def) { routes.set(id, def); }
export const getRoutes = () => routes;

export function parse(hash = location.hash) {
  const token = hash.replace(/^#/, '');
  if (token.startsWith('event-')) return { id: 'explorer', param: token.slice(6) };
  return { id: routes.has(token) ? token : 'overview', param: null };
}

export function go(id, param) {
  const token = id === 'explorer' && param ? `event-${param}` : id;
  if (location.hash.slice(1) === token) { render(); return; }
  location.hash = token;
}

export function render() {
  const r = parse();
  const changed = !current || current.id !== r.id || current.param !== r.param;
  current = r;
  if (changed) onChange(r, routes.get(r.id));
}

export function startRouter(cb) {
  onChange = cb;
  window.addEventListener('hashchange', render);
  render();
}

export const currentRoute = () => current;
