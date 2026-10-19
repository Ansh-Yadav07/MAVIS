// Hash router: bare tokens only (#overview, #graph, ...).
const routes = new Map();
let current = null;
let onChange = () => {};

export function defineRoute(id, def) { routes.set(id, def); }
export const getRoutes = () => routes;

export function parse(hash = location.hash) {
  const token = hash.replace(/^#/, '');
  return { id: routes.has(token) ? token : 'overview', param: null };
}

export function go(id) {
  if (location.hash.slice(1) === id) { render(); return; }
  location.hash = id;
}

export function render() {
  const r = parse();
  const changed = !current || current.id !== r.id;
  current = r;
  if (changed) onChange(r, routes.get(r.id));
}

export function startRouter(cb) {
  onChange = cb;
  window.addEventListener('hashchange', render);
  render();
}

export const currentRoute = () => current;
