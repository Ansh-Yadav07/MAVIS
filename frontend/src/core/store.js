// App state: viewer preferences (kept in this browser) and analyst edits to flows and incidents.
// Storage can be unavailable (private windows, previews), so every access is guarded.

const KEY = 'mavis.ui.v1';

const DEFAULT_PREFS = {
  appearance: 'light',       // light | dark | system
  density: 'comfortable',    // comfortable | compact
  motion: 'system',          // system | reduced
  rail: 'expanded',          // expanded | collapsed
  overviewRange: 'week',     // week | day
  notifyCritical: true,
  notifyHigh: true,
  chartGrid: true,
  pageSize: 25,
  alertBudget: null,         // false-positive budget; null = the engine's calibrated default
};

function load() {
  try {
    const s = JSON.parse(localStorage.getItem(KEY) || '{}');
    return { prefs: { ...DEFAULT_PREFS, ...(s.prefs || {}) }, edits: s.edits || {}, readNotes: s.readNotes || [] };
  } catch {
    return { prefs: { ...DEFAULT_PREFS }, edits: {}, readNotes: [] };
  }
}

const state = load();
const listeners = new Set();

function persist() {
  try { localStorage.setItem(KEY, JSON.stringify(state)); } catch { /* storage blocked: keep in memory */ }
}

export const store = {
  get prefs() { return state.prefs; },
  setPref(key, value) {
    state.prefs[key] = value;
    persist();
    listeners.forEach((fn) => fn({ type: 'pref', key, value }));
  },
  resetPrefs() {
    state.prefs = { ...DEFAULT_PREFS };
    persist();
    listeners.forEach((fn) => fn({ type: 'pref', key: '*' }));
  },
  edit(id) { return state.edits[id] || {}; },
  setEdit(id, patch) {
    state.edits[id] = { ...(state.edits[id] || {}), ...patch };
    persist();
    listeners.forEach((fn) => fn({ type: 'edit', id }));
  },
  isRead(id) { return state.readNotes.includes(id); },
  markRead(ids) {
    state.readNotes = Array.from(new Set([...state.readNotes, ...ids]));
    persist();
    listeners.forEach((fn) => fn({ type: 'notes' }));
  },
  subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); },
  // Transient UI state shared between views (not persisted)
  // session.day: selected capture day id ('mon'|'tue'|...), or null for all days. Views read it
  //   with `store.session.day || undefined` and pass it as the `day` filter of flows()/summary()/etc.
  //   Change it only through setSession() so the shell re-renders the current view.
  // session.query: search text handed to the Event Explorer by the top-bar search.
  session: { selectedFlow: null, threatFilters: null, networkFilters: null, day: null, query: '' },
  setSession(key, value) {
    this.session[key] = value;
    listeners.forEach((fn) => fn({ type: 'session', key, value }));
  },
};
