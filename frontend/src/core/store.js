// App state: viewer preferences (kept in this browser) and analyst edits to sample events.
// Storage can be unavailable (private windows, previews), so every access is guarded.

const KEY = 'mavis.ui.v1';

const DEFAULT_PREFS = {
  appearance: 'dark',        // dark | light | system
  density: 'comfortable',    // comfortable | compact
  motion: 'system',          // system | reduced
  rail: 'expanded',          // expanded | collapsed
  overviewRange: 'week',     // week | day
  notifyCritical: true,
  notifyHigh: true,
  chartGrid: true,
  pageSize: 25,
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
  session: { selectedFlow: null, threatFilters: null, networkFilters: null },
};
