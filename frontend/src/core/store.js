// Viewer preferences, kept in this browser. Storage can be unavailable (private windows,
// previews), so every access is guarded.
const KEY = 'mavis.ui.v2';

const DEFAULT_PREFS = {
  appearance: 'light',       // light | dark | system
  density: 'comfortable',    // comfortable | compact
  motion: 'system',          // system | reduced
  rail: 'expanded',          // expanded | collapsed
  sound: false,              // alarm beep (needs one click per browser session to start audio)
  learnTarget: 400,          // flows to collect while learning normal traffic
};

function load() {
  try {
    const s = JSON.parse(localStorage.getItem(KEY) || '{}');
    return { prefs: { ...DEFAULT_PREFS, ...(s.prefs || {}) } };
  } catch {
    return { prefs: { ...DEFAULT_PREFS } };
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
  subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); },
};
