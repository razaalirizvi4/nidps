// Tiny app-wide store: plain object + subscriber list. No framework -- pages read state.get()
// synchronously when they render, and subscribe() when they need to react to later changes
// (theme toggle, live WebSocket pushes).
import { THEME_STORAGE_KEY, SESSION_STORAGE_KEY } from './config.js';

const listeners = new Set();

const data = {
  theme: localStorage.getItem(THEME_STORAGE_KEY) || 'dark',
  sessionToken: sessionStorage.getItem(SESSION_STORAGE_KEY) || null,
  page: 'overview',
  mobileNavOpen: false,
  live: { flows_analyzed: 0, intrusions_detected: 0, active_blocks: 0 },
  wsStatus: 'offline', // 'offline' | 'connecting' | 'connected' | 'reconnecting'
};

export const state = {
  get(key) {
    return data[key];
  },
  set(key, value) {
    data[key] = value;
    if (key === 'theme') localStorage.setItem(THEME_STORAGE_KEY, value);
    if (key === 'sessionToken') {
      if (value) sessionStorage.setItem(SESSION_STORAGE_KEY, value);
      else sessionStorage.removeItem(SESSION_STORAGE_KEY);
    }
    for (const fn of listeners) fn(key, value);
  },
  subscribe(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },
};
