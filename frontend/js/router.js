// Minimal hash router. Pages register a render(container) function; navigating sets
// location.hash, which re-renders the workspace content area.
const routes = new Map();
let container = null;
let currentCleanup = null;

export const PAGES = [
  ['overview', 'Overview', 'terminal'],
  ['traffic', 'Network Traffic', 'network'],
  ['alerts', 'Intrusion Alerts', 'shield-alert'],
  ['blocked', 'Blocked Hosts', 'ban'],
  ['config', 'Configuration', 'settings'],
  ['health', 'System Health', 'activity'],
];

export function registerRoute(name, render) {
  routes.set(name, render);
}

export function mountRouter(el) {
  container = el;
  window.addEventListener('hashchange', renderCurrentRoute);
}

export function navigate(page) {
  if (location.hash.slice(1) === page) {
    renderCurrentRoute();
  } else {
    location.hash = page;
  }
}

export function currentPage() {
  const name = location.hash.slice(1);
  return routes.has(name) ? name : 'overview';
}

export async function renderCurrentRoute() {
  const page = currentPage();
  if (typeof currentCleanup === 'function') currentCleanup();
  const render = routes.get(page);
  if (!render) return;
  currentCleanup = await render(container);
  document.dispatchEvent(new CustomEvent('nidps:navigated', { detail: { page } }));
}
