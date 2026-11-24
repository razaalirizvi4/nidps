import { state } from './state.js';
import { registerRoute, mountRouter, navigate, renderCurrentRoute, currentPage, PAGES } from './router.js';
import { icon } from './icons.js';
import * as api from './api.js';
import { UnauthorizedError } from './api.js';
import { LiveSocket } from './ws.js';

import { renderLogin } from './pages/login.js';
import { renderOverview } from './pages/overview.js';
import { renderTraffic } from './pages/traffic.js';
import { renderAlerts } from './pages/alerts.js';
import { renderBlocked } from './pages/blocked.js';
import { renderConfig } from './pages/config.js';
import { renderHealth } from './pages/health.js';

const app = document.getElementById('app');
let liveSocket = null;

function applyTheme() {
  document.documentElement.dataset.theme = state.get('theme');
}

function sidebarHtml(active) {
  return `
    <aside class="sidebar">
      <div class="brand"><strong>NIDPS</strong></div>
      <nav aria-label="Primary navigation">
        ${PAGES.map(
          ([id, label, iconName]) => `
          <button class="${active === id ? 'selected' : ''}" data-nav="${id}">
            ${icon(iconName)}<span>${active === id ? '&gt; ' : '  '}${label}</span>
          </button>`,
        ).join('')}
      </nav>
      <div class="side-bottom">
        <span class="account-name">admin</span>
        <button class="logout-button" data-action="logout">${icon('log-out', { size: 14 })}<span>[ Logout ]</span></button>
      </div>
    </aside>`;
}

function wsStatusLabel(status) {
  return { connected: 'online', connecting: 'connecting', reconnecting: 'reconnecting', offline: 'offline (demo)' }[status] || status;
}

function topbarHtml(active) {
  const theme = state.get('theme');
  const wsStatus = state.get('wsStatus');
  const pageLabel = PAGES.find(([id]) => id === active)?.[1] || '';
  return `
    <header class="topbar">
      <button class="mobile-menu term-button" data-action="toggle-mobile-nav" aria-label="Open menu">${icon('menu')}</button>
      <span><b class="green">NIDPS</b> / ${pageLabel}</span>
      <div class="topbar-actions">
        <span class="ws-indicator ${wsStatus}" id="ws-indicator"><span class="ws-dot"></span>${wsStatusLabel(wsStatus)}</span>
        <button class="theme-toggle" data-action="toggle-theme" aria-pressed="${theme === 'light'}" title="Switch to ${theme === 'light' ? 'dark' : 'light'} mode">
          ${icon(theme === 'light' ? 'moon' : 'sun')}<span>${theme === 'light' ? 'Light' : 'Dark'}</span>
        </button>
      </div>
    </header>`;
}

function refreshChrome() {
  const active = currentPage();
  const sidebarEl = app.querySelector('.sidebar');
  if (sidebarEl) sidebarEl.outerHTML = sidebarHtml(active);
  const topbarEl = app.querySelector('.topbar');
  if (topbarEl) topbarEl.outerHTML = topbarHtml(active);
}

function renderShell() {
  const active = currentPage();
  app.innerHTML = `
    <div class="nidps-shell">
      ${sidebarHtml(active)}
      <main class="main-area">
        ${topbarHtml(active)}
        <div id="mobile-nav-slot"></div>
        <div class="workspace" id="workspace"></div>
      </main>
    </div>`;
  mountRouter(document.getElementById('workspace'));
}

function startLiveSocket() {
  liveSocket?.stop();
  liveSocket = new LiveSocket({
    token: state.get('sessionToken') || '',
    onMessage: (snapshot) => {
      state.set('live', snapshot);
      document.dispatchEvent(new CustomEvent('nidps:live', { detail: snapshot }));
    },
    onStatus: (status) => {
      state.set('wsStatus', status);
      const el = document.getElementById('ws-indicator');
      if (el) {
        el.className = `ws-indicator ${status}`;
        el.innerHTML = `<span class="ws-dot"></span>${wsStatusLabel(status)}`;
      }
    },
    pollFallback: () => api.getOverview(),
  });
  liveSocket.start();
}

async function showDashboard() {
  renderShell();
  registerRoute('overview', renderOverview);
  registerRoute('traffic', renderTraffic);
  registerRoute('alerts', renderAlerts);
  registerRoute('blocked', renderBlocked);
  registerRoute('config', renderConfig);
  registerRoute('health', renderHealth);
  await renderCurrentRoute();
  startLiveSocket();
}

function showLogin() {
  liveSocket?.stop();
  renderLogin(app, async () => {
    await showDashboard();
  });
}

async function boot() {
  applyTheme();
  try {
    await api.getOverview(); // doubles as a session check; demo fallback keeps this offline-friendly
    await showDashboard();
  } catch (err) {
    if (err instanceof UnauthorizedError) showLogin();
    else await showDashboard(); // unexpected error: still show the shell with demo data
  }
}

document.addEventListener('nidps:navigated', refreshChrome);

document.addEventListener('click', async (e) => {
  const navBtn = e.target.closest('[data-nav]');
  if (navBtn) {
    navigate(navBtn.dataset.nav);
    document.getElementById('mobile-nav-slot').innerHTML = '';
    state.set('mobileNavOpen', false);
    return;
  }
  if (e.target.closest('[data-action="toggle-theme"]')) {
    state.set('theme', state.get('theme') === 'light' ? 'dark' : 'light');
    applyTheme();
    refreshChrome();
    return;
  }
  if (e.target.closest('[data-action="toggle-mobile-nav"]')) {
    const slot = document.getElementById('mobile-nav-slot');
    const open = !state.get('mobileNavOpen');
    state.set('mobileNavOpen', open);
    slot.innerHTML = open ? `<div class="mobile-nav">${sidebarHtml(currentPage())}</div>` : '';
    return;
  }
  if (e.target.closest('[data-action="logout"]')) {
    await api.logout();
    state.set('sessionToken', null);
    showLogin();
  }
});

boot();
