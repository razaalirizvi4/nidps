import * as api from '../api.js';
import { pane } from '../components/pane.js';
import { table } from '../components/table.js';
import { statusPill, escapeHtml } from '../components/status.js';
import { icon } from '../icons.js';
import { navigate } from '../router.js';
import { state } from '../state.js';

function summaryHtml(overview) {
  return `
    <div class="summary-line">
      <div><span>packets / flows analyzed</span><b>${overview.flows_analyzed.toLocaleString()}</b></div>
      <div><span>intrusions detected</span><b class="red">${overview.intrusions_detected.toLocaleString()}</b></div>
      <div><span>active blocks</span><b class="amber">${overview.active_blocks.toLocaleString()}</b></div>
      <div><span>protection status</span><b class="green">operational</b></div>
    </div>
    <p class="pane-note">engine ml-ids v2.4 &nbsp;|&nbsp; refreshed live &nbsp;|&nbsp; failure mode fail-open</p>`;
}

export async function renderOverview(root) {
  root.innerHTML = `
    <div class="page-intro"><div><h1>Network Protection Overview</h1></div></div>
    <div id="overview-summary">${pane('SYSTEM SUMMARY', summaryHtml(state.get('live')))}</div>
    <div id="overview-alerts"></div>`;

  // Seed with a fresh snapshot immediately -- the WebSocket (or its polling fallback) only
  // updates state.live on its own ~2s cadence, which would otherwise leave this panel at zero
  // until the first tick.
  const initial = await api.getOverview();
  state.set('live', initial);
  root.querySelector('#overview-summary').innerHTML = pane('SYSTEM SUMMARY', summaryHtml(initial));

  async function loadAlerts() {
    const alerts = await api.getAlerts({ limit: 3 });
    const rows = alerts.slice(0, 3).map((a) => [
      escapeHtml(a.time || a.created_at || ''),
      escapeHtml(a.host_ip),
      escapeHtml(a.attack_class || ''),
      statusPill(a.decision, a.decision === 'BLOCK' ? 'red' : 'amber'),
    ]);
    root.querySelector('#overview-alerts').innerHTML = pane(
      'RECENT ALERTS',
      `${table(['Time', 'Source IP', 'Attack Type', 'Action'], rows)}
       <button class="link" data-action="view-all-alerts">view all alerts ${icon('chevron-right')}</button>`,
    );
  }
  await loadAlerts();

  function onLive() {
    root.querySelector('#overview-summary').innerHTML = pane('SYSTEM SUMMARY', summaryHtml(state.get('live')));
  }
  document.addEventListener('nidps:live', onLive);

  root.addEventListener('click', (e) => {
    if (e.target.closest('[data-action="view-all-alerts"]')) navigate('alerts');
  });

  return () => document.removeEventListener('nidps:live', onLive);
}
