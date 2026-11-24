import * as api from '../api.js';
import { pane } from '../components/pane.js';
import { table } from '../components/table.js';
import { escapeHtml } from '../components/status.js';
import { icon } from '../icons.js';
import { state } from '../state.js';
import { renderLineChart, destroyChart } from '../charts/lineChart.js';
import { demoTrafficHistory, demoTrafficLabels } from '../demoData.js';

export async function renderTraffic(root) {
  const overview = state.get('live');
  const hosts = await api.getHosts();

  root.innerHTML = `
    <div class="page-intro"><div><h1>Network Traffic</h1></div></div>
    <div class="mini-grid">
      ${pane('THROUGHPUT', `<b class="big-number">842 <small>KB/s</small></b><span class="muted">current observed flow</span>`)}
      ${pane('FLOWS ANALYZED', `<b class="big-number">${overview.flows_analyzed.toLocaleString()}</b><span class="muted">last 24 hours</span>`)}
      ${pane('CONNECTED DEVICES', `<b class="big-number">${hosts.length}</b><span class="muted">tracked hosts</span>`)}
    </div>
    ${pane('TRAFFIC HISTORY', `<div class="chart large"><canvas id="traffic-chart"></canvas></div>`)}
    <div id="devices-pane"></div>`;

  renderLineChart('traffic-chart', { labels: demoTrafficLabels, data: demoTrafficHistory });

  function renderDevices(query = '') {
    const shown = hosts.filter((h) => `${h.ip_address} ${h.hostname || ''}`.toLowerCase().includes(query.toLowerCase()));
    const rows = shown.map((h) => [
      escapeHtml(h.ip_address),
      escapeHtml(h.hostname || '—'),
      `<span class="${Number(h.risk_score) > 60 ? 'red' : ''}">${escapeHtml(h.risk_score ?? 0)}</span>`,
      escapeHtml(h.last_seen || '—'),
    ]);
    root.querySelector('#devices-pane').innerHTML = pane(
      'CONNECTED DEVICES AND FLOWS',
      `<div class="filter-row">
         <div class="input-wrap">${icon('search')}<input id="device-filter" aria-label="Filter devices" placeholder="filter by host or IP" value="${escapeHtml(query)}"/></div>
         <span class="muted">showing ${shown.length} / ${hosts.length}</span>
       </div>
       ${table(['Device / IP', 'Hostname', 'Risk', 'Last Activity'], rows)}`,
    );
    root.querySelector('#device-filter').addEventListener('input', (e) => renderDevices(e.target.value));
  }
  renderDevices();

  return () => destroyChart('traffic-chart');
}
