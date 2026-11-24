import * as api from '../api.js';
import { pane } from '../components/pane.js';
import { table } from '../components/table.js';
import { statusPill, escapeHtml } from '../components/status.js';

const RESOURCES = [
  ['CPU USAGE', '12%'],
  ['MEMORY USAGE', '26%'],
  ['DEVICE TEMPERATURE', '48°C'],
  ['SYSTEM UPTIME', '14d 06h 22m'],
  ['THROUGHPUT', '842 KB/s'],
  ['AVAILABLE STORAGE', '68%'],
];

const EVENT_LOG = [
  ['14:31:50', 'watchdog health check passed'],
  ['13:04:12', 'prevention engine restarted automatically'],
  ['13:04:18', 'component recovered / protection restored'],
  ['12:00:00', 'routine ruleset validation completed'],
];

export async function renderHealth(root) {
  const components = await api.getHealth();
  const rows = components.map((c) => [
    escapeHtml(c.component),
    statusPill(c.state, c.state === 'RUNNING' || c.state === 'NORMAL' ? 'green' : c.state === 'DEGRADED' ? 'amber' : 'red'),
    escapeHtml(c.detected_at || '—'),
    `<span class="muted">${escapeHtml(c.recovered_at || 'none recorded')}</span>`,
  ]);

  root.innerHTML = `
    <div class="page-intro"><div><h1>System Health</h1></div></div>
    ${pane('COMPONENT STATUS', table(['Component', 'Status', 'Last Successful Check', 'Last Failure'], rows))}
    <div class="two-col">
      ${pane(
        'RESOURCE MONITORING',
        `<div class="resource-list">
           ${RESOURCES.map(
             ([label, value]) => `<div><span>${label}</span><b>${value}</b><i><em style="width:${value.includes('%') ? value : '32%'}"></em></i></div>`,
           ).join('')}
         </div>`,
      )}
      ${pane(
        'FAILURE AND RECOVERY HISTORY',
        `<div class="event-log">${EVENT_LOG.map(([t, text]) => `<p><span>${t}</span> ${text}</p>`).join('')}</div>`,
      )}
    </div>`;
}
