import * as api from '../api.js';
import { pane } from '../components/pane.js';
import { table } from '../components/table.js';
import { statusPill, escapeHtml } from '../components/status.js';
import { icon } from '../icons.js';

let allAlerts = [];
let selectedId = null;

function detailHtml(alert, evidence) {
  if (!alert) return pane('ALERT EVIDENCE', '<p class="muted">select an alert to inspect evidence</p>', { className: 'detail' });
  const tone = alert.decision === 'BLOCK' ? 'red' : alert.decision === 'PASS' ? 'green' : 'amber';
  const evidenceLines = evidence
    .map((e) => `<b>LAYER ${escapeHtml(e.layer)}</b><span>${e.evidence_type === 'SIGNATURE' ? `signature match / rule sid ${escapeHtml(e.signature_id ?? '—')}` : e.predicted_class ? `predicted class: ${escapeHtml(e.predicted_class)} / confidence ${escapeHtml(e.confidence ?? '—')}` : `anomaly score: ${escapeHtml(e.score ?? '—')}`}</span>`)
    .join('');
  return pane(
    'ALERT EVIDENCE',
    `<p class="muted">event ${escapeHtml(alert.time || alert.created_at || '')}</p>
     <p><b>${escapeHtml(alert.attack_class || 'UNKNOWN')}</b><br/>${escapeHtml(alert.host_ip)} → ${escapeHtml(alert.dst || '—')}</p>
     <div class="evidence">
       <p>${statusPill(`final verdict: ${alert.decision}`, tone)}</p>
       <p>risk score <b class="amber">${escapeHtml(alert.risk ?? '—')}/100</b></p>
       <hr/>
       ${evidenceLines || '<span class="muted">no evidence rows recorded</span>'}
     </div>
     <p class="pane-note">decision made because signature and model evidence exceeded the configured host risk threshold.</p>`,
    { className: 'detail' },
  );
}

async function renderList(root, query = '') {
  const filtered = allAlerts.filter(
    (a) => a.host_ip.includes(query) || (a.attack_class || '').toLowerCase().includes(query.toLowerCase()) || a.decision.toLowerCase().includes(query.toLowerCase()),
  );
  const rows = filtered.map((a) => [
    escapeHtml(a.time || a.created_at || ''),
    escapeHtml(a.host_ip),
    escapeHtml(a.dst || '—'),
    escapeHtml(a.attack_class || '—'),
    escapeHtml((a.layers || []).join(', ')),
    escapeHtml(a.confidence ?? '—'),
    statusPill(a.decision, a.decision === 'BLOCK' ? 'red' : a.decision === 'PASS' ? 'green' : 'amber'),
  ]);
  root.querySelector('#alerts-list').innerHTML = pane(
    'DETECTION RESULTS',
    `<div class="filter-row">
       <div class="input-wrap">${icon('search')}<input id="alert-filter" aria-label="Filter alerts" placeholder="filter IP, type, verdict" value="${escapeHtml(query)}"/></div>
       <span class="muted">${filtered.length} events</span>
     </div>
     ${table(['Time', 'Source', 'Destination', 'Classification', 'Layer', 'Conf.', 'Verdict'], rows, {
       rowAttrs: (row, i) => `data-verdict-id="${filtered[i].verdict_id}" class="${filtered[i].verdict_id === selectedId ? 'row-selected' : ''}"`,
     })}`,
    { className: 'grow' },
  );
  root.querySelector('#alert-filter').addEventListener('input', (e) => renderList(root, e.target.value));
}

async function selectAlert(root, verdictId) {
  selectedId = verdictId;
  const alert = allAlerts.find((a) => a.verdict_id === verdictId);
  const evidence = await api.getAlertEvidence(verdictId);
  root.querySelector('#alert-detail').innerHTML = detailHtml(alert, evidence);
}

export async function renderAlerts(root) {
  allAlerts = await api.getAlerts();
  selectedId = allAlerts[1]?.verdict_id ?? allAlerts[0]?.verdict_id ?? null;

  root.innerHTML = `
    <div class="page-intro"><div><h1>Intrusion Alerts</h1></div></div>
    <div class="content-split">
      <div id="alerts-list"></div>
      <div id="alert-detail"></div>
    </div>`;

  await renderList(root);
  if (selectedId != null) await selectAlert(root, selectedId);

  function onClick(e) {
    const row = e.target.closest('tr[data-verdict-id]');
    if (row) selectAlert(root, Number(row.dataset.verdictId));
  }
  root.addEventListener('click', onClick);
  return () => root.removeEventListener('click', onClick);
}
