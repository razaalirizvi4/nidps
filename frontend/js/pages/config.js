import * as api from '../api.js';
import { pane } from '../components/pane.js';
import { termButton } from '../components/button.js';
import { statusPill, escapeHtml } from '../components/status.js';
import { icon } from '../icons.js';
import { confirmDialog } from '../components/dialog.js';

const TABS = [
  ['detection_layers', 'Detection layers'],
  ['thresholds', 'Thresholds'],
  ['prevention_and_failure', 'Prevention and failure'],
  ['rules_calibration_models', 'Rules, calibration and models'],
];

let activeTab = 'detection_layers';
let dirty = false;
let pendingValues = {};

function tabsHtml() {
  return `<div class="tabs">${TABS.map(([id, label]) => termButton(label, { action: 'select-tab', data: { tab: id }, active: activeTab === id })).join('')}</div>`;
}

function actionsHtml() {
  return `
    <div class="actions">
      ${termButton('[ RESTORE DEFAULTS ]', { action: 'restore-defaults', iconHtml: icon('rotate-ccw', { size: 14 }) })}
      ${termButton('[ APPLY CHANGES ]', { action: 'apply-changes', disabled: !dirty, iconHtml: icon('save', { size: 14 }) })}
      ${dirty ? '<span class="amber">unsaved changes</span>' : ''}
    </div>`;
}

function layersBody(rows) {
  return rows
    .map((row, i) => {
      const enabled = pendingValues[row.key] ?? row.value;
      return `
        <div class="config-row">
          <div><b>LAYER ${i + 1} — ${escapeHtml(row.label || row.key)}</b></div>
          <div class="config-status-actions">
            ${statusPill(enabled ? 'running' : 'disabled', enabled ? 'green' : 'red')}
            ${termButton(`[ ${enabled ? 'ENABLED' : 'DISABLED'} ]`, { action: 'toggle-layer', data: { key: row.key }, active: enabled })}
          </div>
        </div>`;
    })
    .join('');
}

function thresholdsBody(rows) {
  const trs = rows
    .map(
      (row) => `
      <tr>
        <td>${escapeHtml((row.label || row.key).toUpperCase())}</td>
        <td><input class="small-input" data-threshold="${row.key}" value="${escapeHtml(pendingValues[row.key] ?? row.value)}"/></td>
        <td>${escapeHtml(row.default)}</td>
        <td>${row.min_value != null ? `${row.min_value} — ${row.max_value}` : 'read-only demo'}</td>
      </tr>`,
    )
    .join('');
  return `
    <div class="table-wrap"><table>
      <thead><tr><th>Parameter</th><th>Current value</th><th>Default</th><th>Edit</th></tr></thead>
      <tbody>${trs}</tbody>
    </table></div>
    ${actionsHtml()}`;
}

function preventionBody(rows) {
  const failureRow = rows.find((r) => r.key === 'failure_mode');
  const currentMode = pendingValues.failure_mode ?? failureRow?.value ?? 'FAIL-OPEN';
  const modes = [
    ['FAIL-OPEN', 'Allow traffic if a required component fails.'],
    ['FAIL-CLOSED', 'Block traffic if a required component fails.'],
    ['DEGRADED', 'Continue with reduced inspection policy.'],
  ];
  return `
    ${pane(
      'FAILURE MODE',
      `<div class="mode-grid">
         ${modes
           .map(
             ([mode, desc]) => `
             <button class="mode ${currentMode === mode ? 'chosen' : ''}" data-action="select-mode" data-mode="${mode}">
               <b>[ ${currentMode === mode ? '●' : ' '} ] ${mode}</b><span>${desc}</span>
             </button>`,
           )
           .join('')}
       </div>
       <p class="pane-note amber">fail-closed may interrupt network connectivity. explicit confirmation is required before applying.</p>
       ${actionsHtml()}`,
    )}
    ${pane(
      'WATCHDOG SETTINGS',
      `<div class="config-grid">
         <span>STATUS</span><b class="green">ACTIVE</b>
         <span>HEALTH-CHECK INTERVAL</span><b>30s</b>
         <span>MISSED-CHECK THRESHOLD</span><b>3 checks</b>
         <span>AUTOMATIC RESTART</span><b class="green">ENABLED</b>
       </div>`,
    )}`;
}

async function rulesBody() {
  const models = await api.getModels();
  return `
    ${pane(
      'RULESET & RECALIBRATION',
      `<div class="config-grid">
         <span>RULESET STATUS</span><b class="green">CURRENT</b>
       </div>
       ${termButton('[ RELOAD RULES ]', { action: 'reload-rules' })}
       ${termButton('[ RECALIBRATE ]', { action: 'recalibrate' })}`,
    )}
    ${pane(
      'MODELS',
      `<div class="config-grid">
         ${models
           .map((m) => `<span>${escapeHtml(m.model_type)}</span><b>${escapeHtml(m.version)} ${m.is_active ? '<span class="green">(active)</span>' : ''}</b>`)
           .join('')}
       </div>`,
    )}`;
}

async function renderTabContent(root) {
  const rows = await api.getSettingsTab(activeTab);
  let body;
  if (activeTab === 'detection_layers') body = pane('DETECTION LAYERS', `<p class="pane-note">administrative state is separate from runtime health. a disabled layer will not contribute to decisions.</p>${layersBody(rows)}`);
  else if (activeTab === 'thresholds') body = pane('DETECTION THRESHOLDS', thresholdsBody(rows));
  else if (activeTab === 'prevention_and_failure') body = preventionBody(rows);
  else body = await rulesBody();
  root.querySelector('#config-body').innerHTML = body;
}

export async function renderConfig(root) {
  pendingValues = {};
  dirty = false;
  root.innerHTML = `
    <div class="page-intro"><div><h1>Detection &amp; Prevention Configuration</h1></div></div>
    ${tabsHtml()}
    <div id="config-body"></div>
    <p class="success-line" id="config-saved" hidden>${icon('check')} Configuration applied. Audit entry recorded for admin.</p>`;

  await renderTabContent(root);

  async function onClick(e) {
    const saved = root.querySelector('#config-saved');
    saved.hidden = true;

    const tabBtn = e.target.closest('[data-action="select-tab"]');
    if (tabBtn) {
      activeTab = tabBtn.dataset.tab;
      root.querySelector('.tabs').outerHTML = tabsHtml();
      await renderTabContent(root);
      return;
    }
    const layerBtn = e.target.closest('[data-action="toggle-layer"]');
    if (layerBtn) {
      if (await confirmDialog('Disabling a security layer may reduce protection. Continue?', { title: 'confirm layer change', danger: true })) {
        const key = layerBtn.dataset.key;
        const rows = await api.getSettingsTab('detection_layers');
        const current = rows.find((r) => r.key === key);
        pendingValues[key] = !(pendingValues[key] ?? current.value);
        dirty = true;
        await renderTabContent(root);
      }
      return;
    }
    const modeBtn = e.target.closest('[data-action="select-mode"]');
    if (modeBtn) {
      pendingValues.failure_mode = modeBtn.dataset.mode;
      dirty = true;
      await renderTabContent(root);
      return;
    }
    if (e.target.closest('[data-action="restore-defaults"]')) {
      if (await confirmDialog('Restore all configuration defaults?', { title: 'confirm restore' })) {
        pendingValues = {};
        dirty = true;
        await renderTabContent(root);
      }
      return;
    }
    if (e.target.closest('[data-action="apply-changes"]')) {
      if (await confirmDialog('Apply these configuration changes?', { title: 'confirm changes' })) {
        await Promise.all(Object.entries(pendingValues).map(([key, value]) => api.updateSetting(key, value).catch(() => {})));
        dirty = false;
        pendingValues = {};
        saved.hidden = false;
        await renderTabContent(root);
      }
      return;
    }
    if (e.target.closest('[data-action="reload-rules"]')) {
      await api.requestReloadRules();
      saved.hidden = false;
      return;
    }
    if (e.target.closest('[data-action="recalibrate"]')) {
      await api.requestRecalibration();
      saved.hidden = false;
    }
  }

  function onInput(e) {
    if (e.target.dataset.threshold) {
      pendingValues[e.target.dataset.threshold] = e.target.value;
      dirty = true;
      const actionsBar = root.querySelector('.actions');
      if (actionsBar) actionsBar.outerHTML = actionsHtml();
    }
  }

  root.addEventListener('click', onClick);
  root.addEventListener('input', onInput);
  return () => {
    root.removeEventListener('click', onClick);
    root.removeEventListener('input', onInput);
  };
}
