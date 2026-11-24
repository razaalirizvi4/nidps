import * as api from '../api.js';
import { pane } from '../components/pane.js';
import { table } from '../components/table.js';
import { termButton } from '../components/button.js';
import { statusPill, escapeHtml } from '../components/status.js';
import { confirmDialog } from '../components/dialog.js';

async function renderBlocks(root) {
  const blocks = await api.getBlockedHosts();
  const rows = blocks.map((b) => [
    escapeHtml(b.ip_address),
    escapeHtml(b.hostname || '—'),
    escapeHtml(`${b.attack_class || '—'} / ${(b.layers || []).join('+')}`),
    escapeHtml(b.start_time || '—'),
    escapeHtml(b.remaining || b.expires_at || '—'),
    termButton('[ UNBLOCK ]', { action: 'unblock', data: { ip: b.ip_address }, danger: true }),
  ]);
  root.querySelector('#active-blocks').innerHTML = pane(
    'ACTIVE BLOCKS',
    table(['IP Address', 'Host / Device', 'Reason / Evidence', 'Blocked At', 'Remaining', 'Action'], rows),
  );
}

async function renderAllowlist(root, draftIp = '') {
  const allow = await api.getAllowlist();
  const rows = allow.map((a) => [
    escapeHtml(a.address),
    escapeHtml(a.description || '—'),
    escapeHtml(a.added_by ?? 'system'),
    termButton('[ REMOVE ]', { action: 'remove-allow', data: { id: a.entry_id }, disabled: a.is_permanent }),
  ]);
  root.querySelector('#allowlist-pane').innerHTML = pane(
    'ALLOWLIST',
    `${table(['IP / Host', 'Description', 'Added By', ''], rows)}
     <div class="inline-form">
       <input id="allow-ip" aria-label="Allowlist IP" placeholder="IP address" value="${escapeHtml(draftIp)}"/>
       ${termButton('[ ADD ENTRY ]', { action: 'add-allow' })}
     </div>`,
  );
}

export async function renderBlocked(root) {
  root.innerHTML = `
    <div class="page-intro"><div><h1>Blocked Hosts &amp; Allowlist</h1></div></div>
    <div id="active-blocks"></div>
    <div class="two-col">
      <div id="allowlist-pane"></div>
      ${pane(
        'PREVENTION STATUS',
        `<p>${statusPill('blocking engine active', 'green')}</p>
         <p class="muted">rate limit: 8 / 60 blocks used</p>
         <p class="muted">default duration: 30 minutes</p>`,
      )}
    </div>`;

  await renderBlocks(root);
  await renderAllowlist(root);

  async function onClick(e) {
    const unblockBtn = e.target.closest('[data-action="unblock"]');
    if (unblockBtn) {
      if (await confirmDialog('Release this blocked host?', { title: 'confirm unblock' })) {
        await api.unblockHost(unblockBtn.dataset.ip);
        await renderBlocks(root);
      }
      return;
    }
    const removeBtn = e.target.closest('[data-action="remove-allow"]');
    if (removeBtn) {
      await api.removeAllowlistEntry(Number(removeBtn.dataset.id));
      await renderAllowlist(root);
      return;
    }
    if (e.target.closest('[data-action="add-allow"]')) {
      const input = root.querySelector('#allow-ip');
      const value = input.value.trim();
      if (value) {
        await api.addAllowlistEntry(value, 'manual entry');
        await renderAllowlist(root);
      }
    }
  }
  root.addEventListener('click', onClick);
  return () => root.removeEventListener('click', onClick);
}
