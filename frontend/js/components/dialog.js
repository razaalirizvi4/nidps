// Themed replacement for window.confirm()/window.alert(). Renders an overlay pane styled like
// the rest of the dashboard (dark/light aware via CSS variables) instead of the browser's native
// dialog. confirmDialog() resolves true/false; alertDialog() resolves once dismissed.
import { escapeHtml } from './status.js';
import { icon } from '../icons.js';

function openDialog({ title, message, danger = false, confirmLabel = '[ CONFIRM ]', cancelLabel = '[ CANCEL ]', showCancel = true }) {
  return new Promise((resolve) => {
    const backdrop = document.createElement('div');
    backdrop.className = 'dialog-backdrop';
    backdrop.innerHTML = `
      <div class="dialog-box" role="alertdialog" aria-modal="true" aria-labelledby="dialog-title">
        <header><span id="dialog-title">[ ${escapeHtml(title)} ]</span><button class="dialog-close" aria-label="Close" data-dialog="cancel">${icon('x', { size: 14 })}</button></header>
        <p>${escapeHtml(message)}</p>
        <div class="dialog-actions">
          ${showCancel ? `<button class="term-button" data-dialog="cancel">${cancelLabel}</button>` : ''}
          <button class="term-button ${danger ? 'danger' : 'active'}" data-dialog="confirm" autofocus>${confirmLabel}</button>
        </div>
      </div>`;
    document.body.appendChild(backdrop);

    function cleanup(result) {
      document.removeEventListener('keydown', onKeydown);
      backdrop.remove();
      resolve(result);
    }
    function onKeydown(e) {
      if (e.key === 'Escape') cleanup(false);
      if (e.key === 'Enter' && document.activeElement?.dataset.dialog !== 'cancel') cleanup(true);
    }
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) cleanup(false);
      const btn = e.target.closest('[data-dialog]');
      if (btn) cleanup(btn.dataset.dialog === 'confirm');
    });
    document.addEventListener('keydown', onKeydown);
    backdrop.querySelector('[data-dialog="confirm"]').focus();
  });
}

export function confirmDialog(message, opts = {}) {
  return openDialog({ title: opts.title || 'confirm', message, danger: opts.danger, confirmLabel: opts.confirmLabel, cancelLabel: opts.cancelLabel });
}

export function alertDialog(message, opts = {}) {
  return openDialog({ title: opts.title || 'notice', message, showCancel: false, confirmLabel: opts.confirmLabel || '[ OK ]' });
}
