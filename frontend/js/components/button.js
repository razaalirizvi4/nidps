// Buttons render as plain markup with data-attributes; pages bind click handlers via event
// delegation (see app.js's document-level click listener) rather than per-button listeners, so
// buttons can be freely re-rendered on every data refresh without leaking listeners.
export function termButton(label, { action = '', data = {}, active = false, danger = false, disabled = false, iconHtml = '' } = {}) {
  const dataAttrs = Object.entries(data).map(([k, v]) => `data-${k}="${String(v).replace(/"/g, '&quot;')}"`).join(' ');
  return `<button class="term-button ${active ? 'active' : ''} ${danger ? 'danger' : ''}" ${disabled ? 'disabled' : ''} data-action="${action}" ${dataAttrs}>${iconHtml}${label}</button>`;
}
