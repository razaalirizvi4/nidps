export function statusPill(text, tone = 'green') {
  return `<span class="status ${tone}">${escapeHtml(text)}</span>`;
}

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
