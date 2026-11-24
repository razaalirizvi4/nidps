// Minimal inline-SVG icon set (stroke-based, 24x24, no dependency) used across the dashboard.
// Add new icons by extending PATHS -- icon() wraps whatever markup is given in a sized <svg>.

const PATHS = {
  terminal: '<polyline points="4 6 9 12 4 18"/><line x1="11" y1="18" x2="20" y2="18"/>',
  network: '<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><line x1="12" y1="7.5" x2="6.2" y2="17"/><line x1="12" y1="7.5" x2="17.8" y2="17"/>',
  'shield-alert': '<path d="M12 3l7 3v6c0 5-3.5 7.5-7 9-3.5-1.5-7-4-7-9V6l7-3z"/><line x1="12" y1="9" x2="12" y2="13.5"/><circle cx="12" cy="16.3" r="0.6" fill="currentColor" stroke="none"/>',
  ban: '<circle cx="12" cy="12" r="9"/><line x1="5.6" y1="5.6" x2="18.4" y2="18.4"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M12 2.5v3M12 18.5v3M4.2 6.2l2.1 2.1M17.7 15.7l2.1 2.1M1.5 12h3M19.5 12h3M4.2 17.8l2.1-2.1M17.7 8.3l2.1-2.1"/>',
  activity: '<polyline points="2.5 13 7 13 9.5 20 14.5 4 17 13 21.5 13"/>',
  menu: '<line x1="3.5" y1="7" x2="20.5" y2="7"/><line x1="3.5" y1="12" x2="20.5" y2="12"/><line x1="3.5" y1="17" x2="20.5" y2="17"/>',
  sun: '<circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.4M12 19.1v2.4M4.2 4.2l1.7 1.7M18.1 18.1l1.7 1.7M2.5 12h2.4M19.1 12h2.4M4.2 19.8l1.7-1.7M18.1 5.9l1.7-1.7"/>',
  moon: '<path d="M20 14.5A8.5 8.5 0 1 1 9.5 4 7 7 0 0 0 20 14.5z"/>',
  'log-out': '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="15 16 20 12 15 8"/><line x1="20" y1="12" x2="8.5" y2="12"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><line x1="20" y1="20" x2="15.3" y2="15.3"/>',
  check: '<polyline points="4.5 12.5 9.5 17.5 19.5 6.5"/>',
  'chevron-right': '<polyline points="9 5 16 12 9 19"/>',
  'rotate-ccw': '<path d="M3.5 12a8.5 8.5 0 1 0 2.8-6.3"/><polyline points="2.5 4 3.3 8.8 8 7.6"/>',
  save: '<path d="M4 4h12l4 4v12H4z"/><rect x="8" y="14" width="8" height="6"/><rect x="8" y="4" width="6" height="4"/>',
  x: '<line x1="5.5" y1="5.5" x2="18.5" y2="18.5"/><line x1="18.5" y1="5.5" x2="5.5" y2="18.5"/>',
  'alert-triangle': '<path d="M12 3.5 21.5 20h-19z"/><line x1="12" y1="9.5" x2="12" y2="14.5"/><circle cx="12" cy="17.2" r="0.6" fill="currentColor" stroke="none"/>',
  'chevron-down': '<polyline points="5 9 12 16 19 9"/>',
};

export function icon(name, { size = 16, className = '' } = {}) {
  const body = PATHS[name];
  if (!body) return '';
  return `<svg class="${className}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
}
