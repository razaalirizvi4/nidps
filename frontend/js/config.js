// Runtime configuration for the NIDPS dashboard frontend.
//
// API_BASE / WS_BASE default to same-origin, which is correct once this static site is served by
// (or alongside) the services/dashboard FastAPI app. Override by setting window.NIDPS_API_BASE /
// window.NIDPS_WS_BASE before this script runs (e.g. a small inline <script> in index.html) if the
// API is hosted elsewhere during development.
export const API_BASE = window.NIDPS_API_BASE || '';
export const WS_BASE = window.NIDPS_WS_BASE || (API_BASE || (location.origin.replace(/^http/, 'ws')));

// FR-9.2: the dashboard must refresh at least every 2 seconds. The /ws/live endpoint (see
// docs/superpowers/plans/2026-10-10-06-management-dashboard.md, Task 13) only pushes a fresh
// snapshot after it receives a text frame from the client, so this is the client-side ping period
// that drives that cadence -- keep this at or below 2000ms.
export const LIVE_REFRESH_MS = 2000;

export const SESSION_STORAGE_KEY = 'nidps.session_token';
export const THEME_STORAGE_KEY = 'nidps.theme';
