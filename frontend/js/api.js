// Thin client for the services/dashboard FastAPI contract documented in
// docs/superpowers/plans/2026-10-10-06-management-dashboard.md (Task 13). Session auth is a
// cookie set by /api/login; this client never stores the password and only keeps the WS token
// (needed because WebSocket requests can't carry the httponly cookie's value for the ?token=
// query param -- the backend plan hands it back in the login JSON body for exactly this reason).
import { API_BASE } from './config.js';
import * as demo from './demoData.js';

export class UnauthorizedError extends Error {}
export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options,
    });
  } catch (networkError) {
    throw networkError; // caller decides whether to fall back to demo data
  }
  if (response.status === 401) {
    // The server's actual reason matters here: /api/login's 401 body is "invalid_credentials" or
    // "locked", distinct from a protected route's generic "not_authenticated" -- losing that (as
    // this used to, by hardcoding the message) makes a wrong password look identical to a locked
    // account or an expired session, with no way for the user to tell which actually happened.
    const body = await response.json().catch(() => ({}));
    throw new UnauthorizedError(body.detail || 'not_authenticated');
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new ApiError(body.detail || `request failed: ${response.status}`, response.status);
  }
  return response;
}

// Wraps a live-API call with a fallback to demo data when there's effectively no backend to talk
// to: a network-level failure (connection refused -- the real services/dashboard isn't running),
// or a 404 (no such route -- e.g. this frontend served standalone by a plain static file server,
// which 404s /api/* instead of refusing the connection). A 401 always propagates -- that means
// "log in again", not "show demo data" -- and so does any other 4xx/5xx, which indicates a real
// backend that is misbehaving rather than simply absent.
async function withDemoFallback(liveCall, demoValue) {
  try {
    return await liveCall();
  } catch (err) {
    if (err instanceof UnauthorizedError) throw err;
    if (err instanceof ApiError && err.status !== 404) throw err;
    console.info('[nidps] API unreachable, using demo data:', err.message);
    return demoValue;
  }
}

export async function login(username, password) {
  const res = await request('/api/login', { method: 'POST', body: JSON.stringify({ username, password }) });
  return res.json(); // { ok, token }
}

export async function logout() {
  try {
    await request('/api/logout', { method: 'POST' });
  } catch {
    // best-effort; the client clears its own session state regardless
  }
}

export function getOverview() {
  return withDemoFallback(async () => (await request('/api/overview')).json(), demo.demoOverview);
}

export function getAlerts(params = {}) {
  const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''));
  return withDemoFallback(
    async () => (await request(`/api/alerts${qs.toString() ? `?${qs}` : ''}`)).json(),
    demo.demoAlerts,
  );
}

export function getAlertEvidence(verdictId) {
  return withDemoFallback(
    async () => (await request(`/api/alerts/${verdictId}/evidence`)).json(),
    demo.demoEvidence[verdictId] || [],
  );
}

export function getBlockedHosts() {
  return withDemoFallback(async () => (await request('/api/blocked-hosts')).json(), demo.demoBlockedHosts);
}

export async function unblockHost(ip) {
  return (await request(`/api/blocked-hosts/${encodeURIComponent(ip)}/unblock`, { method: 'POST' })).json();
}

export function getAllowlist() {
  return withDemoFallback(async () => (await request('/api/allowlist')).json(), demo.demoAllowlist);
}

export async function addAllowlistEntry(address, description) {
  return (await request('/api/allowlist', { method: 'POST', body: JSON.stringify({ address, description }) })).json();
}

export async function removeAllowlistEntry(entryId) {
  return (await request(`/api/allowlist/${entryId}`, { method: 'DELETE' })).json();
}

export function getHosts() {
  return withDemoFallback(async () => (await request('/api/hosts')).json(), demo.demoHosts);
}

export function getSettingsTab(tab) {
  return withDemoFallback(
    async () => (await request(`/api/settings/${tab}`)).json(),
    demo.demoSettingsTabs[tab] || [],
  );
}

export async function updateSetting(key, value) {
  return (await request(`/api/settings/${encodeURIComponent(key)}`, { method: 'PUT', body: JSON.stringify({ value }) })).json();
}

export async function requestReloadRules() {
  return (await request('/api/admin/reload-rules', { method: 'POST' })).json();
}

export async function requestRecalibration() {
  return (await request('/api/admin/recalibrate', { method: 'POST' })).json();
}

export function getHealth() {
  return withDemoFallback(async () => (await request('/api/health')).json(), demo.demoHealth);
}

export function getModels() {
  return withDemoFallback(async () => (await request('/api/models')).json(), demo.demoModels);
}

export function exportUrl(kind, start, end) {
  const qs = new URLSearchParams({ start, end });
  return `${API_BASE}/api/export/${kind}.csv?${qs}`;
}
