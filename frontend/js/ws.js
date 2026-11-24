// LiveSocket: wraps /ws/live from services/dashboard (see docs/superpowers/plans/
// 2026-10-10-06-management-dashboard.md, Task 13). That endpoint sends one snapshot on connect,
// then waits for a text frame from the client before sending the next one -- so this class's own
// ping timer (every LIVE_REFRESH_MS) is what actually drives the >=2s refresh cadence (FR-9.2),
// not a server-side timer. Falls back to local polling via `pollFallback` if the socket never
// connects (e.g. the backend doesn't exist yet), so callers always keep getting updates.
import { WS_BASE, LIVE_REFRESH_MS } from './config.js';

const RECONNECT_DELAYS_MS = [1000, 2000, 5000, 10000];

export class LiveSocket {
  constructor({ token, onMessage, onStatus, pollFallback }) {
    this._token = token;
    this._onMessage = onMessage;
    this._onStatus = onStatus || (() => {});
    this._pollFallback = pollFallback;
    this._pingTimer = null;
    this._reconnectAttempt = 0;
    this._closedByUser = false;
    this._pollTimer = null;
    this._socket = null;
  }

  start() {
    this._closedByUser = false;
    this._connect();
  }

  stop() {
    this._closedByUser = true;
    clearInterval(this._pingTimer);
    clearInterval(this._pollTimer);
    this._socket?.close();
  }

  _connect() {
    this._setStatus(this._reconnectAttempt === 0 ? 'connecting' : 'reconnecting');
    let socket;
    try {
      socket = new WebSocket(`${WS_BASE}/ws/live?token=${encodeURIComponent(this._token)}`);
    } catch {
      this._fallbackToPolling();
      return;
    }
    this._socket = socket;

    socket.onopen = () => {
      this._reconnectAttempt = 0;
      clearInterval(this._pollTimer);
      this._setStatus('connected');
      this._pingTimer = setInterval(() => {
        if (socket.readyState === WebSocket.OPEN) socket.send('ping');
      }, LIVE_REFRESH_MS);
    };
    socket.onmessage = (event) => {
      try {
        this._onMessage(JSON.parse(event.data));
      } catch {
        /* ignore malformed frame */
      }
    };
    socket.onclose = () => {
      clearInterval(this._pingTimer);
      if (this._closedByUser) return;
      this._setStatus('reconnecting');
      const delay = RECONNECT_DELAYS_MS[Math.min(this._reconnectAttempt, RECONNECT_DELAYS_MS.length - 1)];
      this._reconnectAttempt += 1;
      if (this._reconnectAttempt >= 3) this._fallbackToPolling();
      setTimeout(() => {
        if (!this._closedByUser) this._connect();
      }, delay);
    };
    socket.onerror = () => socket.close();
  }

  _fallbackToPolling() {
    if (this._pollTimer || !this._pollFallback) return;
    this._setStatus('offline');
    this._pollTimer = setInterval(async () => {
      try {
        this._onMessage(await this._pollFallback());
      } catch {
        /* keep retrying silently */
      }
    }, LIVE_REFRESH_MS);
  }

  _setStatus(status) {
    this._onStatus(status);
  }
}
