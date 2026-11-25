# NIDPS Dashboard Frontend

A static, dependency-free (beyond a vendored Chart.js) HTML/CSS/JS single-page app. No build step —
open `index.html` through any static file server and it runs.

## Running it

```bash
cd frontend
python3 -m http.server 5173
```

Then open `http://localhost:5173`.

## Talking to the backend

This client calls the `services/dashboard` FastAPI contract documented in
`docs/superpowers/plans/2026-10-10-06-management-dashboard.md` (Task 13):

- `POST /api/login`, `POST /api/logout`
- `GET /api/overview`, `GET /api/alerts`, `GET /api/alerts/{verdict_id}/evidence`
- `GET /api/blocked-hosts`, `POST /api/blocked-hosts/{ip}/unblock`
- `GET /api/allowlist`, `POST /api/allowlist`, `DELETE /api/allowlist/{entry_id}`
- `GET /api/hosts`, `GET /api/settings/{tab}`, `PUT /api/settings/{key}`
- `POST /api/admin/reload-rules`, `POST /api/admin/recalibrate`
- `GET /api/health`, `GET /api/models`
- `GET /api/export/alerts.csv` / `.../blocks.csv`
- `WS /ws/live` — pushes a live snapshot (`flows_analyzed`/`intrusions_detected`/`active_blocks`)
  every time it receives a ping from the client; `js/ws.js` pings every `LIVE_REFRESH_MS` (2s) to
  satisfy the >=2s refresh requirement.

By default the client assumes the API is same-origin. To point at a different host during
development, set these before `js/app.js` loads (e.g. a small inline `<script>` in `index.html`):

```html
<script>
  window.NIDPS_API_BASE = 'http://localhost:8443';
  window.NIDPS_WS_BASE = 'ws://localhost:8443';
</script>
```

If every API call in `js/api.js` is unreachable (connection refused, or a 404 because this page is
being served standalone with no backend behind it), it falls back to the fixture data in
`js/demoData.js` so the UI stays fully browsable. A real `401` from a running backend is never
swallowed by that fallback — it sends you to the login screen, same as it would with the backend
live.

### Running against the real backend

`services/dashboard/` (see the top-level `README.md`, step 7) implements this exact API. Since the
frontend (port 5173 above) and the dashboard (port 8443 by default) are different origins, and
session auth is a cookie, the dashboard needs to be told to allow credentialed requests from this
origin:

```bash
NIDPS_DASHBOARD_CORS_ORIGINS=http://localhost:5173 python3 -m services.dashboard.main
```

(or set `NIDPS_DASHBOARD_CORS_ORIGINS` once in the repo root's `.env` — see the main `README.md`'s
"Environment variables" section — so you don't need to repeat it every time.)

Then set `window.NIDPS_API_BASE`/`window.NIDPS_WS_BASE` as shown above and reload. Without that
env var, the dashboard sends no CORS headers at all (correct for a same-origin deployment, e.g.
this frontend served by the dashboard itself) and the browser will refuse the cross-origin
request — the UI falls back to demo data in that case rather than erroring visibly, so if data
looks static, check this first.

## Folder structure

```
frontend/
  index.html          entry point
  css/
    theme.css          color tokens (dark/light), fonts, reset
    layout.css         shell: sidebar, topbar, workspace grid, responsive breakpoints
    components.css     panes, tables, buttons, status pills, tabs, forms
    login.css          login screen
  js/
    app.js             bootstrap: shell, theme toggle, auth gate, live WebSocket wiring
    config.js           API base URL, WS base URL, refresh interval
    api.js               REST client + demo-data fallback
    ws.js                 LiveSocket: WebSocket wrapper with reconnect + polling fallback
    state.js              tiny app-wide store (theme, session, live stats)
    router.js             hash-based page router
    icons.js               inline-SVG icon set
    demoData.js             offline fixture data (see "Talking to the backend" above)
    components/              pane.js, table.js, status.js, button.js, dialog.js — small render helpers
    charts/                   lineChart.js — Chart.js wrapper for the traffic-history chart
    pages/                     overview.js, traffic.js, alerts.js, blocked.js, config.js, health.js, login.js
  vendor/
    chart.umd.min.js            vendored Chart.js build (no CDN at runtime)
  assets/
    favicon.svg
```
