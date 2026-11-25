"""FastAPI app wiring every dashboard module into the routes the six screens call (FR-9, FR-10,
FR-11.3). create_app() takes its conn/bus/session_store as parameters rather than constructing
them itself, so every test here runs against an in-memory DB and fakeredis with no real network or
filesystem dependency."""
from __future__ import annotations

import sqlite3

from fastapi import Cookie, Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

from common.bus import EventBus
from common.config_loader import get as cfg_get
from services.dashboard import csv_export, queries
from services.dashboard.admin_commands import AdminCommands
from services.dashboard.auth import authenticate
from services.dashboard.config_api import get_tab, update_setting
from services.dashboard.live_stats import LiveStats
from services.dashboard.sessions import SessionStore

SESSION_COOKIE = "nidps_session"


class LoginRequest(BaseModel):
    username: str
    password: str


class SettingUpdate(BaseModel):
    value: object


class AllowlistCreate(BaseModel):
    address: str
    description: str = ""


def create_app(
    conn: sqlite3.Connection,
    bus: EventBus,
    session_store: SessionStore,
    live_stats: LiveStats,
    cors_origins: list[str] | None = None,
) -> FastAPI:
    """cors_origins: the frontend (frontend/, a static HTML/CSS/JS site -- see its README) is
    normally served from a different origin/port than this API during development, e.g.
    http://localhost:5173 against this API on :8443. Session auth is a cookie, so credentialed
    cross-origin requests need an explicit allow-list (CORS forbids combining
    allow_credentials=True with a wildcard "*" origin) -- pass the frontend's origin(s) here, or
    leave unset for a same-origin deployment (e.g. this API also serving the built frontend),
    where no CORS headers are needed at all.

    live_stats: must be the SAME LiveStats instance whose consume_once() is being driven by a
    background thread (see main.py) -- its in-memory counters only move when something calls
    consume_once() on that exact object. Constructing a second, separate LiveStats(conn, bus) here
    (the original bug this comment replaces) silently produces a live_stats.snapshot() that is
    always frozen at zero flows/intrusions, since nothing ever consumes into it."""
    app = FastAPI(title="NIDPS Dashboard API")
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    admin_commands = AdminCommands(bus)

    def _config_get(key: str):
        return cfg_get(conn, key)

    def require_session(nidps_session: str | None = Cookie(default=None)) -> int:
        user_id = session_store.user_id_for(nidps_session) if nidps_session else None
        if user_id is None:
            raise HTTPException(status_code=401, detail="not_authenticated")
        return user_id

    @app.post("/api/login")
    def login(body: LoginRequest):
        result = authenticate(conn, _config_get, body.username, body.password)
        if not result.ok:
            raise HTTPException(status_code=401, detail=result.reason)
        token = session_store.create(result.user_id)
        resp = JSONResponse({"ok": True, "token": token})
        resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax")
        return resp

    @app.post("/api/logout")
    def logout(nidps_session: str | None = Cookie(default=None)):
        if nidps_session:
            session_store.revoke(nidps_session)
        return {"ok": True}

    @app.get("/api/overview")
    def overview(user_id: int = Depends(require_session)):
        return live_stats.snapshot()

    @app.get("/api/alerts")
    def alerts(
        host_ip: str | None = None, attack_class: str | None = None, limit: int = 50,
        user_id: int = Depends(require_session),
    ):
        return queries.list_alerts(conn, limit=limit, host_ip=host_ip, attack_class=attack_class)

    @app.get("/api/alerts/{verdict_id}/evidence")
    def evidence(verdict_id: int, user_id: int = Depends(require_session)):
        return queries.alert_evidence(conn, verdict_id)

    @app.get("/api/blocked-hosts")
    def blocked_hosts(user_id: int = Depends(require_session)):
        return queries.list_blocked_hosts(conn)

    @app.post("/api/blocked-hosts/{ip}/unblock", status_code=202)
    def unblock(ip: str, user_id: int = Depends(require_session)):
        admin_commands.request_unblock(ip, requested_by=user_id)
        return {"ok": True, "status": "requested"}

    @app.get("/api/allowlist")
    def allowlist(user_id: int = Depends(require_session)):
        return queries.list_allowlist(conn)

    @app.post("/api/allowlist")
    def add_allowlist(body: AllowlistCreate, user_id: int = Depends(require_session)):
        entry_id = queries.add_allowlist_entry(conn, body.address, body.description, added_by=user_id)
        return {"entry_id": entry_id}

    @app.delete("/api/allowlist/{entry_id}")
    def remove_allowlist(entry_id: int, user_id: int = Depends(require_session)):
        queries.remove_allowlist_entry(conn, entry_id)
        return {"ok": True}

    @app.get("/api/hosts")
    def hosts(user_id: int = Depends(require_session)):
        return queries.list_hosts(conn)

    @app.get("/api/settings/{tab}")
    def settings_tab(tab: str, user_id: int = Depends(require_session)):
        try:
            return get_tab(conn, tab)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown_tab")

    @app.put("/api/settings/{key}")
    def settings_update(key: str, body: SettingUpdate, user_id: int = Depends(require_session)):
        try:
            update_setting(conn, key, body.value, user_id=user_id)
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"ok": True}

    @app.post("/api/admin/reload-rules", status_code=202)
    def reload_rules(user_id: int = Depends(require_session)):
        admin_commands.request_reload_rules(requested_by=user_id)
        return {"ok": True, "status": "requested"}

    @app.post("/api/admin/recalibrate", status_code=202)
    def recalibrate(user_id: int = Depends(require_session)):
        admin_commands.request_recalibration(requested_by=user_id)
        return {"ok": True, "status": "requested"}

    @app.get("/api/health")
    def health(user_id: int = Depends(require_session)):
        return queries.component_health(conn)

    @app.get("/api/models")
    def models(user_id: int = Depends(require_session)):
        return queries.list_models(conn)

    @app.get("/api/export/alerts.csv")
    def export_alerts(start: str = Query(...), end: str = Query(...), user_id: int = Depends(require_session)):
        return PlainTextResponse(csv_export.export_alerts_csv(conn, start, end), media_type="text/csv")

    @app.get("/api/export/blocks.csv")
    def export_blocks(start: str = Query(...), end: str = Query(...), user_id: int = Depends(require_session)):
        return PlainTextResponse(csv_export.export_blocks_csv(conn, start, end), media_type="text/csv")

    @app.websocket("/ws/live")
    async def ws_live(websocket: WebSocket, token: str = Query(...)):
        user_id = session_store.user_id_for(token)
        if user_id is None:
            await websocket.close(code=4401)
            return
        await websocket.accept()
        try:
            await websocket.send_json(live_stats.snapshot())
            while True:
                await websocket.receive_text()  # keepalive ping from the client; ignored
                await websocket.send_json(live_stats.snapshot())
        except WebSocketDisconnect:
            pass

    return app
