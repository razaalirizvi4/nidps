import fakeredis
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from common.bus import EventBus
from common.config_loader import seed_defaults
from common.db.migrate import connect
from services.dashboard.api import create_app
from services.dashboard.auth import create_admin_user
from services.dashboard.live_stats import LiveStats
from services.dashboard.sessions import SessionStore


def _client():
    # check_same_thread=False: FastAPI dispatches sync routes to a worker-threadpool thread,
    # which differs from the thread this fixture runs on. See common/db/migrate.py::connect().
    conn = connect(":memory:", check_same_thread=False)
    seed_defaults(conn)
    create_admin_user(conn, "admin", "correct-password")
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    sessions = SessionStore(fakeredis.FakeRedis(decode_responses=True))
    live_stats = LiveStats(conn, bus)
    app = create_app(conn, bus, sessions, live_stats)
    return TestClient(app), conn, live_stats


def test_protected_route_rejects_unauthenticated_request():
    client, _, _ = _client()

    response = client.get("/api/overview")

    assert response.status_code == 401


def test_login_with_wrong_password_returns_generic_error():
    client, _, _ = _client()

    response = client.post("/api/login", json={"username": "admin", "password": "wrong"})

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_credentials"


def test_login_then_overview_succeeds():
    client, _, _ = _client()

    login = client.post("/api/login", json={"username": "admin", "password": "correct-password"})
    assert login.status_code == 200

    overview = client.get("/api/overview")
    assert overview.status_code == 200
    body = overview.json()
    assert "flows_analyzed" in body
    assert "intrusions_detected" in body
    assert "active_blocks" in body


def test_logout_revokes_session():
    client, _, _ = _client()
    client.post("/api/login", json={"username": "admin", "password": "correct-password"})

    client.post("/api/logout")

    assert client.get("/api/overview").status_code == 401


def test_settings_tab_requires_auth_then_returns_rows():
    client, _, _ = _client()
    client.post("/api/login", json={"username": "admin", "password": "correct-password"})

    response = client.get("/api/settings/detection_layers")

    assert response.status_code == 200
    keys = {row["key"] for row in response.json()}
    assert "detection.layer1_enabled" in keys


def test_update_setting_then_read_back():
    client, _, _ = _client()
    client.post("/api/login", json={"username": "admin", "password": "correct-password"})

    put = client.put("/api/settings/risk.block_threshold", json={"value": 7.0})
    assert put.status_code == 200

    rows = client.get("/api/settings/thresholds").json()
    row = next(r for r in rows if r["key"] == "risk.block_threshold")
    assert row["value"] == 7.0


def test_allowlist_add_then_list():
    client, _, _ = _client()
    client.post("/api/login", json={"username": "admin", "password": "correct-password"})

    add = client.post("/api/allowlist", json={"address": "192.168.1.1", "description": "ISP gateway"})
    assert add.status_code == 200

    rows = client.get("/api/allowlist").json()
    assert any(r["address"] == "192.168.1.1" for r in rows)


def test_unblock_route_publishes_admin_command_without_error():
    client, _, _ = _client()
    client.post("/api/login", json={"username": "admin", "password": "correct-password"})

    response = client.post("/api/blocked-hosts/10.0.0.5/unblock")

    assert response.status_code == 202  # accepted -- see admin_commands.py's documented gap


def test_export_alerts_csv_returns_csv_content_type():
    client, _, _ = _client()
    client.post("/api/login", json={"username": "admin", "password": "correct-password"})

    response = client.get(
        "/api/export/alerts.csv",
        params={"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T00:00:00Z"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")


def test_websocket_live_requires_valid_session_token():
    client, _, _ = _client()
    login = client.post("/api/login", json={"username": "admin", "password": "correct-password"})
    token = login.json()["token"]

    with client.websocket_connect(f"/ws/live?token={token}") as ws:
        message = ws.receive_json()
        assert "flows_analyzed" in message


def test_websocket_live_rejects_invalid_token():
    client, _, _ = _client()

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/live?token=not-a-real-token"):
            pass


def test_cors_allows_credentialed_requests_from_a_configured_frontend_origin():
    """The frontend (frontend/) is normally served from a different origin/port than this API in
    development -- session auth is a cookie, so the allow-list must echo back the specific origin
    with allow-credentials, not a wildcard (browsers reject "*" combined with credentials)."""
    conn = connect(":memory:", check_same_thread=False)
    seed_defaults(conn)
    create_admin_user(conn, "admin", "correct-password")
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    sessions = SessionStore(fakeredis.FakeRedis(decode_responses=True))
    live_stats = LiveStats(conn, bus)
    app = create_app(conn, bus, sessions, live_stats, cors_origins=["http://localhost:5173"])
    client = TestClient(app)

    response = client.get(
        "/api/overview", headers={"Origin": "http://localhost:5173"}
    )

    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert response.headers["access-control-allow-credentials"] == "true"


def test_cors_headers_absent_without_configured_origins():
    client, _, _ = _client()

    response = client.get("/api/overview", headers={"Origin": "http://localhost:5173"})

    assert "access-control-allow-origin" not in response.headers


def test_overview_reflects_the_same_live_stats_instance_a_consumer_would_drive():
    """Regression test for a real bug caught in live smoke testing: create_app() used to construct
    its own private LiveStats(conn, bus), separate from the one a background thread's
    consume_once() loop actually feeds (see main.py) -- so /api/overview and /ws/live always read
    a frozen-at-zero snapshot no matter how much real traffic the system processed. This asserts
    that mutating the exact LiveStats object passed into create_app() is what /api/overview sees,
    which only holds if it's the same object (not a copy or a separately-constructed one)."""
    client, _, live_stats = _client()
    client.post("/api/login", json={"username": "admin", "password": "correct-password"})
    live_stats._flows_analyzed = 42
    live_stats._intrusions_detected = 7

    body = client.get("/api/overview").json()

    assert body["flows_analyzed"] == 42
    assert body["intrusions_detected"] == 7
