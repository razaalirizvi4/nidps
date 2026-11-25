"""Dashboard entry point. Runs the Event Store and live-stats consumers on background threads and
serves the FastAPI app via uvicorn in the foreground, publishing a heartbeat every
watchdog.heartbeat_interval_s so a future watchdog service can supervise this process the same way
it supervises decision/flowextract/sigbridge/mlscorer/arpmon today -- no watchdog service exists
yet in this codebase, so nothing currently consumes this heartbeat; publishing it anyway costs
nothing and means there's no second change needed when one is built.

No admin_user row is created automatically -- run
`python -m services.dashboard.create_admin <db_path> <username> <password>` once before first
login."""
from __future__ import annotations

import os
import threading
import time

import uvicorn

from common.bus import STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, encode_envelope
from common.config_loader import get as config_get
from common.config_loader import seed_defaults
from common.db.migrate import connect
from common.env import load_env
from common.logging_setup import configure_logging
from common.schemas import ComponentHealth, HealthState, utc_now_iso

from services.dashboard.api import create_app
from services.dashboard.event_store import EventStore
from services.dashboard.live_stats import LiveStats
from services.dashboard.sessions import SessionStore

COMPONENT_NAME = "dashboard"


def _run_consumer_loop(name: str, consume_once, stop_event: threading.Event) -> None:
    logger = configure_logging(f"{COMPONENT_NAME}.{name}")
    while not stop_event.is_set():
        try:
            consume_once(block_ms=1000)
        except Exception:
            logger.exception("consumer loop error")
            time.sleep(1.0)


def _heartbeat_loop(bus: EventBus, config_fn, stop_event: threading.Event) -> None:
    logger = configure_logging(COMPONENT_NAME)
    while not stop_event.is_set():
        interval = float(config_fn("watchdog.heartbeat_interval_s"))
        health = ComponentHealth(
            name=COMPONENT_NAME, state=HealthState.NORMAL, last_heartbeat=utc_now_iso()
        )
        bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, health))
        logger.info('{"event": "heartbeat"}')
        time.sleep(interval)


def main() -> None:
    load_env()
    db_path = os.environ.get("NIDPS_DB_PATH", "/var/lib/nidps/nidps.sqlite3")
    redis_url = os.environ.get("NIDPS_REDIS_URL", "redis://localhost:6379/0")
    host = os.environ.get("NIDPS_DASHBOARD_HOST", "0.0.0.0")
    port = int(os.environ.get("NIDPS_DASHBOARD_PORT", "8443"))
    cors_origins_env = os.environ.get("NIDPS_DASHBOARD_CORS_ORIGINS", "")
    cors_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()] or None

    # check_same_thread=False: this connection is shared between uvicorn's request-handling
    # threadpool and this process's own background consumer/heartbeat threads below.
    conn = connect(db_path, check_same_thread=False)
    seed_defaults(conn)
    bus = EventBus.from_url(redis_url)
    session_store = SessionStore(bus._client, ttl_s=1800)

    event_store = EventStore(conn, bus)
    live_stats = LiveStats(conn, bus)
    stop_event = threading.Event()

    threads = [
        threading.Thread(
            target=_run_consumer_loop, args=("event-store", event_store.consume_once, stop_event),
            daemon=True,
        ),
        threading.Thread(
            target=_run_consumer_loop, args=("live-stats", live_stats.consume_once, stop_event),
            daemon=True,
        ),
        threading.Thread(
            target=_heartbeat_loop, args=(bus, lambda key: config_get(conn, key), stop_event),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()

    app = create_app(conn, bus, session_store, live_stats, cors_origins=cors_origins)
    try:
        uvicorn.run(app, host=host, port=port, log_level="info")
    finally:
        stop_event.set()


if __name__ == "__main__":
    main()
