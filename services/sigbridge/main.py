"""Entry point for the Suricata eve.json bridge. process_alerts() is the dependency-injected core
every test calls; main() wraps it in a real polling loop with a heartbeat tick."""
from __future__ import annotations

import os
import time

from common.bus import STREAM_EVIDENCE, STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, encode_envelope
from common.config_loader import get as config_get
from common.db.migrate import connect
from services.sigbridge.eve_tailer import EveTailer
from services.sigbridge.signature_detector import SignatureDetector


def process_alerts(conn, bus: EventBus, detector: SignatureDetector, alerts) -> int:
    weight = config_get(conn, "risk.weight_signature")
    published = 0
    for alert in alerts:
        ev = detector.ingestEveAlert(alert)
        ev.weight = weight
        bus.publish(STREAM_EVIDENCE, encode_envelope(MessageType.EVIDENCE, ev))
        published += 1
    return published


def publish_heartbeat(bus: EventBus, detector: SignatureDetector) -> None:
    bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, detector.heartbeat()))


def main() -> None:
    db_path = os.environ.get("NIDPS_DB_PATH", "/var/lib/nidps/nidps.sqlite3")
    redis_url = os.environ.get("NIDPS_REDIS_URL", "redis://localhost:6379/0")
    eve_path = os.environ.get("NIDPS_EVE_JSON_PATH", "/var/log/suricata/eve.json")

    conn = connect(db_path)
    bus = EventBus.from_url(redis_url)
    tailer = EveTailer(eve_path)
    detector = SignatureDetector()

    last_heartbeat = 0.0
    while True:
        alerts = tailer.poll()
        if alerts:
            process_alerts(conn, bus, detector, alerts)
        now = time.time()
        heartbeat_interval = config_get(conn, "watchdog.heartbeat_interval_s")
        if now - last_heartbeat >= heartbeat_interval:
            publish_heartbeat(bus, detector)
            last_heartbeat = now
        time.sleep(1.0)


if __name__ == "__main__":
    main()
