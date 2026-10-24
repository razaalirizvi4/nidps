import fakeredis

from common.bus import STREAM_EVIDENCE, STREAM_HEARTBEATS, EventBus
from common.bus_messages import decode_envelope
from common.config_loader import seed_defaults
from common.db.migrate import connect
from services.sigbridge.main import process_alerts, publish_heartbeat
from services.sigbridge.signature_detector import SignatureDetector


def test_process_alerts_fills_weight_and_publishes_evidence():
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    detector = SignatureDetector()
    alerts = [
        {"src_ip": "10.0.0.5", "alert": {"signature_id": 1, "severity": 1, "action": "drop"}},
    ]

    published = process_alerts(conn, bus, detector, alerts)

    assert published == 1
    received = []
    bus.consume(
        STREAM_EVIDENCE, group="decision", consumer="c1", handler=received.append, block_ms=100
    )
    assert len(received) == 1
    envelope = decode_envelope(received[0])
    assert envelope["payload"]["strength"] == 1.0
    assert envelope["payload"]["weight"] == 3.0  # risk.weight_signature default


def test_publish_heartbeat_sends_component_health():
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    detector = SignatureDetector()
    publish_heartbeat(bus, detector)

    received = []
    bus.consume(
        STREAM_HEARTBEATS, group="watchdog", consumer="c1", handler=received.append, block_ms=100
    )
    assert len(received) == 1
    assert decode_envelope(received[0])["payload"]["name"] == "sigbridge"
