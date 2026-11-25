import fakeredis

from common.bus import STREAM_FLOWS, STREAM_VERDICTS, EventBus
from common.bus_messages import MessageType, encode_envelope
from common.db.migrate import connect
from common.schemas import Action, Verdict
from services.dashboard.live_stats import LiveStats


def _bus():
    return EventBus(fakeredis.FakeRedis(decode_responses=True))


def test_snapshot_starts_at_zero():
    conn = connect(":memory:")
    stats = LiveStats(conn, _bus())

    assert stats.snapshot() == {"flows_analyzed": 0, "intrusions_detected": 0, "active_blocks": 0}


def test_flow_ready_messages_increment_flows_analyzed():
    conn = connect(":memory:")
    bus = _bus()
    stats = LiveStats(conn, bus)
    bus.publish(STREAM_FLOWS, encode_envelope(MessageType.FLOW_READY, {"flow_id": 1, "host_ip": "10.0.0.1"}))
    bus.publish(STREAM_FLOWS, encode_envelope(MessageType.FLOW_READY, {"flow_id": 2, "host_ip": "10.0.0.1"}))

    stats.consume_once(block_ms=100)

    assert stats.snapshot()["flows_analyzed"] == 2


def test_alert_and_block_verdicts_increment_intrusions_detected_but_pass_does_not():
    conn = connect(":memory:")
    bus = _bus()
    stats = LiveStats(conn, bus)
    for action in (Action.ALERT, Action.BLOCK, Action.PASS):
        verdict = Verdict(action=action, layers=[], explanation="x", host_ip="10.0.0.1")
        bus.publish(STREAM_VERDICTS, encode_envelope(MessageType.VERDICT, verdict))

    stats.consume_once(block_ms=100)

    assert stats.snapshot()["intrusions_detected"] == 2


def test_active_blocks_reads_from_database():
    conn = connect(":memory:")
    conn.execute("INSERT INTO host (ip_address, is_internal) VALUES ('10.0.0.5', 1)")
    host_id = conn.execute("SELECT host_id FROM host").fetchone()[0]
    conn.execute(
        "INSERT INTO verdict (host_id, decision, layers, explanation) VALUES (?, 'BLOCK', '[]', 'x')",
        (host_id,),
    )
    verdict_id = conn.execute("SELECT verdict_id FROM verdict").fetchone()[0]
    conn.execute(
        "INSERT INTO block_entry (host_id, verdict_id, offence_count, duration_s, start_time, "
        "expires_at, status) VALUES (?, ?, 1, 300, '2026-01-01T00:00:00Z', '2026-01-01T00:05:00Z', 'ACTIVE')",
        (host_id, verdict_id),
    )
    conn.commit()
    stats = LiveStats(conn, _bus())

    assert stats.snapshot()["active_blocks"] == 1
