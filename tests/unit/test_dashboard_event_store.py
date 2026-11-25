import fakeredis

from common.bus import STREAM_EVIDENCE, STREAM_HOST_SCORES, EventBus
from common.bus_messages import MessageType, encode_envelope
from common.db.migrate import connect
from common.schemas import Evidence, EvidenceType, HostScore, Layer
from services.dashboard.event_store import EventStore


def _bus():
    return EventBus(fakeredis.FakeRedis(decode_responses=True))


def test_handle_evidence_writes_row_and_upserts_host():
    conn = connect(":memory:")
    store = EventStore(conn, _bus())
    ev = Evidence(
        source=Layer.L1_SIGNATURE, flow_id="42", host_ip="10.0.0.5",
        kind=EvidenceType.SIGNATURE, strength=1.0, weight=3.0, signature_id=2032754,
    )
    raw = encode_envelope(MessageType.EVIDENCE, ev)

    store.handle_evidence(raw)

    row = conn.execute(
        "SELECT layer, evidence_type, signature_id, score, weight FROM evidence"
    ).fetchone()
    assert row == ("L1", "SIGNATURE", 2032754, 1.0, 3.0)
    host = conn.execute("SELECT ip_address FROM host WHERE ip_address = '10.0.0.5'").fetchone()
    assert host is not None


def test_handle_evidence_without_a_known_flow_id_leaves_flow_id_null():
    conn = connect(":memory:")
    store = EventStore(conn, _bus())
    ev = Evidence(
        source=Layer.L2_ANOMALY, flow_id=None, host_ip="10.0.0.9",
        kind=EvidenceType.ANOMALY, strength=0.8, weight=2.0,
    )
    raw = encode_envelope(MessageType.EVIDENCE, ev)

    store.handle_evidence(raw)

    row = conn.execute("SELECT flow_id FROM evidence").fetchone()
    assert row == (None,)


def test_handle_host_score_updates_host_risk_score():
    conn = connect(":memory:")
    store = EventStore(conn, _bus())
    conn.execute("INSERT INTO host (ip_address, is_internal, risk_score) VALUES ('10.0.0.5', 1, 0)")
    conn.commit()
    raw = encode_envelope(MessageType.HOST_SCORE_UPDATED, HostScore(host_ip="10.0.0.5", score=6.4))

    store.handle_host_score(raw)

    score = conn.execute("SELECT risk_score FROM host WHERE ip_address = '10.0.0.5'").fetchone()[0]
    assert score == 6.4


def test_handle_host_score_upserts_unknown_host():
    conn = connect(":memory:")
    store = EventStore(conn, _bus())
    raw = encode_envelope(MessageType.HOST_SCORE_UPDATED, HostScore(host_ip="10.0.0.77", score=2.0))

    store.handle_host_score(raw)

    row = conn.execute("SELECT risk_score FROM host WHERE ip_address = '10.0.0.77'").fetchone()
    assert row == (2.0,)


def test_consume_once_drains_both_streams():
    conn = connect(":memory:")
    bus = _bus()
    store = EventStore(conn, bus)
    ev = Evidence(
        source=Layer.L2_ANOMALY, flow_id="1", host_ip="10.0.0.1",
        kind=EvidenceType.ANOMALY, strength=0.8, weight=2.0,
    )
    bus.publish(STREAM_EVIDENCE, encode_envelope(MessageType.EVIDENCE, ev))
    bus.publish(
        STREAM_HOST_SCORES,
        encode_envelope(MessageType.HOST_SCORE_UPDATED, HostScore(host_ip="10.0.0.1", score=1.5)),
    )

    store.consume_once(block_ms=100)

    assert conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1
    assert conn.execute("SELECT risk_score FROM host WHERE ip_address='10.0.0.1'").fetchone()[0] == 1.5


def test_event_store_never_writes_to_the_verdict_table():
    """Guards the scope note in event_store.py: verdict stays single-writer
    (services.decision.verdict_store.VerdictStore). If a future edit adds STREAM_VERDICTS handling
    here, this is the test that should catch the resulting double-count."""
    conn = connect(":memory:")
    store = EventStore(conn, _bus())

    assert not hasattr(store, "handle_verdict")
