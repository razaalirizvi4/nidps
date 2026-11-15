import fakeredis

from common.bus import (
    STREAM_HEARTBEATS,
    STREAM_HOST_SCORES,
    STREAM_VERDICTS,
    EventBus,
)
from common.bus_messages import MessageType, decode_envelope, encode_envelope
from common.config_loader import seed_defaults
from common.db.migrate import connect
from common.schemas import Evidence, EvidenceType, Layer
from services.decision.allowlist import Allowlist
from services.decision.correlator import EvidenceCorrelator
from services.decision.engine import DecisionEngine
from services.decision.main import (
    decide_groups,
    evidence_from_payload,
    process_evidence_message,
    publish_heartbeat,
    publish_score_refresh,
)
from services.decision.risk_tracker import RiskScoreTracker
from services.flowextract.config_cache import CachedConfig


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


def _setup():
    conn = connect(":memory:")
    seed_defaults(conn)
    config = CachedConfig(conn)
    risk = RiskScoreTracker(half_life_s=lambda: config.get("risk.half_life_s"))
    engine = DecisionEngine(risk, Allowlist(conn), config)
    clock = Clock()
    correlator = EvidenceCorrelator(window_s=3.0, clock=clock)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    return engine, correlator, bus, risk, clock


def _read(bus, stream, group="test"):
    out = []
    bus.consume(stream, group=group, consumer="t", handler=out.append, count=100, block_ms=50)
    return [decode_envelope(b) for b in out]


def _send(bus, engine, correlator, **kw):
    fields = dict(source=Layer.L2_ANOMALY, flow_id=None, host_ip="10.0.0.57",
                  kind=EvidenceType.EXFIL, strength=1.0, weight=2.0,
                  timestamp="2026-11-01T10:00:00.000000Z")
    fields.update(kw)
    body = encode_envelope(MessageType.EVIDENCE, Evidence(**fields))
    return process_evidence_message(engine, correlator, bus, body)


def test_evidence_survives_the_bus_round_trip():
    ev = Evidence(source=Layer.L1_SIGNATURE, flow_id=None, host_ip="10.0.0.9",
                  kind=EvidenceType.SIGNATURE, strength=1.0, weight=3.0, signature_id=42)
    payload = decode_envelope(encode_envelope(MessageType.EVIDENCE, ev))["payload"]
    assert evidence_from_payload(payload) == ev


def test_three_alerts_through_the_bus_end_in_a_block_and_scores_rise_then_reset():
    engine, correlator, bus, _, _ = _setup()
    for _ in range(3):
        assert _send(bus, engine, correlator) == 1

    verdicts = _read(bus, STREAM_VERDICTS)
    assert [v["payload"]["action"] for v in verdicts] == ["ALERT", "ALERT", "BLOCK"]
    assert verdicts[0]["type"] == "verdict"
    assert verdicts[2]["payload"]["layers"][0] == "HOST"

    scores = [s["payload"]["score"] for s in _read(bus, STREAM_HOST_SCORES)]
    assert scores[0] == 2.0
    assert scores[1] > scores[0]
    assert scores[-1] == 0.0


def test_flow_evidence_is_held_until_the_window_closes():
    engine, correlator, bus, _, clock = _setup()
    assert _send(bus, engine, correlator, flow_id="9", kind=EvidenceType.ANOMALY) == 0
    assert _read(bus, STREAM_VERDICTS) == []
    clock.t = 3.0
    assert decide_groups(engine, bus, correlator.flush_due()) == 1
    assert len(_read(bus, STREAM_VERDICTS)) == 1


def test_hard_signature_is_published_without_waiting():
    engine, correlator, bus, _, _ = _setup()
    _send(bus, engine, correlator, flow_id="9", kind=EvidenceType.SIGNATURE,
          source=Layer.L1_SIGNATURE, weight=3.0)
    (verdict,) = _read(bus, STREAM_VERDICTS)
    assert verdict["payload"]["action"] == "BLOCK"


def test_score_refresh_publishes_current_scores():
    engine, correlator, bus, risk, _ = _setup()
    _send(bus, engine, correlator)
    _read(bus, STREAM_HOST_SCORES)
    assert publish_score_refresh(bus, risk) == 1


def test_heartbeat_names_the_service():
    _, _, bus, _, _ = _setup()
    publish_heartbeat(bus)
    (hb,) = _read(bus, STREAM_HEARTBEATS)
    assert hb["payload"]["name"] == "decision"
