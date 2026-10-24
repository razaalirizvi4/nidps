import pytest

from common.bus_messages import MessageType, decode_envelope, encode_envelope
from common.schemas import ComponentHealth, Evidence, EvidenceType, HealthState, Layer


def test_evidence_round_trip():
    ev = Evidence(
        source=Layer.L2_ANOMALY,
        flow_id="f1",
        host_ip="10.10.0.57",
        kind=EvidenceType.ANOMALY,
        strength=0.71,
        weight=2.0,
    )
    raw = encode_envelope(MessageType.EVIDENCE, ev)
    envelope = decode_envelope(raw)

    assert envelope["type"] == "evidence"
    assert envelope["payload"]["source"] == "L2"
    assert envelope["payload"]["strength"] == 0.71


def test_heartbeat_round_trip():
    health = ComponentHealth(
        name="flowextract", state=HealthState.NORMAL, last_heartbeat="2026-10-10T00:00:00Z"
    )
    raw = encode_envelope(MessageType.HEARTBEAT, health)
    envelope = decode_envelope(raw)

    assert envelope["payload"]["state"] == "NORMAL"


def test_decode_rejects_unknown_schema_version():
    raw = '{"schema_version": "9.9", "payload": {}}'
    with pytest.raises(ValueError):
        decode_envelope(raw)


def test_flow_ready_round_trip():
    raw = encode_envelope(MessageType.FLOW_READY, {"flow_id": 42, "host_ip": "10.10.0.5"})
    envelope = decode_envelope(raw)

    assert envelope["type"] == "flow_ready"
    assert envelope["payload"] == {"flow_id": 42, "host_ip": "10.10.0.5"}
