# tests/unit/test_anomaly_service.py
import json

import fakeredis
import numpy as np

from common.bus import STREAM_EVIDENCE, STREAM_FLOWS, STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, decode_envelope, encode_envelope
from common.config_loader import seed_defaults
from common.db.migrate import connect
from services.flowextract.features import FEATURE_NAMES
from services.flowextract.persistence import upsert_host, write_flow_record
from services.flowextract.flow_assembler import EmittedFlow
from services.mlscorer.anomaly import AnomalyDetector, fit_bootstrap_model
from services.mlscorer.calibration import CalibrationState
from services.mlscorer.host_behaviour import BeaconTracker, ExfiltrationTracker, HostBehaviourTracker
from services.mlscorer.anomaly_service import is_new_destination, process_flow_ready, publish_heartbeat
from common.schemas import FEATURE_COUNT, TLSFingerprint

_FWD_IDX = FEATURE_NAMES.index("total_fwd_bytes")
_BWD_IDX = FEATURE_NAMES.index("total_bwd_bytes")


def _write_flow(
    conn, host_id, dst_ip="1.2.3.4", fwd=10.0, bwd=10.0, ja3=None, sni=None,
    src_port=1, dst_port=2, segment_no=0,
):
    values = [0.0] * FEATURE_COUNT
    values[_FWD_IDX] = fwd
    values[_BWD_IDX] = bwd
    emitted = EmittedFlow(
        src_ip="10.0.0.5", dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, protocol="TCP",
        start_time=1_700_000_000.0, end_time=1_700_000_000.5, segment_no=segment_no,
        is_partial=False, feature_values=values, tls=TLSFingerprint(ja3=ja3, server_name=sni),
    )
    return write_flow_record(conn, emitted, host_id)


def test_is_new_destination_excludes_the_flows_own_row():
    conn = connect(":memory:")
    host_id = upsert_host(conn, "10.0.0.5")
    flow_id = _write_flow(conn, host_id, dst_ip="9.9.9.9")
    # The only flow_record row for this (host_id, dst_ip) pair IS this flow itself.
    assert is_new_destination(conn, host_id, "9.9.9.9", flow_id, 1, 2, "TCP") is True


def test_is_new_destination_false_when_a_different_flow_already_visited():
    conn = connect(":memory:")
    host_id = upsert_host(conn, "10.0.0.5")
    # A genuinely separate earlier conversation (different source port) to the same destination.
    _write_flow(conn, host_id, dst_ip="9.9.9.9", src_port=40000)
    newer_flow_id = _write_flow(conn, host_id, dst_ip="9.9.9.9")
    assert is_new_destination(conn, host_id, "9.9.9.9", newer_flow_id, 1, 2, "TCP") is False


def test_is_new_destination_ignores_earlier_segments_of_the_same_five_tuple():
    conn = connect(":memory:")
    host_id = upsert_host(conn, "10.0.0.5")
    # A brand new destination with no prior rows at all is new.
    first_segment = _write_flow(conn, host_id, dst_ip="9.9.9.9", segment_no=0)
    assert is_new_destination(conn, host_id, "9.9.9.9", first_segment, 1, 2, "TCP") is True

    # Segment 1 of the SAME logical conversation (same five-tuple) must not make the
    # destination look already-visited -- otherwise FR-4.5's fast path, which requires
    # is_partial (i.e. a non-first segment), could never fire.
    second_segment = _write_flow(conn, host_id, dst_ip="9.9.9.9", segment_no=1)
    assert is_new_destination(conn, host_id, "9.9.9.9", second_segment, 1, 2, "TCP") is True

    # But a genuinely different earlier flow to the same destination still counts as a visit.
    _write_flow(conn, host_id, dst_ip="9.9.9.9", src_port=40000)
    third_segment = _write_flow(conn, host_id, dst_ip="9.9.9.9", segment_no=2)
    assert is_new_destination(conn, host_id, "9.9.9.9", third_segment, 1, 2, "TCP") is False


def test_process_flow_ready_runs_host_behaviour_tracker_without_a_detector():
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    host_id = upsert_host(conn, "10.0.0.5")
    flow_id = _write_flow(conn, host_id, dst_ip="9.9.9.9", fwd=10.0, bwd=10.0)
    body = encode_envelope(MessageType.FLOW_READY, {"flow_id": flow_id, "host_ip": "10.0.0.5"})

    tracker = HostBehaviourTracker(
        exfil=ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None),
        beacon=BeaconTracker(min_connections=5, cv_threshold=0.15),
    )
    published = process_flow_ready(conn, bus, detector=None, tracker=tracker, body=body)
    assert published == 0  # nothing anomalous about one small flow to a fresh destination


def test_process_flow_ready_scores_with_detector_and_publishes_weighted_evidence():
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    host_id = upsert_host(conn, "10.0.0.5")
    flow_id = _write_flow(conn, host_id)

    rng = np.random.RandomState(42)
    model = fit_bootstrap_model(rng.normal(0, 1, (100, FEATURE_COUNT)), n_estimators=50, max_samples=64)
    # threshold=0.0 guarantees this flow's score exceeds it, so analyse() returns Evidence.
    calibration = CalibrationState(threshold=0.0, global_threshold=0.0, computed_at="x", sample_count=0)
    detector = AnomalyDetector(model=model, calibration=calibration, model_id=7)
    tracker = HostBehaviourTracker(
        exfil=ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None),
        beacon=BeaconTracker(min_connections=5, cv_threshold=0.15),
    )
    body = encode_envelope(MessageType.FLOW_READY, {"flow_id": flow_id, "host_ip": "10.0.0.5"})

    published = process_flow_ready(conn, bus, detector, tracker, body)
    assert published == 1

    received = []
    bus.consume(STREAM_EVIDENCE, group="decision", consumer="c1", handler=received.append, block_ms=100)
    assert len(received) == 1
    payload = decode_envelope(received[0])["payload"]
    assert payload["kind"] == "ANOMALY"
    assert payload["weight"] == 2.0  # risk.weight_anomaly default
    assert payload["model_id"] == 7


def test_process_flow_ready_fires_exfil_fast_path_for_a_partial_flow_to_a_new_destination():
    # Regression guard for FR-4.5: the fast path requires is_partial AND is_new_destination
    # at the same time. is_partial now arrives on the FLOW_READY message (the real
    # FlowAssembler flag) rather than being inferred from segment_no, and
    # is_new_destination no longer counts earlier segments of this same conversation --
    # so the combination is reachable from the real DB-backed loader.
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    host_id = upsert_host(conn, "10.0.0.5")
    # A huge one-sided upload, still in progress (segment 1 of an active-timeout split).
    _write_flow(conn, host_id, dst_ip="9.9.9.9", fwd=5_000_000.0, bwd=100.0, segment_no=0)
    flow_id = _write_flow(conn, host_id, dst_ip="9.9.9.9", fwd=5_000_000.0, bwd=100.0, segment_no=1)
    body = encode_envelope(
        MessageType.FLOW_READY,
        {"flow_id": flow_id, "host_ip": "10.0.0.5", "is_partial": True},
    )

    tracker = HostBehaviourTracker(
        exfil=ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=1_000_000),
        beacon=BeaconTracker(min_connections=5, cv_threshold=0.15),
    )
    published = process_flow_ready(conn, bus, detector=None, tracker=tracker, body=body)
    assert published == 1

    received = []
    bus.consume(STREAM_EVIDENCE, group="decision", consumer="c1", handler=received.append, block_ms=100)
    assert len(received) == 1
    payload = decode_envelope(received[0])["payload"]
    assert payload["kind"] == "EXFIL"
    assert payload["weight"] == 2.0  # risk.weight_exfil default


def test_process_flow_ready_returns_zero_for_missing_flow_record():
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    tracker = HostBehaviourTracker(
        exfil=ExfiltrationTracker(ewma_alpha=0.5, bucket_seconds=60, k_std=2.0, u_max=None),
        beacon=BeaconTracker(min_connections=5, cv_threshold=0.15),
    )
    body = encode_envelope(MessageType.FLOW_READY, {"flow_id": 9999, "host_ip": "10.0.0.5"})
    assert process_flow_ready(conn, bus, detector=None, tracker=tracker, body=body) == 0


def test_publish_heartbeat_sends_component_health():
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    publish_heartbeat(bus, "mlscorer-anomaly")
    received = []
    bus.consume(STREAM_HEARTBEATS, group="watchdog", consumer="c1", handler=received.append, block_ms=100)
    assert len(received) == 1
    envelope = decode_envelope(received[0])
    assert envelope["payload"]["name"] == "mlscorer-anomaly"
    assert envelope["payload"]["state"] == "NORMAL"
