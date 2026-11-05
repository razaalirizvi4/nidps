"""Entry point for Layer-2 host-behaviour anomaly scoring. process_flow_ready() is the
dependency-injected core every test calls; main() wraps it in a real bus-consume loop with
periodic model bootstrap retry, recalibration, and heartbeat ticks."""
from __future__ import annotations

import json
import os
import socket
import time
from datetime import datetime, timezone
from typing import Optional

from common.bus import STREAM_EVIDENCE, STREAM_FLOWS, STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, decode_envelope, encode_envelope
from common.config_loader import get as config_get
from common.db.migrate import connect
from common.logging_setup import configure_logging
from common.schemas import (
    ComponentHealth,
    EvidenceType,
    FlowFeatures,
    HealthState,
    SCHEMA_VERSION,
    utc_now_iso,
)
from services.flowextract.config_cache import CachedConfig
from services.flowextract.features import FEATURE_NAMES
from services.mlscorer.anomaly import AnomalyDetector, load_active_model
from services.mlscorer.calibration import load_calibration_state, recalibrate_if_due
from services.mlscorer.host_behaviour import BeaconTracker, ExfiltrationTracker, FlowObservation, HostBehaviourTracker

_FWD_IDX = FEATURE_NAMES.index("total_fwd_bytes")
_BWD_IDX = FEATURE_NAMES.index("total_bwd_bytes")

_WEIGHT_CONFIG_KEY = {
    EvidenceType.ANOMALY: "risk.weight_anomaly",
    EvidenceType.EXFIL: "risk.weight_exfil",
    EvidenceType.BEACON: "risk.weight_beacon",
}


def _iso_to_epoch(iso_str: str) -> float:
    """Inverse of services/flowextract/persistence._epoch_to_iso()."""
    return datetime.strptime(iso_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc).timestamp()


def is_new_destination(conn, host_id: int, dst_ip: str, flow_id: int) -> bool:
    row = conn.execute(
        "SELECT 1 FROM flow_record WHERE host_id = ? AND dst_ip = ? AND flow_id != ? LIMIT 1",
        (host_id, dst_ip, flow_id),
    ).fetchone()
    return row is None


def load_flow_observation(conn, flow_id: int, host_ip: str) -> Optional[tuple]:
    row = conn.execute(
        """SELECT host_id, dst_ip, sni, ja3, segment_no, features, end_time
           FROM flow_record WHERE flow_id = ?""",
        (flow_id,),
    ).fetchone()
    if row is None:
        return None
    host_id, dst_ip, sni, ja3, segment_no, features_json, end_time = row
    values = json.loads(features_json)
    features = FlowFeatures(schema_version=SCHEMA_VERSION, values=values)
    obs = FlowObservation(
        host_ip=host_ip,
        dst_ip=dst_ip,
        sni=sni,
        ja3=ja3,
        fwd_bytes=values[_FWD_IDX],
        bwd_bytes=values[_BWD_IDX],
        end_time_epoch=_iso_to_epoch(end_time),
        # segment_no is not itself an is-open flag -- flow_record never persisted one (a
        # known, documented gap). segment_no > 0 means this is a later segment of an
        # ongoing flow, so it is the best available proxy for "plausibly still open".
        is_partial=segment_no > 0,
        is_new_destination=is_new_destination(conn, host_id, dst_ip, flow_id),
    )
    return features, obs


def process_flow_ready(
    conn, bus: EventBus, detector: Optional[AnomalyDetector], tracker: HostBehaviourTracker, body: str
) -> int:
    envelope = decode_envelope(body)
    payload = envelope["payload"]
    flow_id = payload["flow_id"]
    host_ip = payload["host_ip"]

    loaded = load_flow_observation(conn, flow_id, host_ip)
    if loaded is None:
        return 0
    features, obs = loaded

    evidence_list = tracker.observe(obs)
    if detector is not None:
        evidence_list = evidence_list + (detector.analyse((host_ip, flow_id, features)) or [])

    published = 0
    for ev in evidence_list:
        ev.weight = config_get(conn, _WEIGHT_CONFIG_KEY[ev.kind])
        bus.publish(STREAM_EVIDENCE, encode_envelope(MessageType.EVIDENCE, ev))
        published += 1
    return published


def publish_heartbeat(bus: EventBus, component_name: str) -> None:
    health = ComponentHealth(name=component_name, state=HealthState.NORMAL, last_heartbeat=utc_now_iso())
    bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, health))


def main() -> None:
    db_path = os.environ.get("NIDPS_DB_PATH", "/var/lib/nidps/nidps.sqlite3")
    redis_url = os.environ.get("NIDPS_REDIS_URL", "redis://localhost:6379/0")

    logger = configure_logging("mlscorer-anomaly")

    conn = connect(db_path)
    bus = EventBus.from_url(redis_url)
    cached_config = CachedConfig(conn)
    consumer_name = socket.gethostname()

    detector: Optional[AnomalyDetector] = None
    model_id: Optional[int] = None
    last_model_attempt = 0.0

    def _try_bootstrap_detector() -> None:
        nonlocal detector, model_id, last_model_attempt
        try:
            loaded_model_id, model = load_active_model(conn)
            calibration = load_calibration_state(conn, loaded_model_id)
            detector = AnomalyDetector(model=model, calibration=calibration, model_id=loaded_model_id)
            model_id = loaded_model_id
        except LookupError:
            detector = None
        last_model_attempt = time.time()

    _try_bootstrap_detector()

    tracker = HostBehaviourTracker(
        exfil=ExfiltrationTracker(
            ewma_alpha=cached_config.get("exfil.ewma_alpha"),
            bucket_seconds=cached_config.get("exfil.bucket_seconds"),
            k_std=cached_config.get("exfil.k_std"),
            u_max=detector.calibration.u_max if detector is not None else None,
        ),
        beacon=BeaconTracker(
            min_connections=cached_config.get("beacon.min_connections"),
            cv_threshold=cached_config.get("beacon.cv_threshold"),
        ),
    )

    logger.info("mlscorer-anomaly starting, consumer=%s", consumer_name)
    last_heartbeat = 0.0
    last_recalibration_check = 0.0

    def _handle(body: str) -> None:
        try:
            process_flow_ready(conn, bus, detector, tracker, body)
        except Exception:
            logger.exception("error processing FLOW_READY message")

    while True:
        try:
            bus.consume(STREAM_FLOWS, group="layer2-anomaly", consumer=consumer_name, handler=_handle, block_ms=1000)

            now = time.time()

            if detector is None and now - last_model_attempt >= 60.0:
                _try_bootstrap_detector()
                if detector is not None:
                    tracker._exfil.set_u_max(detector.calibration.u_max)

            if detector is not None:
                window_hours = cached_config.get("anomaly.calibration_window_hours")
                window_seconds = window_hours * 3600
                if now - last_recalibration_check >= window_seconds:
                    now_iso = utc_now_iso()
                    window_start_iso = datetime.fromtimestamp(
                        now - window_seconds, tz=timezone.utc
                    ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    new_state = recalibrate_if_due(
                        conn,
                        detector.score,
                        model_id,
                        detector.calibration,
                        window_start_iso,
                        now_iso,
                        now_iso,
                    )
                    if new_state is not detector.calibration:
                        detector.calibration = new_state
                        tracker._exfil.set_u_max(new_state.u_max)
                    last_recalibration_check = now

            heartbeat_interval = config_get(conn, "watchdog.heartbeat_interval_s")
            if now - last_heartbeat >= heartbeat_interval:
                publish_heartbeat(bus, "mlscorer-anomaly")
                last_heartbeat = now
        except Exception:
            logger.exception("error in mlscorer-anomaly poll loop")


if __name__ == "__main__":
    main()
