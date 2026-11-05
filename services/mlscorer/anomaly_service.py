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


def is_new_destination(
    conn, host_id: int, dst_ip: str, flow_id: int, src_port: int, dst_port: int, protocol: str
) -> bool:
    """True when this host has no *other* conversation on record with dst_ip.

    Rows belonging to the same logical five-tuple conversation (earlier active-timeout
    segments of this very flow) are excluded along with the flow's own row: a later
    segment of an in-progress upload must still count as "a destination never contacted
    before", otherwise FR-4.5's fast path (which requires is_partial, i.e. a non-first
    segment) could never fire. A genuinely separate earlier flow to the same destination
    still correctly makes this NOT a new destination.
    """
    row = conn.execute(
        """SELECT 1 FROM flow_record
           WHERE host_id = ? AND dst_ip = ? AND flow_id != ?
             AND NOT (src_port = ? AND dst_port = ? AND protocol = ?)
           LIMIT 1""",
        (host_id, dst_ip, flow_id, src_port, dst_port, protocol),
    ).fetchone()
    return row is None


def load_flow_observation(conn, flow_id: int, host_ip: str, is_partial: bool) -> Optional[tuple]:
    row = conn.execute(
        """SELECT host_id, dst_ip, sni, ja3, src_port, dst_port, protocol, features, end_time
           FROM flow_record WHERE flow_id = ?""",
        (flow_id,),
    ).fetchone()
    if row is None:
        return None
    host_id, dst_ip, sni, ja3, src_port, dst_port, protocol, features_json, end_time = row
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
        # The real FlowAssembler flag, carried on the FLOW_READY message by flowextract.
        is_partial=is_partial,
        is_new_destination=is_new_destination(
            conn, host_id, dst_ip, flow_id, src_port, dst_port, protocol
        ),
    )
    return features, obs


def process_flow_ready(
    conn, bus: EventBus, detector: Optional[AnomalyDetector], tracker: HostBehaviourTracker, body: str
) -> int:
    envelope = decode_envelope(body)
    payload = envelope["payload"]
    flow_id = payload["flow_id"]
    host_ip = payload["host_ip"]
    # Default False for backward compatibility with messages queued before flowextract
    # started publishing the real FlowAssembler is_partial flag.
    is_partial = payload.get("is_partial", False)

    loaded = load_flow_observation(conn, flow_id, host_ip, is_partial)
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
            try:
                loaded_model_id, model = load_active_model(conn)
                calibration = load_calibration_state(conn, loaded_model_id)
                detector = AnomalyDetector(
                    model=model, calibration=calibration, model_id=loaded_model_id
                )
                model_id = loaded_model_id
                logger.info("anomaly model %d loaded", loaded_model_id)
            except LookupError:
                detector = None
                logger.warning("no active IFOREST model; anomaly scoring disabled, will retry in 60s")
            except Exception:
                # A present-but-unloadable artifact (missing file, corrupt pickle, missing
                # module) must not crash the service: exfiltration/beaconing detection and
                # heartbeats need no model at all.
                detector = None
                logger.exception(
                    "failed to load active IFOREST model; anomaly scoring disabled, will retry in 60s"
                )
        finally:
            # Unconditional, so a failure of any kind still honours the 60s retry backoff.
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

            # Each periodic block is guarded locally so a failure in one cannot skip the
            # ones that follow it -- above all the heartbeat, which the watchdog relies on
            # and which needs neither a model nor a calibration state.
            try:
                if detector is None and now - last_model_attempt >= 60.0:
                    _try_bootstrap_detector()
                    if detector is not None:
                        tracker._exfil.set_u_max(detector.calibration.u_max)
            except Exception:
                logger.exception("error during anomaly model bootstrap retry")

            try:
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
            except Exception:
                logger.exception("error during anomaly recalibration check")

            heartbeat_interval = config_get(conn, "watchdog.heartbeat_interval_s")
            if now - last_heartbeat >= heartbeat_interval:
                publish_heartbeat(bus, "mlscorer-anomaly")
                last_heartbeat = now
        except Exception:
            logger.exception("error in mlscorer-anomaly poll loop")


if __name__ == "__main__":
    main()
