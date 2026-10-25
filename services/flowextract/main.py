"""Entry point for the flow-extraction service. run_once() is the dependency-injected core every
test calls; main() wraps it in a real scapy.sniff() loop with wall-clock-timed idle-expiry,
retention purge, and heartbeat ticks."""
from __future__ import annotations

import os
import time

from common.bus import STREAM_FLOWS, STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, encode_envelope
from common.db.migrate import connect
from common.logging_setup import configure_logging
from common.schemas import ComponentHealth, HealthState, utc_now_iso
from services.flowextract.capture import parse_packet
from services.flowextract.config_cache import CachedConfig
from services.flowextract.flow_assembler import FlowAssembler
from services.flowextract.persistence import upsert_host, write_flow_record
from services.flowextract.retention import purge_old_flows

EXTRACTOR_VERSION = "1.0"


def _persist_and_publish(conn, bus: EventBus, emitted, extractor_version: str = EXTRACTOR_VERSION) -> int:
    host_id = upsert_host(conn, emitted.src_ip)
    flow_id = write_flow_record(conn, emitted, host_id, extractor_version)
    body = encode_envelope(
        MessageType.FLOW_READY, {"flow_id": flow_id, "host_ip": emitted.src_ip}
    )
    # A bus.publish failure here is NOT caught locally -- it propagates up through run_once()
    # into _on_packet()'s try/except in main(), which logs it instead of crashing the service.
    bus.publish(STREAM_FLOWS, body)
    return 1


def run_once(
    conn, bus: EventBus, assembler: FlowAssembler, cached_config: CachedConfig, packets, now: float
) -> int:
    assembler.active_timeout = cached_config.get("network.active_timeout_s")
    assembler.idle_timeout = cached_config.get("network.idle_timeout_s")
    published = 0
    for meta in packets:
        for emitted in assembler.onPacket(meta):
            published += _persist_and_publish(conn, bus, emitted)
    for emitted in assembler.expireIdle(now):
        published += _persist_and_publish(conn, bus, emitted)
    return published


def publish_heartbeat(bus: EventBus, component_name: str) -> None:
    health = ComponentHealth(
        name=component_name, state=HealthState.NORMAL, last_heartbeat=utc_now_iso()
    )
    bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, health))


def main() -> None:
    db_path = os.environ.get("NIDPS_DB_PATH", "/var/lib/nidps/nidps.sqlite3")
    redis_url = os.environ.get("NIDPS_REDIS_URL", "redis://localhost:6379/0")
    interface = os.environ.get("NIDPS_CAPTURE_INTERFACE", "wlan0")

    logger = configure_logging("flowextract")

    conn = connect(db_path)
    bus = EventBus.from_url(redis_url)
    assembler = FlowAssembler()
    cached_config = CachedConfig(conn)

    state = {"last_expire": time.time(), "last_purge": time.time(), "last_heartbeat": 0.0}

    from scapy.all import sniff  # imported here so no test needs a live capture backend

    def _on_packet(scapy_pkt) -> None:
        try:
            meta = parse_packet(scapy_pkt)
            if meta is not None:
                run_once(conn, bus, assembler, cached_config, [meta], now=meta.timestamp)

            now = time.time()
            heartbeat_interval = cached_config.get("watchdog.heartbeat_interval_s")
            if now - state["last_heartbeat"] >= heartbeat_interval:
                publish_heartbeat(bus, "flowextract")
                state["last_heartbeat"] = now
            if now - state["last_expire"] >= 1.0:
                run_once(conn, bus, assembler, cached_config, [], now=now)
                state["last_expire"] = now
            if now - state["last_purge"] >= 60.0:
                purge_old_flows(conn, cached_config.get("retention.flow_days"))
                state["last_purge"] = now
        except Exception:
            logger.exception("error processing packet")

    logger.info("flowextract starting on interface %s", interface)
    sniff(iface=interface, prn=_on_packet, store=False)


if __name__ == "__main__":
    main()
