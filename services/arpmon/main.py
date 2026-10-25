"""Entry point for the ARP-spoofing monitor. process_frames() is the dependency-injected core
every test calls; main() wraps it in a real scapy.sniff() loop with periodic lease-file refresh
and heartbeat ticks."""
from __future__ import annotations

import os
import time
from typing import Optional

from common.bus import STREAM_EVIDENCE, STREAM_HEARTBEATS, EventBus
from common.bus_messages import MessageType, encode_envelope
from common.config_loader import get as config_get
from common.db.migrate import connect
from common.logging_setup import configure_logging
from services.arpmon.arp_monitor import ArpFrame, ArpMonitor
from services.arpmon.leases import parse_dnsmasq_leases


def parse_arp_packet(pkt, timestamp: float) -> Optional[ArpFrame]:
    from scapy.layers.l2 import ARP

    if ARP not in pkt:
        return None
    arp = pkt[ARP]
    is_reply = arp.op == 2
    is_gratuitous = arp.op == 1 and arp.psrc == arp.pdst
    return ArpFrame(
        sender_ip=arp.psrc, sender_mac=arp.hwsrc, is_reply=is_reply,
        is_gratuitous=is_gratuitous, timestamp=timestamp,
    )


def process_frames(conn, bus: EventBus, monitor: ArpMonitor, frames) -> int:
    weight = config_get(conn, "risk.weight_signature")
    published = 0
    for frame in frames:
        for ev in monitor.onArp(frame):
            ev.weight = weight
            bus.publish(STREAM_EVIDENCE, encode_envelope(MessageType.EVIDENCE, ev))
            published += 1
    return published


def publish_heartbeat(bus: EventBus, monitor: ArpMonitor) -> None:
    bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, monitor.heartbeat()))


def _refresh_bindings_safely(monitor: ArpMonitor, lease_path: str, logger) -> None:
    """Refreshes monitor.bindings from the dnsmasq lease file, but never lets a transient
    read glitch (missing file, permission error) silently wipe out trust bindings that were
    already successfully loaded -- that would disable ARP-spoof detection with no signal
    (I9). Only an empty-to-empty transition (the very first refresh, before the lease file
    is available) is allowed through."""
    new_bindings = parse_dnsmasq_leases(lease_path)
    if not new_bindings and monitor.bindings:
        logger.warning(
            "lease file %s read as empty; keeping existing %d binding(s)",
            lease_path, len(monitor.bindings),
        )
        return
    monitor.refreshBindings(new_bindings)


def main() -> None:
    db_path = os.environ.get("NIDPS_DB_PATH", "/var/lib/nidps/nidps.sqlite3")
    redis_url = os.environ.get("NIDPS_REDIS_URL", "redis://localhost:6379/0")
    interface = os.environ.get("NIDPS_CAPTURE_INTERFACE", "wlan0")
    gateway_ip = os.environ["NIDPS_GATEWAY_IP"]
    ap_mac = os.environ["NIDPS_AP_MAC"]
    lease_path = os.environ.get("NIDPS_DHCP_LEASE_PATH", "/var/lib/misc/dnsmasq.leases")

    logger = configure_logging("arpmon")

    conn = connect(db_path)
    bus = EventBus.from_url(redis_url)
    monitor = ArpMonitor(gateway_ip=gateway_ip, ap_mac=ap_mac)
    _refresh_bindings_safely(monitor, lease_path, logger)

    state = {"last_lease_refresh": time.time(), "last_heartbeat": 0.0}

    from scapy.all import sniff

    def _on_packet(scapy_pkt) -> None:
        try:
            frame = parse_arp_packet(scapy_pkt, timestamp=time.time())
            if frame is not None:
                process_frames(conn, bus, monitor, [frame])

            now = time.time()
            heartbeat_interval = config_get(conn, "watchdog.heartbeat_interval_s")
            if now - state["last_heartbeat"] >= heartbeat_interval:
                publish_heartbeat(bus, monitor)
                state["last_heartbeat"] = now
            if now - state["last_lease_refresh"] >= 5.0:
                _refresh_bindings_safely(monitor, lease_path, logger)
                state["last_lease_refresh"] = now
        except Exception:
            logger.exception("error processing packet")

    logger.info("arpmon starting on interface %s", interface)
    sniff(iface=interface, filter="arp", prn=_on_packet, store=False)


if __name__ == "__main__":
    main()
