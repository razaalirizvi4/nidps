"""Enforcer service entry point: consumes BLOCK verdicts from STREAM_VERDICTS with consumer
group 'enforcer', runs Enforcer.enforce(), periodically reconciles expired block_entry rows,
and publishes a heartbeat at watchdog.heartbeat_interval_s. Seeds the three permanent allowlist
entries (FR-7.3) from NIDPS_HOST_IP / NIDPS_GATEWAY_IP / NIDPS_DNS_IP at startup."""
from __future__ import annotations

import os
import time
from typing import Optional

from common.bus import STREAM_HEARTBEATS, STREAM_VERDICTS, EventBus
from common.bus_messages import MessageType, decode_envelope, encode_envelope
from common.config_loader import seed_defaults
from common.db.migrate import connect
from common.env import load_env
from common.logging_setup import configure_logging
from common.schemas import Action, ComponentHealth, HealthState, Layer, Verdict, utc_now_iso

from services.enforcer.allowlist import AllowlistStore
from services.enforcer.config_cache import CachedConfig
from services.enforcer.enforcer import Enforcer
from services.enforcer.ipset_client import IpsetClient

COMPONENT_NAME = "enforcer"
CONSUMER_GROUP = "enforcer"


def _verdict_from_payload(payload: dict) -> Verdict:
    return Verdict(
        action=Action(payload["action"]),
        layers=[Layer(layer) for layer in payload["layers"]],
        explanation=payload["explanation"],
        flow_id=payload.get("flow_id"),
        host_ip=payload.get("host_ip"),
        attack_class=payload.get("attack_class"),
        timestamp=payload.get("timestamp", utc_now_iso()),
    )


def run(
    conn=None,
    bus: Optional[EventBus] = None,
    db_path: str = "nidps.db",
    redis_url: str = "redis://localhost:6379/0",
    nidps_ip: Optional[str] = None,
    gateway_ip: Optional[str] = None,
    dns_ip: Optional[str] = None,
    ipset_runner=None,
    poll_interval_s: float = 0.5,
    stop_after_iterations: Optional[int] = None,
) -> None:
    logger = configure_logging(COMPONENT_NAME)
    conn = conn or connect(db_path)
    seed_defaults(conn)
    bus = bus or EventBus.from_url(redis_url)

    config_cache = CachedConfig(conn)
    allowlist = AllowlistStore(conn)

    nidps_ip = nidps_ip or os.environ.get("NIDPS_HOST_IP")
    gateway_ip = gateway_ip or os.environ.get("NIDPS_GATEWAY_IP")
    dns_ip = dns_ip or os.environ.get("NIDPS_DNS_IP")
    if not all([nidps_ip, gateway_ip, dns_ip]):
        logger.warning(
            "one or more of NIDPS_HOST_IP/NIDPS_GATEWAY_IP/NIDPS_DNS_IP is unset; "
            "the corresponding system allowlist entry will not be seeded"
        )
    allowlist.seed_system_entries(nidps_ip=nidps_ip, gateway_ip=gateway_ip, dns_ip=dns_ip)

    ipset_client = IpsetClient(runner=ipset_runner) if ipset_runner else IpsetClient()
    ipset_client.ensure_set_exists()
    ipset_client.ensure_firewall_rules()

    enforcer = Enforcer(conn, ipset_client, allowlist, config_cache.get, bus)

    def handle_raw(raw: str) -> None:
        envelope = decode_envelope(raw)
        if envelope["type"] != MessageType.VERDICT.value:
            return
        verdict = _verdict_from_payload(envelope["payload"])
        if verdict.action != Action.BLOCK:
            return
        if not verdict.host_ip:
            return
        enforcer.enforce(verdict, envelope["message_id"])

    last_heartbeat = 0.0
    iterations = 0
    while stop_after_iterations is None or iterations < stop_after_iterations:
        try:
            bus.consume(
                STREAM_VERDICTS,
                group=CONSUMER_GROUP,
                consumer=f"{COMPONENT_NAME}-1",
                handler=handle_raw,
                block_ms=int(poll_interval_s * 1000),
            )
            enforcer.reconcile_expired_blocks()

            now = time.time()
            heartbeat_interval = config_cache.get("watchdog.heartbeat_interval_s")
            if now - last_heartbeat >= heartbeat_interval:
                health = ComponentHealth(
                    name=COMPONENT_NAME, state=HealthState.NORMAL, last_heartbeat=utc_now_iso()
                )
                bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, health))
                last_heartbeat = now
        except Exception:
            configure_logging(COMPONENT_NAME).exception("error in enforcer poll loop")
        iterations += 1


if __name__ == "__main__":
    import os

    load_env()
    run(
        db_path=os.environ.get("NIDPS_DB_PATH", "/var/lib/nidps/nidps.sqlite3"),
        redis_url=os.environ.get("NIDPS_REDIS_URL", "redis://localhost:6379/0"),
    )
