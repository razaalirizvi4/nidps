"""Entry point for the decision engine. process_evidence_message() and publish_decision() are the
dependency-injected core the tests call; main() wraps them in a bus-consume loop with the
correlator flush, a periodic host-score refresh (so the dashboard sees scores decay), and a
heartbeat."""
from __future__ import annotations

import logging
import os
import socket
import time
from typing import Optional

from common.bus import (
    STREAM_EVIDENCE,
    STREAM_HEARTBEATS,
    STREAM_HOST_SCORES,
    STREAM_VERDICTS,
    EventBus,
)
from common.bus_messages import MessageType, decode_envelope, encode_envelope
from common.config_loader import get as config_get
from common.db.migrate import connect
from common.logging_setup import configure_logging
from common.schemas import (
    ComponentHealth,
    Evidence,
    EvidenceType,
    HealthState,
    HostScore,
    Layer,
    utc_now_iso,
)
from services.decision.allowlist import Allowlist
from services.decision.correlator import EvidenceCorrelator
from services.decision.engine import Decision, DecisionEngine
from services.decision.risk_tracker import RiskScoreTracker
from services.decision.verdict_store import VerdictStore
from services.flowextract.config_cache import CachedConfig

SCORE_REFRESH_S = 30.0


def evidence_from_payload(payload: dict) -> Evidence:
    return Evidence(
        source=Layer(payload["source"]),
        flow_id=payload.get("flow_id"),
        host_ip=payload["host_ip"],
        kind=EvidenceType(payload["kind"]),
        strength=payload["strength"],
        weight=payload["weight"],
        timestamp=payload.get("timestamp") or utc_now_iso(),
        signature_id=payload.get("signature_id"),
        predicted_class=payload.get("predicted_class"),
        confidence=payload.get("confidence"),
        model_id=payload.get("model_id"),
    )


def publish_decision(bus: EventBus, decision: Decision) -> None:
    bus.publish(STREAM_VERDICTS, encode_envelope(MessageType.VERDICT, decision.verdict))
    if decision.host_score is not None:
        bus.publish(
            STREAM_HOST_SCORES,
            encode_envelope(MessageType.HOST_SCORE_UPDATED, decision.host_score),
        )


def decide_groups(
    engine: DecisionEngine, bus: EventBus, groups: list, store: Optional[VerdictStore] = None
) -> int:
    for group in groups:
        decision = engine.decide(group)
        publish_decision(bus, decision)
        if store is not None:
            # The verdict is already on the bus, so a database failure must not undo or hide it.
            try:
                store.save(decision.verdict)
            except Exception:
                logging.getLogger("decision").exception("could not persist verdict")
    return len(groups)


def process_evidence_message(
    engine: DecisionEngine,
    correlator: EvidenceCorrelator,
    bus: EventBus,
    body: str,
    store: Optional[VerdictStore] = None,
) -> int:
    envelope = decode_envelope(body)
    evidence = evidence_from_payload(envelope["payload"])
    return decide_groups(engine, bus, correlator.add(evidence), store)


def publish_score_refresh(bus: EventBus, risk: RiskScoreTracker) -> int:
    scores = risk.snapshot(utc_now_iso())
    for host_ip, score in scores.items():
        bus.publish(
            STREAM_HOST_SCORES,
            encode_envelope(MessageType.HOST_SCORE_UPDATED, HostScore(host_ip=host_ip, score=score)),
        )
    return len(scores)


def publish_heartbeat(bus: EventBus) -> None:
    health = ComponentHealth(name="decision", state=HealthState.NORMAL, last_heartbeat=utc_now_iso())
    bus.publish(STREAM_HEARTBEATS, encode_envelope(MessageType.HEARTBEAT, health))


def main() -> None:
    db_path = os.environ.get("NIDPS_DB_PATH", "/var/lib/nidps/nidps.sqlite3")
    redis_url = os.environ.get("NIDPS_REDIS_URL", "redis://localhost:6379/0")

    logger = configure_logging("decision")
    conn = connect(db_path)
    bus = EventBus.from_url(redis_url)
    config = CachedConfig(conn)
    consumer_name = socket.gethostname()

    risk = RiskScoreTracker(half_life_s=lambda: config.get("risk.half_life_s"))
    engine = DecisionEngine(risk, Allowlist(conn), config)
    correlator = EvidenceCorrelator(window_s=3.0)
    store = VerdictStore(conn)

    def _handle(body: str) -> None:
        try:
            process_evidence_message(engine, correlator, bus, body, store)
        except Exception:
            logger.exception("error processing EVIDENCE message")

    logger.info("decision engine starting, consumer=%s", consumer_name)
    last_heartbeat = 0.0
    last_refresh = time.time()
    while True:
        try:
            bus.consume(
                STREAM_EVIDENCE, group="decision", consumer=consumer_name, handler=_handle, block_ms=1000
            )
            now = time.time()

            try:
                decide_groups(engine, bus, correlator.flush_due(), store)
            except Exception:
                logger.exception("error flushing correlated evidence")

            try:
                if now - last_refresh >= SCORE_REFRESH_S:
                    publish_score_refresh(bus, risk)
                    last_refresh = now
            except Exception:
                logger.exception("error publishing host score refresh")

            if now - last_heartbeat >= config_get(conn, "watchdog.heartbeat_interval_s"):
                publish_heartbeat(bus)
                last_heartbeat = now
        except Exception:
            logger.exception("error in decision poll loop")


if __name__ == "__main__":
    main()
