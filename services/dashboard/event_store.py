"""EventStore: persists evidence rows and host.risk_score updates from the bus (FR-11.1, FR-6.3's
persisted side).

Scope note -- this deliberately does NOT subscribe to STREAM_VERDICTS or write the verdict table.
services/decision/verdict_store.py::VerdictStore already persists every non-PASS Verdict
synchronously, with its own autoincrement verdict_id, as part of services/decision/main.py's
per-message processing (see decide_groups() there). There is no separate "Enforcer" service in
this codebase computing a second, deterministic verdict_id for BLOCK rows, so there is no dual-write
to reconcile -- adding a second STREAM_VERDICTS consumer here that also INSERTs into verdict would
simply double-count every alert and block. verdict stays single-writer.

evidence, by contrast, has no writer yet anywhere in the codebase (confirmed: no other module runs
"INSERT INTO evidence"), and services/flowextract/persistence.py's upsert_host() explicitly says it
"Never writes host.risk_score (owned by the later Event Store phase)" -- this module is that later
phase for both of those."""
from __future__ import annotations

import sqlite3

from common.bus import STREAM_EVIDENCE, STREAM_HOST_SCORES, EventBus
from common.bus_messages import decode_envelope
from common.schemas import utc_now_iso

_CONSUMER_GROUP = "dashboard-event-store"


class EventStore:
    def __init__(self, conn: sqlite3.Connection, bus: EventBus, consumer_name: str = "event-store-1"):
        self._conn = conn
        self._bus = bus
        self._consumer = consumer_name

    def _upsert_host(self, ip: str) -> int:
        now = utc_now_iso()
        self._conn.execute(
            "INSERT OR IGNORE INTO host (ip_address, is_internal, first_seen, last_seen) "
            "VALUES (?, 1, ?, ?)",
            (ip, now, now),
        )
        self._conn.execute("UPDATE host SET last_seen = ? WHERE ip_address = ?", (now, ip))
        return self._conn.execute(
            "SELECT host_id FROM host WHERE ip_address = ?", (ip,)
        ).fetchone()[0]

    def _flow_row_id(self, flow_id) -> "int | None":
        """evidence.flow_id has a real FK into flow_record; a flow id that names no stored row
        (e.g. a correlation-window flow that hasn't been persisted, or never will be) must become
        NULL rather than violate the constraint. Same guard as
        services/decision/verdict_store.py::VerdictStore._flow_row_id()."""
        try:
            candidate = int(flow_id)
        except (TypeError, ValueError):
            return None
        row = self._conn.execute(
            "SELECT 1 FROM flow_record WHERE flow_id = ?", (candidate,)
        ).fetchone()
        return candidate if row else None

    def handle_evidence(self, raw: str) -> None:
        envelope = decode_envelope(raw)
        payload = envelope["payload"]
        host_id = self._upsert_host(payload["host_ip"])
        flow_id = self._flow_row_id(payload.get("flow_id"))
        self._conn.execute(
            """INSERT INTO evidence
               (flow_id, host_id, layer, evidence_type, signature_id, score, predicted_class,
                confidence, weight, model_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                flow_id, host_id, payload["source"], payload["kind"], payload.get("signature_id"),
                payload.get("strength"), payload.get("predicted_class"), payload.get("confidence"),
                payload["weight"], payload.get("model_id"), payload.get("timestamp", utc_now_iso()),
            ),
        )
        self._conn.commit()

    def handle_host_score(self, raw: str) -> None:
        envelope = decode_envelope(raw)
        payload = envelope["payload"]
        host_id = self._upsert_host(payload["host_ip"])
        self._conn.execute(
            "UPDATE host SET risk_score = ? WHERE host_id = ?", (payload["score"], host_id)
        )
        self._conn.commit()

    def consume_once(self, block_ms: int = 1000) -> None:
        self._bus.consume(
            STREAM_EVIDENCE, group=_CONSUMER_GROUP, consumer=self._consumer,
            handler=self.handle_evidence, block_ms=block_ms,
        )
        self._bus.consume(
            STREAM_HOST_SCORES, group=_CONSUMER_GROUP, consumer=self._consumer,
            handler=self.handle_host_score, block_ms=block_ms,
        )
