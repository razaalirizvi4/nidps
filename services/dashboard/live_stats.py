"""In-memory live counters for the Overview screen's [SYSTEM SUMMARY] panel (FR-9.2). Per the
spec's design note, live counters are kept in memory and on the event bus rather than in the
database -- flows_analyzed/intrusions_detected are tallied from their own "dashboard-live-stats"
consumer group (independent of every other service's group on the same streams, e.g. decision's
own "decision" group on STREAM_EVIDENCE -- Redis Streams consumer groups are independent by
design), and only active_blocks is a cheap COUNT(*) read of block_entry (the one counter that
isn't naturally bus-derived and is inexpensive to read directly).

Active blocks will read as 0 until something actually inserts block_entry rows -- as of this
writing nothing in the codebase does (confirmed: services/mlscorer/calibration.py only reads the
table to exclude already-blocked hosts from calibration sampling). That's a real, pre-existing gap
in the enforcement side of the system, not a bug in this counter."""
from __future__ import annotations

import sqlite3

from common.bus import STREAM_FLOWS, STREAM_VERDICTS, EventBus
from common.bus_messages import decode_envelope

_CONSUMER_GROUP = "dashboard-live-stats"


class LiveStats:
    def __init__(self, conn: sqlite3.Connection, bus: EventBus, consumer_name: str = "live-stats-1"):
        self._conn = conn
        self._bus = bus
        self._consumer = consumer_name
        self._flows_analyzed = 0
        self._intrusions_detected = 0

    def _on_flow(self, raw: str) -> None:
        decode_envelope(raw)  # validates envelope schema version
        self._flows_analyzed += 1

    def _on_verdict(self, raw: str) -> None:
        envelope = decode_envelope(raw)
        if envelope["payload"]["action"] in ("ALERT", "BLOCK"):
            self._intrusions_detected += 1

    def consume_once(self, block_ms: int = 1000) -> None:
        self._bus.consume(
            STREAM_FLOWS, group=_CONSUMER_GROUP, consumer=self._consumer,
            handler=self._on_flow, block_ms=block_ms,
        )
        self._bus.consume(
            STREAM_VERDICTS, group=_CONSUMER_GROUP, consumer=self._consumer,
            handler=self._on_verdict, block_ms=block_ms,
        )

    def _active_blocks(self) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) FROM block_entry WHERE status = 'ACTIVE'"
        ).fetchone()[0]

    def snapshot(self) -> dict:
        return {
            "flows_analyzed": self._flows_analyzed,
            "intrusions_detected": self._intrusions_detected,
            "active_blocks": self._active_blocks(),
        }
