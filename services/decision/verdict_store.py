"""Persists verdicts to the verdict table (FR-6.2). Only ALERT and BLOCK are stored: a PASS is the
absence of an event, so keeping one per flow would bury the real rows. Verdicts with no source
address cannot be tied to a host and are skipped."""
from __future__ import annotations

import json
from typing import Optional

from common.schemas import Action, Verdict
from services.flowextract.persistence import upsert_host


class VerdictStore:
    def __init__(self, conn) -> None:
        self._conn = conn

    def save(self, verdict: Verdict) -> Optional[int]:
        """Returns the new verdict_id, or None when nothing was stored."""
        if verdict.action == Action.PASS or not verdict.host_ip:
            return None
        host_id = upsert_host(self._conn, verdict.host_ip)
        cur = self._conn.execute(
            """INSERT INTO verdict (flow_id, host_id, decision, layers, attack_class, explanation,
                                    created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                self._flow_row_id(verdict.flow_id),
                host_id,
                verdict.action.value,
                json.dumps([getattr(layer, "value", layer) for layer in verdict.layers]),
                verdict.attack_class,
                verdict.explanation,
                verdict.timestamp,
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def _flow_row_id(self, flow_id) -> Optional[int]:
        """The flow id on evidence is only a link if it names a stored flow_record row."""
        try:
            candidate = int(flow_id)
        except (TypeError, ValueError):
            return None
        row = self._conn.execute(
            "SELECT 1 FROM flow_record WHERE flow_id = ?", (candidate,)
        ).fetchone()
        return candidate if row else None
