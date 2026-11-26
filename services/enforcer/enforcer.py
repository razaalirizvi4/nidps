"""Enforcer.enforce() implements Algorithm 5.6 (enforce a BLOCK verdict). Owns block_entry and
audit_log (FR-7.6) and makes the one explicitly-justified synchronous write to verdict (see the
decision-fusion plan's Global Constraints, 'Verdict dual-write exception')."""
from __future__ import annotations

import json
import logging
import time
from collections import defaultdict, deque
from typing import Callable, Optional

from common.bus import STREAM_VERDICTS, EventBus
from common.bus_messages import MessageType, encode_envelope
from common.schemas import Action, BlockEntry, Verdict, utc_now_iso

from services.enforcer.allowlist import AllowlistStore
from services.enforcer.ipset_client import IpsetClient
from services.enforcer.time_utils import add_seconds_iso, epoch_hours_ago_iso
from services.enforcer.verdict_sync import verdict_id_from_message_id

logger = logging.getLogger("enforcer")


class Enforcer:
    def __init__(
        self,
        conn,
        ipset_client: IpsetClient,
        allowlist: AllowlistStore,
        config_getter: Callable[[str], float],
        bus: EventBus,
        now_fn: Callable[[], float] = time.time,
    ):
        self._conn = conn
        self._ipset = ipset_client
        self.allowlist = allowlist
        self._config_getter = config_getter
        self._bus = bus
        self._now_fn = now_fn
        self._recent_block_times: dict[str, deque] = defaultdict(deque)
        self.maxBlocksPerMinute: Optional[int] = None

    def _upsert_host(self, ip: str) -> int:
        now = utc_now_iso()
        self._conn.execute(
            "INSERT OR IGNORE INTO host (ip_address, is_internal, first_seen, last_seen) "
            "VALUES (?, 1, ?, ?)",
            (ip, now, now),
        )
        self._conn.execute("UPDATE host SET last_seen = ? WHERE ip_address = ?", (now, ip))
        row = self._conn.execute(
            "SELECT host_id FROM host WHERE ip_address = ?", (ip,)
        ).fetchone()
        return row[0]

    def _write_audit(self, action: str, target: str, new_value: Optional[str] = None) -> None:
        self._conn.execute(
            "INSERT INTO audit_log (user_id, action, target, old_value, new_value, timestamp) "
            "VALUES (NULL, ?, ?, NULL, ?, ?)",
            (action, target, new_value, utc_now_iso()),
        )

    def _offence_count_24h(self, host_id: int) -> int:
        cutoff = epoch_hours_ago_iso(24, now_fn=self._now_fn)
        row = self._conn.execute(
            "SELECT COUNT(*) FROM block_entry WHERE host_id = ? AND start_time >= ?",
            (host_id, cutoff),
        ).fetchone()
        return row[0]

    def _prune_recent_blocks(self, host_ip: str) -> None:
        now = self._now_fn()
        times = self._recent_block_times[host_ip]
        while times and now - times[0] > 60.0:
            times.popleft()

    def _verdict_flow_id_int(self, verdict: Verdict) -> Optional[int]:
        if verdict.flow_id is not None and str(verdict.flow_id).isdigit():
            return int(verdict.flow_id)
        return None

    def enforce(self, verdict: Verdict, message_id: str) -> Optional[BlockEntry]:
        host_ip = verdict.host_ip
        self.maxBlocksPerMinute = self._config_getter("enforcement.rate_limit_per_minute")

        if self.allowlist.contains(host_ip):
            logger.info("block suppressed: %s is allowlisted", host_ip)
            self._write_audit("BLOCK_SKIPPED_ALLOWLIST", host_ip, new_value=verdict.explanation)
            self._conn.commit()
            return None

        self._prune_recent_blocks(host_ip)
        if len(self._recent_block_times[host_ip]) >= self.maxBlocksPerMinute:
            logger.warning(
                "block rate limit exceeded for %s (%d/min, max %d); downgrading to ALERT",
                host_ip, len(self._recent_block_times[host_ip]), self.maxBlocksPerMinute,
            )
            self._write_audit("BLOCK_RATE_LIMITED", host_ip, new_value=verdict.explanation)
            self._conn.commit()
            downgraded = Verdict(
                action=Action.ALERT,
                layers=verdict.layers,
                explanation=(
                    f"Block suppressed by rate limit ({self.maxBlocksPerMinute}/min exceeded); "
                    f"raised as ALERT instead. Original reason: {verdict.explanation}"
                ),
                flow_id=verdict.flow_id,
                host_ip=host_ip,
                attack_class=verdict.attack_class,
            )
            self._bus.publish(STREAM_VERDICTS, encode_envelope(MessageType.VERDICT, downgraded))
            return None

        host_id = self._upsert_host(host_ip)
        n = self._offence_count_24h(host_id)
        base = self._config_getter("enforcement.base_block_s")
        max_d = self._config_getter("enforcement.max_block_s")
        duration = int(min(base * (2 ** n), max_d))

        # Deterministic verdict_id from the bus message so the future Event Store can
        # converge on the same row via INSERT OR IGNORE (dual-write exception).
        verdict_id = verdict_id_from_message_id(message_id)
        layers_json = json.dumps([
            layer.value if hasattr(layer, "value") else layer for layer in verdict.layers
        ])
        self._conn.execute(
            """INSERT OR IGNORE INTO verdict
               (verdict_id, flow_id, host_id, decision, layers, attack_class, explanation, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                verdict_id,
                self._verdict_flow_id_int(verdict),
                host_id,
                verdict.action.value,
                layers_json,
                verdict.attack_class,
                verdict.explanation,
                verdict.timestamp,
            ),
        )

        start_time = utc_now_iso()
        expires_at = add_seconds_iso(start_time, duration)
        self._conn.execute(
            """INSERT INTO block_entry
               (host_id, verdict_id, offence_count, duration_s, start_time, expires_at, status)
               VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')""",
            (host_id, verdict_id, n, duration, start_time, expires_at),
        )
        self._write_audit("BLOCK", host_ip, new_value=f"duration_s={duration} offence_count={n}")
        self._conn.commit()

        self._ipset.add(host_ip, duration)
        self._recent_block_times[host_ip].append(self._now_fn())
        logger.info("blocked %s for %ds (offence #%d in last 24h)", host_ip, duration, n)

        return BlockEntry(
            ip=host_ip, reason=verdict.explanation, duration_s=duration, offence_count=n
        )

    def unblock(self, ip: str, released_by: Optional[int] = None) -> None:
        row = self._conn.execute(
            """SELECT block_entry.block_id FROM block_entry
               JOIN host ON host.host_id = block_entry.host_id
               WHERE host.ip_address = ? AND block_entry.status = 'ACTIVE'
               ORDER BY block_entry.start_time DESC LIMIT 1""",
            (ip,),
        ).fetchone()
        self._ipset.remove(ip)
        now = utc_now_iso()
        if row is not None:
            self._conn.execute(
                "UPDATE block_entry SET status = 'RELEASED', released_by = ?, released_at = ? "
                "WHERE block_id = ?",
                (released_by, now, row[0]),
            )
        self._write_audit("BLOCK_RELEASED", ip, new_value=f"released_by={released_by}")
        self._conn.commit()

    def reconcile_expired_blocks(self) -> int:
        """Mark ACTIVE blocks whose expires_at has passed as EXPIRED (DB bookkeeping only —
        ipset's own timeout already removed them from the kernel set)."""
        now = utc_now_iso()
        cursor = self._conn.execute(
            "UPDATE block_entry SET status = 'EXPIRED' WHERE status = 'ACTIVE' AND expires_at <= ?",
            (now,),
        )
        self._conn.commit()
        return cursor.rowcount
