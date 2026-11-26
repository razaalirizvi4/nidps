"""Read/write access to allowlist_entry (FR-7.3). Seeds the three permanent system entries
(NIDPS host, ISP gateway, DNS resolver) so they can never be blocked from day one."""
from __future__ import annotations

from typing import Optional

from common.schemas import utc_now_iso


class AllowlistStore:
    def __init__(self, conn) -> None:
        self._conn = conn

    def seed_system_entries(
        self,
        nidps_ip: Optional[str] = None,
        gateway_ip: Optional[str] = None,
        dns_ip: Optional[str] = None,
        added_by: Optional[int] = None,
    ) -> None:
        entries = [
            (nidps_ip, "NIDPS host (self)"),
            (gateway_ip, "ISP gateway / default route"),
            (dns_ip, "DNS resolver"),
        ]
        for address, description in entries:
            if not address:
                continue
            self._conn.execute(
                """INSERT OR IGNORE INTO allowlist_entry
                   (address, description, is_permanent, added_by, added_at)
                   VALUES (?, ?, 1, ?, ?)""",
                (address, description, added_by, utc_now_iso()),
            )
        self._conn.commit()

    def contains(self, ip: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM allowlist_entry WHERE address = ?", (ip,)
        ).fetchone()
        return row is not None
