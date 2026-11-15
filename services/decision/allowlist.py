"""Read-only allowlist lookup for Algorithm 5.5 line 1. Entries in allowlist_entry.address may
be a single IP or a CIDR range. Cached for a few seconds so a dashboard edit takes effect without
a restart (FR-10.6) but the engine does not query SQLite for every evidence item. The table is
written elsewhere (the enforcer seeds the permanent entries, the dashboard edits the rest)."""
from __future__ import annotations

import ipaddress
import time
from typing import Callable


class Allowlist:
    def __init__(self, conn, ttl_s: float = 5.0, clock: Callable[[], float] = time.monotonic) -> None:
        self._conn = conn
        self._ttl_s = ttl_s
        self._clock = clock
        self._loaded_at = None
        self._networks: list = []

    def _refresh(self) -> None:
        now = self._clock()
        if self._loaded_at is not None and now - self._loaded_at < self._ttl_s:
            return
        networks = []
        for (address,) in self._conn.execute("SELECT address FROM allowlist_entry"):
            try:
                networks.append(ipaddress.ip_network(address.strip(), strict=False))
            except ValueError:
                continue  # a malformed row must not stop the engine
        self._networks = networks
        self._loaded_at = now

    def contains(self, ip: str) -> bool:
        self._refresh()
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._networks if net.version == addr.version)
