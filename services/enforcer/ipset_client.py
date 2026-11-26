"""Thin subprocess wrapper over the ipset/iptables CLIs (FR-7.1, FR-7.2). The ipset sets rely on
their own 'timeout' feature to auto-expire blocks in the kernel — no separate expiry poller
removes entries early; reconcile_expired_blocks() in enforcer.py handles the DB-side status
bookkeeping only.

Two sets are maintained (one per address family) because a single hash:ip set is single-family —
add() picks the right one based on the IP's version so IPv6 hosts (e.g. a phone scanning over its
fe80:: link-local address) actually get blocked instead of silently failing against a family-inet
set. ensure_firewall_rules() inserts the INPUT/FORWARD DROP rules that make ipset membership
actually enforced; without it the sets are just bookkeeping and no traffic is dropped."""
from __future__ import annotations

import ipaddress
import subprocess
from typing import Callable, Optional

Runner = Callable[[list], object]


class IpsetClient:
    def __init__(
        self,
        set_name_v4: str = "nidps_blocklist",
        set_name_v6: str = "nidps_blocklist6",
        runner: Optional[Runner] = None,
    ):
        self._set_name_v4 = set_name_v4
        self._set_name_v6 = set_name_v6
        self._runner = runner or self._default_runner

    @staticmethod
    def _default_runner(argv: list) -> object:
        return subprocess.run(argv, capture_output=True, text=True, check=False)

    def run(self, argv: list) -> object:
        return self._runner(argv)

    def _set_for(self, ip: str) -> str:
        if ipaddress.ip_address(ip).version == 6:
            return self._set_name_v6
        return self._set_name_v4

    def ensure_set_exists(self) -> None:
        self.run([
            "ipset", "create", self._set_name_v4, "hash:ip",
            "family", "inet", "timeout", "0", "-exist",
        ])
        self.run([
            "ipset", "create", self._set_name_v6, "hash:ip",
            "family", "inet6", "timeout", "0", "-exist",
        ])

    def ensure_firewall_rules(self) -> None:
        for binary, set_name in (
            ("iptables", self._set_name_v4),
            ("ip6tables", self._set_name_v6),
        ):
            for chain in ("INPUT", "FORWARD"):
                rule = ["-m", "set", "--match-set", set_name, "src", "-j", "DROP"]
                check = self.run([binary, "-C", chain, *rule])
                if getattr(check, "returncode", 1) != 0:
                    self.run([binary, "-I", chain, *rule])

    def add(self, ip: str, timeout_s: int) -> None:
        self.run(["ipset", "add", self._set_for(ip), ip, "timeout", str(int(timeout_s)), "-exist"])

    def remove(self, ip: str) -> None:
        self.run(["ipset", "del", self._set_for(ip), ip])
