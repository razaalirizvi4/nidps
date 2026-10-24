"""Parses dnsmasq's lease file into the trusted IP->MAC map Algorithm 5.3 calls Bindings. The
path is always a function argument (never hardcoded to /var/lib/misc/dnsmasq.leases) so tests
never touch a real system file."""
from __future__ import annotations


def parse_dnsmasq_leases(path: str) -> dict:
    bindings: dict = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        return bindings

    for line in lines:
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        _expiry, mac, ip = parts[0], parts[1], parts[2]
        bindings[ip] = mac.lower()
    return bindings
