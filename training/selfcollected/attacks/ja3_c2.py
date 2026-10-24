"""Known-bad-JA3 C2 attack (Table 5.4).

Performs a normal Python `ssl` TLS handshake to an attacker-controlled listener.
Its JA3 fingerprint naturally differs from mainstream browsers (no special
crafting needed — this is also why this detection method works against real
malware). See this module's module-level docstring note in the implementation
plan for why a specific pre-known hash is not targeted.
"""

import socket
import ssl
from pathlib import Path

from training.selfcollected.attacks.common.runner import (
    AttackRecord, run_attack,
)


def connect(host: str, port: int) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            return tls_sock.version()


def run(
    victim_ip: str,
    attacker_ip: str,
    out_dir: Path,
    listener_host: str = "127.0.0.1",
    listener_port: int = 8443,
    dry_run: bool = False,
) -> AttackRecord:
    params = {"listener_host": listener_host, "listener_port": listener_port}

    def body():
        connect(listener_host, listener_port)

    return run_attack("ja3_c2", "python-ssl", attacker_ip, victim_ip, out_dir, params, body, dry_run)
