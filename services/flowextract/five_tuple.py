"""Canonical 5-tuple keying (Algorithm 5.1, line 3) so both directions of one conversation map to
the same FlowTable entry, plus the packet-level value object (PacketMeta) that decouples
FlowAssembler from Scapy -- services/flowextract/capture.py is the only module that imports Scapy."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class PacketMeta:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "TCP" or "UDP"
    length: int
    payload_len: int
    tcp_flags: frozenset
    tcp_window: int = 0
    tls_client_hello: Optional[dict] = None
    tls_server_hello: Optional[dict] = None


def canonical_five_tuple(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str
) -> tuple:
    endpoint_a = (src_ip, src_port)
    endpoint_b = (dst_ip, dst_port)
    low, high = (endpoint_a, endpoint_b) if endpoint_a <= endpoint_b else (endpoint_b, endpoint_a)
    return (low, high, protocol)
