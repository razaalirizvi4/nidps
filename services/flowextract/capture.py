"""The only module in this plan that imports Scapy. Converts a raw Scapy packet into a
PacketMeta (Task 3). TLS records are parsed with plain struct-based byte parsing (reusing Task
4's parse_client_hello_body/parse_server_hello_body) rather than scapy.layers.tls, which needs
extra crypto dependencies this plan doesn't otherwise require."""
from __future__ import annotations

from typing import Optional

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from services.flowextract.five_tuple import PacketMeta
from services.flowextract.tls_fingerprint import parse_client_hello_body, parse_server_hello_body

_TCP_FLAG_BITS = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG", "E": "ECE", "C": "CWE",
}


def _decode_tcp_flags(flags) -> frozenset:
    return frozenset(_TCP_FLAG_BITS[c] for c in str(flags) if c in _TCP_FLAG_BITS)


def _extract_tls_handshake(payload: bytes):
    """Returns (client_hello_fields, server_hello_fields); either may be None. Looks for a TLS
    Handshake record (content type 0x16) at the start of the TCP payload."""
    if len(payload) < 9 or payload[0] != 0x16:
        return None, None
    record_len = int.from_bytes(payload[3:5], "big")
    handshake = payload[5 : 5 + record_len]
    if len(handshake) < 4:
        return None, None
    handshake_type = handshake[0]
    body = handshake[4:]
    if handshake_type == 0x01:
        return parse_client_hello_body(body), None
    if handshake_type == 0x02:
        return None, parse_server_hello_body(body)
    return None, None


def parse_packet(pkt) -> Optional[PacketMeta]:
    if IP not in pkt:
        return None
    ip_layer = pkt[IP]
    if TCP in pkt:
        transport = pkt[TCP]
        protocol = "TCP"
        tcp_flags = _decode_tcp_flags(transport.flags)
        tcp_window = int(transport.window)
    elif UDP in pkt:
        transport = pkt[UDP]
        protocol = "UDP"
        tcp_flags = frozenset()
        tcp_window = 0
    else:
        return None

    payload = bytes(pkt[Raw].load) if Raw in pkt else b""
    client_hello = None
    server_hello = None
    if protocol == "TCP" and payload:
        client_hello, server_hello = _extract_tls_handshake(payload)

    return PacketMeta(
        timestamp=float(pkt.time),
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        src_port=int(transport.sport),
        dst_port=int(transport.dport),
        protocol=protocol,
        length=len(pkt),
        payload_len=len(payload),
        tcp_flags=tcp_flags,
        tcp_window=tcp_window,
        tls_client_hello=client_hello,
        tls_server_hello=server_hello,
    )
