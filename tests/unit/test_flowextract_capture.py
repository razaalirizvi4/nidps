from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.packet import Raw

from common.config_loader import seed_defaults, update
from common.db.migrate import connect
from services.flowextract.capture import parse_packet
from services.flowextract.config_cache import CachedConfig

CLIENT_HELLO_RECORD_HEX = (
    "16030100680100006403030000000000000000000000000000000000000000000000000000000000"
    "00000000000a0a0a13011302c02bc02f010000311a1a000000000010000e00000b6578616d706c65"
    "2e636f6d000a00060004001d0017000b00020100001000050003026832"
)


def test_cached_config_returns_seeded_default():
    conn = connect(":memory:")
    seed_defaults(conn)
    cache = CachedConfig(conn)
    assert cache.get("network.active_timeout_s") == 10


def test_cached_config_serves_stale_value_until_ttl_expires():
    conn = connect(":memory:")
    seed_defaults(conn)
    fake_time = [0.0]
    cache = CachedConfig(conn, ttl_s=5.0, clock=lambda: fake_time[0])

    assert cache.get("network.active_timeout_s") == 10
    update(conn, "network.active_timeout_s", 20)
    fake_time[0] = 2.0  # still within the 5s TTL
    assert cache.get("network.active_timeout_s") == 10  # stale on purpose

    fake_time[0] = 6.0  # TTL expired
    assert cache.get("network.active_timeout_s") == 20


def test_parse_packet_extracts_tcp_metadata_and_flags():
    pkt = IP(src="10.0.0.5", dst="93.184.216.34") / TCP(
        sport=51000, dport=443, flags="PA", window=64240
    ) / Raw(load=b"hello")
    pkt.time = 1700000000.123

    meta = parse_packet(pkt)

    assert meta.src_ip == "10.0.0.5"
    assert meta.dst_ip == "93.184.216.34"
    assert meta.src_port == 51000
    assert meta.dst_port == 443
    assert meta.protocol == "TCP"
    assert meta.tcp_flags == frozenset({"PSH", "ACK"})
    assert meta.tcp_window == 64240
    assert meta.payload_len == 5
    assert meta.timestamp == 1700000000.123
    assert meta.tls_client_hello is None


def test_parse_packet_extracts_tls_client_hello():
    record = bytes.fromhex(CLIENT_HELLO_RECORD_HEX)
    pkt = IP(src="10.0.0.5", dst="93.184.216.34") / TCP(
        sport=51000, dport=443, flags="A", window=64240
    ) / Raw(load=record)
    pkt.time = 1700000000.0

    meta = parse_packet(pkt)

    assert meta.tls_client_hello is not None
    assert meta.tls_client_hello["version"] == 771
    assert meta.tls_client_hello["server_name"] == "example.com"


def test_parse_packet_ignores_non_ip_packets():
    assert parse_packet(ARP()) is None


def test_parse_packet_handles_udp():
    pkt = IP(src="10.0.0.9", dst="8.8.8.8") / UDP(sport=51000, dport=53) / Raw(load=b"dns-query")
    pkt.time = 1700000000.0

    meta = parse_packet(pkt)

    assert meta.protocol == "UDP"
    assert meta.tcp_flags == frozenset()
