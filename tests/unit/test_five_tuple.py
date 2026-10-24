from services.flowextract.five_tuple import PacketMeta, canonical_five_tuple


def test_canonical_key_same_regardless_of_direction():
    forward = canonical_five_tuple("10.0.0.5", 51000, "93.184.216.34", 443, "TCP")
    reverse = canonical_five_tuple("93.184.216.34", 443, "10.0.0.5", 51000, "TCP")
    assert forward == reverse


def test_canonical_key_differs_by_protocol():
    tcp_key = canonical_five_tuple("10.0.0.5", 51000, "93.184.216.34", 443, "TCP")
    udp_key = canonical_five_tuple("10.0.0.5", 51000, "93.184.216.34", 443, "UDP")
    assert tcp_key != udp_key


def test_packet_meta_defaults():
    meta = PacketMeta(
        timestamp=1000.0,
        src_ip="10.0.0.5",
        dst_ip="93.184.216.34",
        src_port=51000,
        dst_port=443,
        protocol="TCP",
        length=60,
        payload_len=0,
        tcp_flags=frozenset({"SYN"}),
    )
    assert meta.tcp_window == 0
    assert meta.tls_client_hello is None
    assert meta.tls_server_hello is None
