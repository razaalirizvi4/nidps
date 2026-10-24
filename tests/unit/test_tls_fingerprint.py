from services.flowextract.tls_fingerprint import (
    compute_tls_fingerprint,
    parse_client_hello_body,
    parse_server_hello_body,
)

# Hand-built TLS 1.2 ClientHello Handshake body (NOT including the 4-byte Handshake header or the
# 5-byte record header): version=0x0303, 32 zero-byte random, empty session id, cipher suites
# [0x0a0a(GREASE), 0x1301, 0x1302, 0xc02b, 0xc02f], one compression method (0x00), extensions
# [0x1a1a(GREASE, empty), 0x0000 server_name="example.com", 0x000a supported_groups=[0x001d,
# 0x0017], 0x000b ec_point_formats=[0x00], 0x0010 ALPN="h2"]. Built and verified with a
# standalone script while writing this plan -- the hex below is exactly that script's output.
CLIENT_HELLO_BODY_HEX = (
    "0303000000000000000000000000000000000000000000000000000000000000000000000a0a0a1301"
    "1302c02bc02f010000311a1a000000000010000e00000b6578616d706c652e636f6d000a0006000400"
    "1d0017000b00020100001000050003026832"
)

# Hand-built ServerHello Handshake body: version=0x0303, 32 bytes of 0x11, empty session id,
# chosen cipher 0x1301, compression 0x00, extensions [0x2a2a(GREASE, empty), 0x0000 (empty),
# 0x002b supported_versions=0x0304].
SERVER_HELLO_BODY_HEX = (
    "03031111111111111111111111111111111111111111111111111111111111111111001301000"
    "00e2a2a000000000000002b00020304"
)


def test_parse_client_hello_body_extracts_all_fields():
    body = bytes.fromhex(CLIENT_HELLO_BODY_HEX)
    parsed = parse_client_hello_body(body)

    assert parsed["version"] == 771
    assert parsed["cipher_suites"] == [2570, 4865, 4866, 49195, 49199]
    assert parsed["extensions"] == [6682, 0, 10, 11, 16]
    assert parsed["groups"] == [29, 23]
    assert parsed["point_formats"] == [0]
    assert parsed["server_name"] == "example.com"


def test_compute_ja3_removes_grease_and_matches_known_md5():
    parsed = parse_client_hello_body(bytes.fromhex(CLIENT_HELLO_BODY_HEX))
    ja3 = compute_tls_fingerprint(
        version=parsed["version"],
        cipher_suites=parsed["cipher_suites"],
        extensions=parsed["extensions"],
        groups=parsed["groups"],
        point_formats=parsed["point_formats"],
    )
    assert ja3 == "debfe4007ee55753199d6ce73ed68dc8"


def test_parse_server_hello_body_extracts_fields():
    body = bytes.fromhex(SERVER_HELLO_BODY_HEX)
    parsed = parse_server_hello_body(body)

    assert parsed["version"] == 771
    assert parsed["cipher_suites"] == [4865]
    assert parsed["extensions"] == [10794, 0, 43]


def test_compute_ja3s_removes_grease_and_matches_known_md5():
    parsed = parse_server_hello_body(bytes.fromhex(SERVER_HELLO_BODY_HEX))
    ja3s = compute_tls_fingerprint(
        version=parsed["version"],
        cipher_suites=parsed["cipher_suites"],
        extensions=parsed["extensions"],
    )
    assert ja3s == "32c243fff40e548be0e9d43d09174766"
