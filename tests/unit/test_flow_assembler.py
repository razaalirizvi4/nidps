# tests/unit/test_flow_assembler.py
from services.flowextract.flow_assembler import FlowAssembler
from services.flowextract.five_tuple import PacketMeta
from services.flowextract.tls_fingerprint import parse_client_hello_body

CLIENT_HELLO_BODY_HEX = (
    "0303000000000000000000000000000000000000000000000000000000000000000000000a0a0a1301"
    "1302c02bc02f010000311a1a000000000010000e00000b6578616d706c652e636f6d000a0006000400"
    "1d0017000b00020100001000050003026832"
)


def test_fin_both_directions_emits_full_flow_and_removes_key():
    asm = FlowAssembler(active_timeout=10, idle_timeout=30)
    packets = [
        PacketMeta(0.00, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 60, 0, frozenset({"SYN"})),
        PacketMeta(0.01, "93.184.216.34", "10.0.0.5", 443, 51000, "TCP", 60, 0, frozenset({"SYN", "ACK"})),
        PacketMeta(0.02, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 60, 0, frozenset({"ACK"})),
        PacketMeta(0.03, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 60, 0, frozenset({"FIN", "ACK"})),
        PacketMeta(0.04, "93.184.216.34", "10.0.0.5", 443, 51000, "TCP", 60, 0, frozenset({"FIN", "ACK"})),
    ]
    emitted = []
    for p in packets:
        emitted.extend(asm.onPacket(p))

    assert len(emitted) == 1
    assert emitted[0].is_partial is False
    assert emitted[0].segment_no == 0
    assert emitted[0].src_ip == "10.0.0.5"
    assert emitted[0].dst_ip == "93.184.216.34"
    assert len(emitted[0].feature_values) == 78
    assert len(asm.flow_table) == 0


def test_rst_emits_full_flow_immediately():
    asm = FlowAssembler(active_timeout=10, idle_timeout=30)
    asm.onPacket(PacketMeta(0.0, "10.0.0.5", "1.2.3.4", 51000, 80, "TCP", 60, 0, frozenset({"SYN"})))
    emitted = asm.onPacket(
        PacketMeta(0.01, "1.2.3.4", "10.0.0.5", 80, 51000, "TCP", 60, 0, frozenset({"RST"}))
    )
    assert len(emitted) == 1
    assert emitted[0].is_partial is False
    assert len(asm.flow_table) == 0


def test_active_timeout_emits_partial_and_keeps_key_with_incremented_segment():
    asm = FlowAssembler(active_timeout=10, idle_timeout=30)
    first = PacketMeta(0.0, "10.0.0.5", "1.2.3.4", 51000, 80, "TCP", 60, 0, frozenset({"SYN"}))
    second = PacketMeta(15.0, "10.0.0.5", "1.2.3.4", 51000, 80, "TCP", 60, 10, frozenset({"ACK"}))

    assert asm.onPacket(first) == []
    emitted = asm.onPacket(second)

    assert len(emitted) == 1
    assert emitted[0].is_partial is True
    assert emitted[0].segment_no == 0
    assert len(asm.flow_table) == 1
    kept_state = next(iter(asm.flow_table.values()))
    assert kept_state.segment_no == 1


def test_expire_idle_emits_full_flow_and_removes_key():
    asm = FlowAssembler(active_timeout=10, idle_timeout=30)
    asm.onPacket(PacketMeta(0.0, "10.0.0.9", "5.6.7.8", 51000, 53, "UDP", 60, 40, frozenset()))

    assert len(asm.flow_table) == 1
    expired = asm.expireIdle(now=31.0)

    assert len(expired) == 1
    # Reaching expireIdle means this flow never saw a full FIN/RST close -- it is always
    # partial (C2, item 4): a flow that *did* close fully is emitted and removed by onPacket
    # itself and is already gone from flow_table by the time expireIdle would see it.
    assert expired[0].is_partial is True
    assert len(asm.flow_table) == 0


def test_expire_idle_does_not_fabricate_flow_for_empty_rollover_segment():
    # Cross one active-timeout rollover, then go idle with zero packets in the new segment.
    asm = FlowAssembler(active_timeout=10, idle_timeout=30)
    first = PacketMeta(0.0, "10.0.0.5", "1.2.3.4", 51000, 80, "TCP", 60, 0, frozenset({"SYN"}))
    second = PacketMeta(15.0, "10.0.0.5", "1.2.3.4", 51000, 80, "TCP", 60, 10, frozenset({"ACK"}))

    assert asm.onPacket(first) == []
    rollover_emitted = asm.onPacket(second)
    assert len(rollover_emitted) == 1  # the active-timeout partial emission for segment 0

    assert len(asm.flow_table) == 1
    kept_state = next(iter(asm.flow_table.values()))
    assert kept_state.accumulator.all_len.count == 0  # segment 1 never saw a packet

    expired = asm.expireIdle(now=100.0)

    assert expired == []  # no fabricated all-zero flow_record
    assert len(asm.flow_table) == 0  # the stale key is still removed


def test_expire_idle_marks_flow_with_real_packets_as_partial():
    asm = FlowAssembler(active_timeout=10, idle_timeout=30)
    asm.onPacket(PacketMeta(0.0, "10.0.0.5", "1.2.3.4", 51000, 80, "TCP", 60, 0, frozenset({"SYN"})))
    asm.onPacket(PacketMeta(0.01, "1.2.3.4", "10.0.0.5", 80, 51000, "TCP", 60, 0, frozenset({"ACK"})))

    expired = asm.expireIdle(now=31.0)

    assert len(expired) == 1
    assert expired[0].is_partial is True


def test_tls_client_hello_attaches_ja3_to_flow():
    asm = FlowAssembler(active_timeout=10, idle_timeout=30)
    parsed = parse_client_hello_body(bytes.fromhex(CLIENT_HELLO_BODY_HEX))
    hello_packet = PacketMeta(
        0.0, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 517, 0, frozenset({"ACK"}),
        tls_client_hello=parsed,
    )
    asm.onPacket(hello_packet)
    expired = asm.expireIdle(now=100.0)

    assert expired[0].tls.ja3 == "debfe4007ee55753199d6ce73ed68dc8"
    assert expired[0].tls.server_name == "example.com"
