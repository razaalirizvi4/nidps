import math

from services.flowextract.features import FEATURE_NAMES, FlowFeatureAccumulator
from services.flowextract.five_tuple import PacketMeta


def _idx(name: str) -> int:
    return FEATURE_NAMES.index(name)


def test_feature_names_has_78_unique_entries():
    assert len(FEATURE_NAMES) == 78
    assert len(set(FEATURE_NAMES)) == 78


def test_finalize_matches_hand_verified_worked_example():
    # 5-packet TCP flow, dst_port=443: fwd@t=0 len=100 SYN win=64240; bwd@t=0.05 len=500 SYN,ACK
    # win=29200; fwd@t=0.10 len=200 ACK,PSH payload=150; bwd@t=0.25 len=80 ACK payload=20;
    # fwd@t=0.30 len=150 ACK,FIN payload=50. Every inter-packet gap is < the 1.0s sub-burst gap,
    # so the whole flow is one active burst and there is no idle period. All 78 expected values
    # below were computed and independently verified (Welford math + flag/byte counting) by hand
    # while writing this plan -- see this plan's Task 5 commentary for the full derivation.
    acc = FlowFeatureAccumulator(protocol="TCP", dst_port=443)
    packets = [
        PacketMeta(0.00, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 100, 0, frozenset({"SYN"}), 64240),
        PacketMeta(0.05, "93.184.216.34", "10.0.0.5", 443, 51000, "TCP", 500, 0, frozenset({"SYN", "ACK"}), 29200),
        PacketMeta(0.10, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 200, 150, frozenset({"ACK", "PSH"}), 64240),
        PacketMeta(0.25, "93.184.216.34", "10.0.0.5", 443, 51000, "TCP", 80, 20, frozenset({"ACK"}), 29200),
        PacketMeta(0.30, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 150, 50, frozenset({"ACK", "FIN"}), 64240),
    ]
    directions = [True, False, True, False, True]  # fwd/bwd per packet above
    for meta, is_forward in zip(packets, directions):
        acc.update(meta, is_forward)
    values = acc.finalize()

    assert len(values) == 78
    expected = {
        "duration_s": 0.3,
        "total_fwd_packets": 3.0,
        "total_bwd_packets": 2.0,
        "total_fwd_bytes": 450.0,
        "total_bwd_bytes": 580.0,
        "flow_bytes_per_s": 3433.3333333333335,
        "flow_packets_per_s": 16.666666666666668,
        "down_up_ratio": 580.0 / 450.0,
        "fwd_pkt_len_max": 200.0,
        "fwd_pkt_len_min": 100.0,
        "fwd_pkt_len_mean": 150.0,
        "fwd_pkt_len_std": 50.0,
        "bwd_pkt_len_max": 500.0,
        "bwd_pkt_len_min": 80.0,
        "bwd_pkt_len_mean": 290.0,
        "bwd_pkt_len_std": 296.98484809834997,
        "pkt_len_min": 80.0,
        "pkt_len_max": 500.0,
        "pkt_len_mean": 206.0,
        "pkt_len_std": 170.8215443086732,
        "pkt_len_variance": 29180.0,
        "flow_iat_mean": 0.075,
        "flow_iat_std": 0.05,
        "flow_iat_max": 0.15,
        "flow_iat_min": 0.05,
        "fwd_iat_total": 0.3,
        "fwd_iat_mean": 0.15,
        "fwd_iat_std": 0.07071067811865474,
        "fwd_iat_max": 0.2,
        "fwd_iat_min": 0.1,
        "bwd_iat_total": 0.2,
        "bwd_iat_mean": 0.2,
        "bwd_iat_std": 0.0,
        "bwd_iat_max": 0.2,
        "bwd_iat_min": 0.2,
        "fwd_packets_per_s": 10.0,
        "bwd_packets_per_s": 6.666666666666667,
        "fin_flag_count": 1.0,
        "syn_flag_count": 2.0,
        "rst_flag_count": 0.0,
        "psh_flag_count": 1.0,
        "ack_flag_count": 4.0,
        "urg_flag_count": 0.0,
        "cwe_flag_count": 0.0,
        "ece_flag_count": 0.0,
        "fwd_psh_flags": 1.0,
        "bwd_psh_flags": 0.0,
        "fwd_urg_flags": 0.0,
        "bwd_urg_flags": 0.0,
        "fwd_header_length": 250.0,
        "bwd_header_length": 560.0,
        "avg_packet_size": 206.0,
        "avg_fwd_segment_size": 150.0,
        "avg_bwd_segment_size": 290.0,
        "subflow_fwd_packets": 3.0,
        "subflow_fwd_bytes": 450.0,
        "subflow_bwd_packets": 2.0,
        "subflow_bwd_bytes": 580.0,
        "init_win_bytes_fwd": 64240.0,
        "init_win_bytes_bwd": 29200.0,
        "act_data_pkt_fwd": 2.0,
        "min_seg_size_fwd": 50.0,
        "protocol_tcp": 1.0,
        "protocol_udp": 0.0,
        "active_mean": 0.3,
        "active_std": 0.0,
        "active_max": 0.3,
        "active_min": 0.3,
        "idle_mean": 0.0,
        "idle_std": 0.0,
        "idle_max": 0.0,
        "idle_min": 0.0,
        "dst_port_numeric": 443.0,
        "fwd_bytes_per_s": 1500.0,
        "bwd_bytes_per_s": 1933.3333333333335,
        "fwd_pkt_len_variance": 2500.0,
        "bwd_pkt_len_variance": 88200.0,
        "flow_iat_variance": 0.0025,
    }
    assert len(expected) == 78
    for name, expected_value in expected.items():
        assert math.isclose(values[_idx(name)], expected_value, rel_tol=1e-9, abs_tol=1e-9), name
