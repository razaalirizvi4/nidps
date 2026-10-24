"""FR-3.3: computes the fixed 78-feature vector for one flow (segment) incrementally, as packets
arrive, without storing them (NFR-14). Loosely modelled on the CICFlowMeter feature convention for
recognizability by a later training phase, but every feature here is a single-pass running
statistic -- see this plan's Global Constraints for why the mapping isn't a literal CICFlowMeter
port. SUBFLOW_ACTIVITY_GAP_S partitions one flow's packets into active bursts / idle gaps for the
active_*/idle_* features; it is a local design constant, independent of the flow-level
active/idle *timeouts* that govern when FlowAssembler emits a whole flow (Task 6)."""
from __future__ import annotations

from typing import Optional

from services.flowextract.five_tuple import PacketMeta
from services.flowextract.welford import WelfordAccumulator

SUBFLOW_ACTIVITY_GAP_S = 1.0

FEATURE_NAMES = [
    "duration_s", "total_fwd_packets", "total_bwd_packets", "total_fwd_bytes", "total_bwd_bytes",
    "flow_bytes_per_s", "flow_packets_per_s", "down_up_ratio",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_variance",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_packets_per_s", "bwd_packets_per_s",
    "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
    "ack_flag_count", "urg_flag_count", "cwe_flag_count", "ece_flag_count",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fwd_header_length", "bwd_header_length",
    "avg_packet_size", "avg_fwd_segment_size", "avg_bwd_segment_size",
    "subflow_fwd_packets", "subflow_fwd_bytes", "subflow_bwd_packets", "subflow_bwd_bytes",
    "init_win_bytes_fwd", "init_win_bytes_bwd", "act_data_pkt_fwd", "min_seg_size_fwd",
    "protocol_tcp", "protocol_udp",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
    "dst_port_numeric", "fwd_bytes_per_s", "bwd_bytes_per_s",
    "fwd_pkt_len_variance", "bwd_pkt_len_variance", "flow_iat_variance",
]
assert len(FEATURE_NAMES) == 78


class FlowFeatureAccumulator:
    def __init__(self, protocol: str, dst_port: int) -> None:
        self._protocol = protocol
        self._dst_port = dst_port

        self.fwd_len = WelfordAccumulator()
        self.bwd_len = WelfordAccumulator()
        self.all_len = WelfordAccumulator()
        self.flow_iat = WelfordAccumulator()
        self.fwd_iat = WelfordAccumulator()
        self.bwd_iat = WelfordAccumulator()
        self.fwd_header = WelfordAccumulator()
        self.bwd_header = WelfordAccumulator()
        self.active = WelfordAccumulator()
        self.idle = WelfordAccumulator()

        self._flag_counts = {f: 0 for f in ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWE", "ECE")}
        self._fwd_psh = 0
        self._bwd_psh = 0
        self._fwd_urg = 0
        self._bwd_urg = 0
        self._act_data_pkt_fwd = 0
        self._init_win_fwd: Optional[int] = None
        self._init_win_bwd: Optional[int] = None

        self._first_time: Optional[float] = None
        self._last_time: Optional[float] = None
        self._last_fwd_time: Optional[float] = None
        self._last_bwd_time: Optional[float] = None
        self._burst_start: Optional[float] = None
        self._burst_last: Optional[float] = None

    def update(self, meta: PacketMeta, is_forward: bool) -> None:
        if self._first_time is None:
            self._first_time = meta.timestamp
            self._burst_start = meta.timestamp
        else:
            iat = meta.timestamp - self._last_time
            self.flow_iat.add(iat)
            if iat >= SUBFLOW_ACTIVITY_GAP_S:
                self.active.add(self._burst_last - self._burst_start)
                self.idle.add(iat)
                self._burst_start = meta.timestamp
        self._burst_last = meta.timestamp
        self._last_time = meta.timestamp

        header_len = max(meta.length - meta.payload_len, 0)
        self.all_len.add(meta.length)

        if is_forward:
            self.fwd_len.add(meta.length)
            self.fwd_header.add(header_len)
            if self._last_fwd_time is not None:
                self.fwd_iat.add(meta.timestamp - self._last_fwd_time)
            self._last_fwd_time = meta.timestamp
            if meta.payload_len > 0:
                self._act_data_pkt_fwd += 1
            if "SYN" in meta.tcp_flags and self._init_win_fwd is None:
                self._init_win_fwd = meta.tcp_window
            if "PSH" in meta.tcp_flags:
                self._fwd_psh += 1
            if "URG" in meta.tcp_flags:
                self._fwd_urg += 1
        else:
            self.bwd_len.add(meta.length)
            self.bwd_header.add(header_len)
            if self._last_bwd_time is not None:
                self.bwd_iat.add(meta.timestamp - self._last_bwd_time)
            self._last_bwd_time = meta.timestamp
            if "SYN" in meta.tcp_flags and self._init_win_bwd is None:
                self._init_win_bwd = meta.tcp_window
            if "PSH" in meta.tcp_flags:
                self._bwd_psh += 1
            if "URG" in meta.tcp_flags:
                self._bwd_urg += 1

        for flag in meta.tcp_flags:
            if flag in self._flag_counts:
                self._flag_counts[flag] += 1

    def finalize(self) -> list:
        if self._burst_start is not None and self._burst_last is not None:
            self.active.add(self._burst_last - self._burst_start)

        duration = (self._last_time or 0.0) - (self._first_time or 0.0)
        duration_safe = duration if duration > 0 else 1e-6

        values_by_name = {
            "duration_s": duration,
            "total_fwd_packets": float(self.fwd_len.count),
            "total_bwd_packets": float(self.bwd_len.count),
            "total_fwd_bytes": self.fwd_len.total,
            "total_bwd_bytes": self.bwd_len.total,
            "flow_bytes_per_s": (self.fwd_len.total + self.bwd_len.total) / duration_safe,
            "flow_packets_per_s": (self.fwd_len.count + self.bwd_len.count) / duration_safe,
            "down_up_ratio": self.bwd_len.total / max(self.fwd_len.total, 1.0),
            "fwd_pkt_len_max": self.fwd_len.maximum,
            "fwd_pkt_len_min": self.fwd_len.minimum,
            "fwd_pkt_len_mean": self.fwd_len.mean,
            "fwd_pkt_len_std": self.fwd_len.std,
            "bwd_pkt_len_max": self.bwd_len.maximum,
            "bwd_pkt_len_min": self.bwd_len.minimum,
            "bwd_pkt_len_mean": self.bwd_len.mean,
            "bwd_pkt_len_std": self.bwd_len.std,
            "pkt_len_min": self.all_len.minimum,
            "pkt_len_max": self.all_len.maximum,
            "pkt_len_mean": self.all_len.mean,
            "pkt_len_std": self.all_len.std,
            "pkt_len_variance": self.all_len.variance,
            "flow_iat_mean": self.flow_iat.mean,
            "flow_iat_std": self.flow_iat.std,
            "flow_iat_max": self.flow_iat.maximum,
            "flow_iat_min": self.flow_iat.minimum,
            "fwd_iat_total": self.fwd_iat.total,
            "fwd_iat_mean": self.fwd_iat.mean,
            "fwd_iat_std": self.fwd_iat.std,
            "fwd_iat_max": self.fwd_iat.maximum,
            "fwd_iat_min": self.fwd_iat.minimum,
            "bwd_iat_total": self.bwd_iat.total,
            "bwd_iat_mean": self.bwd_iat.mean,
            "bwd_iat_std": self.bwd_iat.std,
            "bwd_iat_max": self.bwd_iat.maximum,
            "bwd_iat_min": self.bwd_iat.minimum,
            "fwd_packets_per_s": self.fwd_len.count / duration_safe,
            "bwd_packets_per_s": self.bwd_len.count / duration_safe,
            "fin_flag_count": float(self._flag_counts["FIN"]),
            "syn_flag_count": float(self._flag_counts["SYN"]),
            "rst_flag_count": float(self._flag_counts["RST"]),
            "psh_flag_count": float(self._flag_counts["PSH"]),
            "ack_flag_count": float(self._flag_counts["ACK"]),
            "urg_flag_count": float(self._flag_counts["URG"]),
            "cwe_flag_count": float(self._flag_counts["CWE"]),
            "ece_flag_count": float(self._flag_counts["ECE"]),
            "fwd_psh_flags": float(self._fwd_psh),
            "bwd_psh_flags": float(self._bwd_psh),
            "fwd_urg_flags": float(self._fwd_urg),
            "bwd_urg_flags": float(self._bwd_urg),
            "fwd_header_length": self.fwd_header.total,
            "bwd_header_length": self.bwd_header.total,
            "avg_packet_size": self.all_len.mean,
            "avg_fwd_segment_size": self.fwd_len.mean,
            "avg_bwd_segment_size": self.bwd_len.mean,
            "subflow_fwd_packets": float(self.fwd_len.count),
            "subflow_fwd_bytes": self.fwd_len.total,
            "subflow_bwd_packets": float(self.bwd_len.count),
            "subflow_bwd_bytes": self.bwd_len.total,
            "init_win_bytes_fwd": float(self._init_win_fwd or 0),
            "init_win_bytes_bwd": float(self._init_win_bwd or 0),
            "act_data_pkt_fwd": float(self._act_data_pkt_fwd),
            "min_seg_size_fwd": self.fwd_header.minimum,
            "protocol_tcp": 1.0 if self._protocol == "TCP" else 0.0,
            "protocol_udp": 1.0 if self._protocol == "UDP" else 0.0,
            "active_mean": self.active.mean,
            "active_std": self.active.std,
            "active_max": self.active.maximum,
            "active_min": self.active.minimum,
            "idle_mean": self.idle.mean,
            "idle_std": self.idle.std,
            "idle_max": self.idle.maximum,
            "idle_min": self.idle.minimum,
            "dst_port_numeric": float(self._dst_port),
            "fwd_bytes_per_s": self.fwd_len.total / duration_safe,
            "bwd_bytes_per_s": self.bwd_len.total / duration_safe,
            "fwd_pkt_len_variance": self.fwd_len.variance,
            "bwd_pkt_len_variance": self.bwd_len.variance,
            "flow_iat_variance": self.flow_iat.variance,
        }
        return [values_by_name[name] for name in FEATURE_NAMES]
