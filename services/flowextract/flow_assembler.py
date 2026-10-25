"""Algorithm 5.1: bidirectional flow assembly. FlowAssembler.active_timeout/idle_timeout are
plain mutable ints (matching the UML class diagram) -- main.py (Task 9) re-assigns them from
config every capture-loop iteration (FR-10.6); this class itself has no config/DB dependency."""
from __future__ import annotations

from dataclasses import dataclass

from common.schemas import TLSFingerprint
from services.flowextract.features import FlowFeatureAccumulator
from services.flowextract.five_tuple import PacketMeta, canonical_five_tuple
from services.flowextract.tls_fingerprint import compute_tls_fingerprint


@dataclass
class EmittedFlow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    end_time: float
    segment_no: int
    is_partial: bool
    feature_values: list
    tls: TLSFingerprint


class _FlowState:
    def __init__(self, fwd_tuple: tuple, protocol: str, dst_port: int, start_time: float) -> None:
        self.fwd_tuple = fwd_tuple
        self.protocol = protocol
        self.dst_port = dst_port
        self.segment_start = start_time
        self.segment_no = 0
        self.last_seen = start_time
        self.accumulator = FlowFeatureAccumulator(protocol, dst_port)
        self.tls = TLSFingerprint()
        self.fwd_fin = False
        self.bwd_fin = False
        self.rst = False


class FlowAssembler:
    def __init__(self, active_timeout: int = 10, idle_timeout: int = 30) -> None:
        self.flow_table: dict = {}
        self.active_timeout = active_timeout
        self.idle_timeout = idle_timeout

    def onPacket(self, meta: PacketMeta) -> list:
        key = canonical_five_tuple(meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port, meta.protocol)
        emitted = []
        if key not in self.flow_table:
            self.flow_table[key] = _FlowState(
                (meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port),
                meta.protocol, meta.dst_port, meta.timestamp,
            )
        state = self.flow_table[key]
        is_forward = (meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port) == state.fwd_tuple
        state.accumulator.update(meta, is_forward)
        state.last_seen = meta.timestamp

        if meta.tls_client_hello is not None:
            fields = meta.tls_client_hello
            state.tls.ja3 = compute_tls_fingerprint(
                fields["version"], fields["cipher_suites"], fields["extensions"],
                fields["groups"], fields["point_formats"],
            )
            if fields.get("server_name"):
                state.tls.server_name = fields["server_name"]
        if meta.tls_server_hello is not None:
            fields = meta.tls_server_hello
            state.tls.ja3s = compute_tls_fingerprint(
                fields["version"], fields["cipher_suites"], fields["extensions"],
            )

        if "FIN" in meta.tcp_flags:
            if is_forward:
                state.fwd_fin = True
            else:
                state.bwd_fin = True
        if "RST" in meta.tcp_flags:
            state.rst = True

        if state.rst or (state.fwd_fin and state.bwd_fin):
            emitted.append(self.emit(key))
            del self.flow_table[key]
        elif meta.timestamp - state.segment_start >= self.active_timeout:
            emitted.append(self.emit(key, is_partial=True))
            state.segment_no += 1
            state.segment_start = meta.timestamp
            state.accumulator = FlowFeatureAccumulator(meta.protocol, state.dst_port)
            state.tls = TLSFingerprint()
            state.fwd_fin = False
            state.bwd_fin = False
            state.rst = False
        return emitted

    def emit(self, key: tuple, is_partial: bool = False) -> "EmittedFlow":
        state = self.flow_table[key]
        src_ip, src_port, dst_ip, dst_port = state.fwd_tuple
        return EmittedFlow(
            src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
            protocol=state.protocol, start_time=state.segment_start, end_time=state.last_seen,
            segment_no=state.segment_no, is_partial=is_partial,
            feature_values=state.accumulator.finalize(), tls=state.tls,
        )

    def expireIdle(self, now: float) -> list:
        emitted = []
        for key in list(self.flow_table.keys()):
            state = self.flow_table[key]
            if now - state.last_seen >= self.idle_timeout:
                # A flow that rolled over on an active-timeout and then never saw another
                # packet in its new segment has an accumulator that has seen ZERO packets --
                # emitting it would fabricate an all-zero-feature flow_record (C2). Just drop
                # the stale key; there is nothing real to emit.
                if state.accumulator.all_len.count == 0:
                    del self.flow_table[key]
                    continue
                # Reaching expireIdle at all means this flow never saw a full FIN/RST close
                # (that path emits via onPacket and removes the key immediately) -- so every
                # flow emitted here is, by construction, partial.
                emitted.append(self.emit(key, is_partial=True))
                del self.flow_table[key]
        return emitted
