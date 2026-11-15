"""Turns a pcap into the same flow records the live device produces.

This drives the live FlowAssembler and parse_packet() unchanged, so a training row and a
runtime row come from identical code (FR-12.1, NFR-19). The only difference from the live loop
is the clock: idle flows are expired against packet timestamps instead of wall time, and
whatever is still open when the file ends is flushed as partial flows."""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Optional

import numpy as np

from services.flowextract.capture import parse_packet
from services.flowextract.features import FEATURE_NAMES
from services.flowextract.flow_assembler import EmittedFlow, FlowAssembler

META_COLUMNS = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "start_time", "end_time",
    "segment_no", "is_partial", "ja3", "ja3s", "server_name",
]


@dataclass
class PcapStats:
    packets_read: int = 0
    packets_skipped: int = 0  # not IPv4 TCP/UDP, or could not be parsed
    flows: int = 0


def iter_flows(
    pcap_path,
    active_timeout: int = 10,
    idle_timeout: int = 30,
    max_packets: Optional[int] = None,
    expire_every_s: float = 1.0,
    stats: Optional[PcapStats] = None,
) -> Iterator[EmittedFlow]:
    from scapy.utils import PcapReader

    stats = stats if stats is not None else PcapStats()
    assembler = FlowAssembler(active_timeout=active_timeout, idle_timeout=idle_timeout)
    last_expire: Optional[float] = None

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if max_packets is not None and stats.packets_read >= max_packets:
                break
            stats.packets_read += 1
            try:
                meta = parse_packet(pkt)
            except Exception:
                meta = None
            if meta is None:
                stats.packets_skipped += 1
                continue
            for flow in assembler.onPacket(meta):
                stats.flows += 1
                yield flow
            if last_expire is None or meta.timestamp - last_expire >= expire_every_s:
                for flow in assembler.expireIdle(meta.timestamp):
                    stats.flows += 1
                    yield flow
                last_expire = meta.timestamp

    for flow in assembler.expireIdle(float("inf")):
        stats.flows += 1
        yield flow


def _meta_row(flow: EmittedFlow) -> list:
    return [
        flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol,
        f"{flow.start_time:.6f}", f"{flow.end_time:.6f}", flow.segment_no, int(flow.is_partial),
        flow.tls.ja3 or "", flow.tls.ja3s or "", flow.tls.server_name or "",
    ]


def pcap_to_feature_files(
    pcap_path,
    out_dir,
    max_packets: Optional[int] = None,
    progress: Optional[Callable[[PcapStats, int], None]] = None,
    progress_every: int = 200_000,
) -> tuple:
    """Writes <out_dir>/features.npz (X: flows x 78, feature_names) and <out_dir>/flows.csv
    (one metadata row per feature row). Returns (n_flows, stats). Rows with a non-finite
    feature are dropped rather than passed to the model."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stats = PcapStats()
    chunks: list = []
    pending: list = []
    kept = 0
    dropped = 0
    next_report = progress_every

    with open(out_dir / "flows.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(META_COLUMNS)
        for flow in iter_flows(pcap_path, max_packets=max_packets, stats=stats):
            values = flow.feature_values
            if not np.all(np.isfinite(values)):
                dropped += 1
                continue
            pending.append(values)
            writer.writerow(_meta_row(flow))
            kept += 1
            if len(pending) >= 10_000:
                chunks.append(np.asarray(pending, dtype=np.float64))
                pending = []
            if progress is not None and stats.packets_read >= next_report:
                progress(stats, kept)
                next_report = stats.packets_read + progress_every

    if pending:
        chunks.append(np.asarray(pending, dtype=np.float64))
    X = np.vstack(chunks) if chunks else np.empty((0, len(FEATURE_NAMES)))
    np.savez_compressed(out_dir / "features.npz", X=X, feature_names=np.array(FEATURE_NAMES))
    stats.flows = kept
    if dropped:
        (out_dir / "dropped.txt").write_text(f"{dropped} flows with non-finite features\n")
    return kept, stats
