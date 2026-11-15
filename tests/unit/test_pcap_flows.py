import numpy as np
import pytest

scapy = pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

from services.flowextract.features import FEATURE_NAMES
from training.pcap_flows import PcapStats, iter_flows, pcap_to_feature_files


def _pkt(t, src, sport, dst, dport, proto="tcp", flags="A", payload=b""):
    layer = TCP(sport=sport, dport=dport, flags=flags) if proto == "tcp" else UDP(sport=sport, dport=dport)
    pkt = IP(src=src, dst=dst) / layer
    if payload:
        pkt = pkt / Raw(payload)
    pkt.time = t
    return pkt


def tcp_session(t0, client="10.0.0.5", server="93.184.216.34", sport=40000, dport=443, n=4):
    """Handshake, n request/response pairs, then FIN from both sides."""
    pkts = [
        _pkt(t0, client, sport, server, dport, flags="S"),
        _pkt(t0 + 0.01, server, dport, client, sport, flags="SA"),
        _pkt(t0 + 0.02, client, sport, server, dport, flags="A"),
    ]
    t = t0 + 0.03
    for _ in range(n):
        pkts.append(_pkt(t, client, sport, server, dport, flags="PA", payload=b"x" * 200))
        pkts.append(_pkt(t + 0.01, server, dport, client, sport, flags="PA", payload=b"y" * 800))
        t += 0.05
    pkts.append(_pkt(t, client, sport, server, dport, flags="FA"))
    pkts.append(_pkt(t + 0.01, server, dport, client, sport, flags="FA"))
    return pkts


def udp_exchange(t0, client="10.0.0.6", server="8.8.8.8", sport=50000, dport=53):
    return [
        _pkt(t0, client, sport, server, dport, proto="udp", payload=b"q" * 40),
        _pkt(t0 + 0.02, server, dport, client, sport, proto="udp", payload=b"a" * 120),
    ]


@pytest.fixture
def pcap(tmp_path):
    pkts = []
    for i in range(5):
        pkts += tcp_session(1000.0 + i, sport=40000 + i)
    pkts += udp_exchange(1002.0)
    pkts.sort(key=lambda p: float(p.time))
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), pkts)
    return path


def test_flows_are_reassembled_from_packets(pcap):
    stats = PcapStats()
    flows = list(iter_flows(pcap, stats=stats))
    tcp = [f for f in flows if f.protocol == "TCP"]
    udp = [f for f in flows if f.protocol == "UDP"]
    assert len(tcp) == 5 and len(udp) == 1
    assert all(not f.is_partial for f in tcp)  # closed by FIN from both sides
    assert udp[0].is_partial  # no close signal, flushed at end of file
    assert stats.packets_read == 5 * 13 + 2


def test_feature_vectors_use_the_live_schema_and_are_correct(pcap):
    flow = next(f for f in iter_flows(pcap) if f.protocol == "TCP")
    assert len(flow.feature_values) == len(FEATURE_NAMES) == 78
    named = dict(zip(FEATURE_NAMES, flow.feature_values))
    assert named["protocol_tcp"] == 1.0
    assert named["dst_port_numeric"] == 443.0
    assert named["total_fwd_packets"] > 0 and named["total_bwd_packets"] > 0
    assert named["total_bwd_bytes"] > named["total_fwd_bytes"]


def test_idle_flows_are_expired_against_packet_time(tmp_path):
    pkts = udp_exchange(1000.0) + udp_exchange(2000.0, sport=50001)
    path = tmp_path / "idle.pcap"
    wrpcap(str(path), pkts)
    flows = list(iter_flows(path, idle_timeout=30))
    assert len(flows) == 2
    assert flows[0].start_time < 1500 < flows[1].start_time


def test_max_packets_stops_early(pcap):
    stats = PcapStats()
    list(iter_flows(pcap, max_packets=10, stats=stats))
    assert stats.packets_read == 10


def test_non_ip_traffic_is_skipped_not_fatal(tmp_path):
    from scapy.layers.l2 import ARP, Ether

    arp = Ether() / ARP()
    arp.time = 1000.0
    path = tmp_path / "mixed.pcap"
    # Real captures are Ethernet throughout, so frame the IP packets too.
    wrpcap(str(path), [arp] + [Ether() / p for p in udp_exchange(1000.5)])
    stats = PcapStats()
    assert len(list(iter_flows(path, stats=stats))) == 1
    assert stats.packets_skipped == 1


def test_feature_files_are_written(pcap, tmp_path):
    out = tmp_path / "out"
    n, stats = pcap_to_feature_files(pcap, out)
    assert n == 6
    with np.load(out / "features.npz") as data:
        assert data["X"].shape == (6, 78)
        assert list(data["feature_names"]) == list(FEATURE_NAMES)
        assert np.all(np.isfinite(data["X"]))
    lines = (out / "flows.csv").read_text().splitlines()
    assert len(lines) == 7  # header + one row per feature row
    assert lines[0].startswith("src_ip,dst_ip")
