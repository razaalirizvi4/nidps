import fakeredis
from scapy.layers.l2 import ARP

from common.bus import STREAM_EVIDENCE, STREAM_HEARTBEATS, EventBus
from common.bus_messages import decode_envelope
from common.config_loader import seed_defaults
from common.db.migrate import connect
from services.arpmon.arp_monitor import ArpMonitor
from services.arpmon.main import parse_arp_packet, process_frames, publish_heartbeat


def test_parse_arp_packet_detects_reply():
    pkt = ARP(op=2, psrc="10.10.0.5", hwsrc="aa:bb:cc:dd:ee:ff", pdst="10.10.0.1")
    frame = parse_arp_packet(pkt, timestamp=1700000000.0)

    assert frame.sender_ip == "10.10.0.5"
    assert frame.sender_mac == "aa:bb:cc:dd:ee:ff"
    assert frame.is_reply is True
    assert frame.is_gratuitous is False
    assert frame.timestamp == 1700000000.0


def test_parse_arp_packet_detects_gratuitous():
    pkt = ARP(op=1, psrc="10.10.0.9", pdst="10.10.0.9", hwsrc="11:22:33:44:55:66")
    frame = parse_arp_packet(pkt, timestamp=1700000000.0)

    assert frame.is_reply is False
    assert frame.is_gratuitous is True


def test_process_frames_fills_weight_and_publishes_evidence():
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="ff:ff:ff:ff:ff:ff")

    from services.arpmon.arp_monitor import ArpFrame

    published = process_frames(
        conn, bus, monitor,
        [ArpFrame(sender_ip="10.10.0.1", sender_mac="de:ad:be:ef:00:00", is_reply=True, is_gratuitous=False, timestamp=0.0)],
    )

    assert published == 1
    received = []
    bus.consume(STREAM_EVIDENCE, group="decision", consumer="c1", handler=received.append, block_ms=100)
    assert len(received) == 1
    envelope = decode_envelope(received[0])
    assert envelope["payload"]["signature_id"] == 2
    assert envelope["payload"]["weight"] == 3.0  # risk.weight_signature default


def test_publish_heartbeat_sends_component_health():
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    monitor = ArpMonitor(gateway_ip="10.10.0.1", ap_mac="ff:ff:ff:ff:ff:ff")
    publish_heartbeat(bus, monitor)

    received = []
    bus.consume(STREAM_HEARTBEATS, group="watchdog", consumer="c1", handler=received.append, block_ms=100)
    assert len(received) == 1
    assert decode_envelope(received[0])["payload"]["name"] == "arpmon"
