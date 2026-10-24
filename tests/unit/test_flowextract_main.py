import fakeredis

from common.bus import STREAM_FLOWS, STREAM_HEARTBEATS, EventBus
from common.bus_messages import decode_envelope
from common.config_loader import seed_defaults
from common.db.migrate import connect
from services.flowextract.config_cache import CachedConfig
from services.flowextract.five_tuple import PacketMeta
from services.flowextract.flow_assembler import FlowAssembler
from services.flowextract.main import publish_heartbeat, run_once


def test_run_once_persists_flow_and_publishes_flow_ready():
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    assembler = FlowAssembler()
    cached_config = CachedConfig(conn)

    packets = [
        PacketMeta(0.00, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 60, 0, frozenset({"SYN"})),
        PacketMeta(0.01, "93.184.216.34", "10.0.0.5", 443, 51000, "TCP", 60, 0, frozenset({"SYN", "ACK"})),
        PacketMeta(0.02, "10.0.0.5", "93.184.216.34", 51000, 443, "TCP", 60, 0, frozenset({"FIN", "ACK"})),
        PacketMeta(0.03, "93.184.216.34", "10.0.0.5", 443, 51000, "TCP", 60, 0, frozenset({"FIN", "ACK"})),
    ]
    published = run_once(conn, bus, assembler, cached_config, packets, now=0.03)

    assert published == 1
    assert conn.execute("SELECT COUNT(*) FROM flow_record").fetchone()[0] == 1

    received = []
    bus.consume(
        STREAM_FLOWS, group="layer2-anomaly", consumer="c1", handler=received.append, block_ms=100
    )
    assert len(received) == 1
    envelope = decode_envelope(received[0])
    assert envelope["type"] == "flow_ready"
    assert envelope["payload"]["host_ip"] == "10.0.0.5"


def test_run_once_expires_idle_flows_with_no_new_packets():
    conn = connect(":memory:")
    seed_defaults(conn)
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    assembler = FlowAssembler(idle_timeout=30)
    cached_config = CachedConfig(conn)

    assembler.onPacket(
        PacketMeta(0.0, "10.0.0.9", "5.6.7.8", 51000, 53, "UDP", 60, 40, frozenset())
    )
    published = run_once(conn, bus, assembler, cached_config, [], now=31.0)

    assert published == 1
    assert len(assembler.flow_table) == 0


def test_publish_heartbeat_sends_component_health():
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    publish_heartbeat(bus, "flowextract")

    received = []
    bus.consume(
        STREAM_HEARTBEATS, group="watchdog", consumer="c1", handler=received.append, block_ms=100
    )
    assert len(received) == 1
    envelope = decode_envelope(received[0])
    assert envelope["payload"]["name"] == "flowextract"
    assert envelope["payload"]["state"] == "NORMAL"
