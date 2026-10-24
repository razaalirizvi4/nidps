import fakeredis

from common.bus import STREAM_EVIDENCE, STREAM_FLOWS, EventBus


def test_publish_and_consume_round_trip():
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    bus.publish(STREAM_EVIDENCE, "hello")

    received = []
    bus.consume(
        STREAM_EVIDENCE, group="test-group", consumer="c1", handler=received.append, block_ms=100
    )

    assert received == ["hello"]


def test_consume_acks_so_message_is_not_redelivered():
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    bus.publish(STREAM_EVIDENCE, "once")

    first = []
    bus.consume(
        STREAM_EVIDENCE, group="test-group", consumer="c1", handler=first.append, block_ms=100
    )
    second = []
    bus.consume(
        STREAM_EVIDENCE, group="test-group", consumer="c1", handler=second.append, block_ms=100
    )

    assert first == ["once"]
    assert second == []


def test_stream_flows_name_is_fixed():
    assert STREAM_FLOWS == "nidps:flows"


def test_publish_and_consume_on_stream_flows():
    import fakeredis

    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    bus.publish(STREAM_FLOWS, "flow-ready-body")

    received = []
    bus.consume(
        STREAM_FLOWS, group="layer2-anomaly", consumer="c1", handler=received.append, block_ms=100
    )
    assert received == ["flow-ready-body"]
