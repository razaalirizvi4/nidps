import fakeredis

from common.bus import STREAM_ADMIN_COMMANDS, EventBus
from common.bus_messages import MessageType, decode_envelope, encode_envelope


def test_stream_admin_commands_name():
    assert STREAM_ADMIN_COMMANDS == "nidps:admin_commands"


def test_publish_and_consume_admin_command_round_trip():
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    bus.publish(
        STREAM_ADMIN_COMMANDS,
        encode_envelope(MessageType.UNBLOCK_REQUESTED, {"ip": "10.0.0.5", "requested_by": 1}),
    )

    received = []
    bus.consume(
        STREAM_ADMIN_COMMANDS, group="test", consumer="c1", handler=received.append, block_ms=100
    )

    envelope = decode_envelope(received[0])
    assert envelope["type"] == MessageType.UNBLOCK_REQUESTED.value
    assert envelope["payload"]["ip"] == "10.0.0.5"


def test_reload_rules_and_recalibrate_message_types_exist():
    assert MessageType.RELOAD_RULES_REQUESTED.value == "reload_rules_requested"
    assert MessageType.RECALIBRATE_REQUESTED.value == "recalibrate_requested"
