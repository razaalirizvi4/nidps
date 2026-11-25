import fakeredis

from common.bus import STREAM_ADMIN_COMMANDS, EventBus
from common.bus_messages import MessageType, decode_envelope
from services.dashboard.admin_commands import AdminCommands


def _bus():
    return EventBus(fakeredis.FakeRedis(decode_responses=True))


def test_request_unblock_publishes_correct_message_type_and_payload():
    bus = _bus()
    commands = AdminCommands(bus)

    commands.request_unblock("10.0.0.5", requested_by=1)

    received = []
    bus.consume(STREAM_ADMIN_COMMANDS, group="g", consumer="c", handler=received.append, block_ms=100)
    envelope = decode_envelope(received[0])
    assert envelope["type"] == MessageType.UNBLOCK_REQUESTED.value
    assert envelope["payload"] == {"ip": "10.0.0.5", "requested_by": 1}


def test_request_reload_rules_publishes_correct_message_type():
    bus = _bus()
    commands = AdminCommands(bus)

    commands.request_reload_rules(requested_by=1)

    received = []
    bus.consume(STREAM_ADMIN_COMMANDS, group="g", consumer="c", handler=received.append, block_ms=100)
    assert decode_envelope(received[0])["type"] == MessageType.RELOAD_RULES_REQUESTED.value


def test_request_recalibration_publishes_correct_message_type():
    bus = _bus()
    commands = AdminCommands(bus)

    commands.request_recalibration(requested_by=1)

    received = []
    bus.consume(STREAM_ADMIN_COMMANDS, group="g", consumer="c", handler=received.append, block_ms=100)
    assert decode_envelope(received[0])["type"] == MessageType.RECALIBRATE_REQUESTED.value
