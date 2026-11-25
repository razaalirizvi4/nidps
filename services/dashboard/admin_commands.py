"""Publish side of the admin-command bus contract (FR-9.5 unblock, FR-10.5 reload rules / recalibrate
on demand). STREAM_ADMIN_COMMANDS has no consumer anywhere in the codebase yet -- there is no
enforcement service to act on UNBLOCK_REQUESTED, and sigbridge/mlscorer's main.py loops only
subscribe to the streams their own services defined. These three actions therefore publish
successfully and are durably queued (Redis Streams retain unacked entries) but currently have no
visible effect until that consumer is built. This is a documented, known gap -- not a bug here."""
from __future__ import annotations

from common.bus import STREAM_ADMIN_COMMANDS, EventBus
from common.bus_messages import MessageType, encode_envelope


class AdminCommands:
    def __init__(self, bus: EventBus):
        self._bus = bus

    def request_unblock(self, ip: str, requested_by: int) -> None:
        self._bus.publish(
            STREAM_ADMIN_COMMANDS,
            encode_envelope(MessageType.UNBLOCK_REQUESTED, {"ip": ip, "requested_by": requested_by}),
        )

    def request_reload_rules(self, requested_by: int) -> None:
        self._bus.publish(
            STREAM_ADMIN_COMMANDS,
            encode_envelope(MessageType.RELOAD_RULES_REQUESTED, {"requested_by": requested_by}),
        )

    def request_recalibration(self, requested_by: int) -> None:
        self._bus.publish(
            STREAM_ADMIN_COMMANDS,
            encode_envelope(MessageType.RECALIBRATE_REQUESTED, {"requested_by": requested_by}),
        )
