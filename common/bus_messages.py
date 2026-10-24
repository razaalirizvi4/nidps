"""Versioned JSON envelope wrapped around every event-bus message."""
from __future__ import annotations

import dataclasses
import enum
import json
import uuid
from typing import Any

from common.schemas import utc_now_iso

ENVELOPE_SCHEMA_VERSION = "1.0"


class MessageType(str, enum.Enum):
    EVIDENCE = "evidence"
    VERDICT = "verdict"
    HEARTBEAT = "heartbeat"
    CONFIG_CHANGE = "config_change"
    FLOW_READY = "flow_ready"


def _default(obj: Any):
    if isinstance(obj, enum.Enum):
        return obj.value
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    raise TypeError(f"Cannot serialize {type(obj)!r}")


def encode_envelope(message_type: MessageType, payload: Any) -> str:
    envelope = {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "message_id": str(uuid.uuid4()),
        "produced_at": utc_now_iso(),
        "type": message_type.value,
        "payload": payload,
    }
    return json.dumps(envelope, default=_default)


def decode_envelope(raw: str) -> dict:
    envelope = json.loads(raw)
    if envelope.get("schema_version") != ENVELOPE_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported envelope schema version: {envelope.get('schema_version')!r}"
        )
    return envelope
